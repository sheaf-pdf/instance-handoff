//! Unix: the runtime folder, an `flock` on `instance.lock`, an AF_UNIX
//! socket beside it, and a `poll` loop on the crate's thread.

use std::ffi::{CString, OsStr, OsString};
use std::io::{self, Read};
#[cfg(target_os = "macos")]
use std::os::fd::RawFd;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::naming;
use crate::server::{Core, Session};
use crate::wire::refusal;
use crate::{AppId, Payload, Reason};

pub(crate) const SUPPORTED: bool = true;

pub(crate) type Listener = UnixListener;

/// Before a launch sends its request. Nothing to do on Unix: Windows lets
/// the owner take the foreground here.
pub(crate) fn before_hand_off(_owner_pid: Option<u32>) {}

const LOCK_FILE: &str = "instance.lock";
const SOCKET_FILE: &str = "instance.sock";
/// Connections open at once; more are accepted and closed, and retry.
const MAX_CONNECTIONS: usize = 64;

/// The effective user id, as the kernel reports it in this process's own
/// namespace. On Linux it comes from the system call, not from the C
/// library's `geteuid`, which fakeroot replaces to report root.
fn euid() -> libc::uid_t {
    #[cfg(target_os = "linux")]
    {
        // 32-bit x86, arm and sparc keep the 16-bit call under the plain
        // name. On m68k, libc's SYS_geteuid is already the 32-bit one.
        #[cfg(any(target_arch = "x86", target_arch = "arm", target_arch = "sparc"))]
        let nr = libc::SYS_geteuid32;
        #[cfg(not(any(target_arch = "x86", target_arch = "arm", target_arch = "sparc")))]
        let nr = libc::SYS_geteuid;
        // SAFETY: geteuid takes no arguments and can't fail.
        unsafe { libc::syscall(nr) as libc::uid_t }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: geteuid has no preconditions and can't fail.
        unsafe { libc::geteuid() }
    }
}

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn cstr(s: &OsStr) -> io::Result<CString> {
    CString::new(s.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a NUL in the path"))
}

fn denied(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, why.to_owned())
}

// ---------------------------------------------------------------------------
// Where the folder is
// ---------------------------------------------------------------------------

// Each platform's rule uses some of these.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Base {
    /// Exists already, and must be this user's and writable by nobody else.
    Trusted,
    /// The shared temporary folder: never created or checked. Only the
    /// subfolder made in it is.
    Shared,
    /// [`Builder::dir`](crate::Builder::dir): created when missing, and
    /// must be private.
    Create,
    /// Root's own base: created when missing, though never its parent, and
    /// must be a real folder, root's, and writable by nobody else.
    System,
}

/// A runtime folder: a base, and the subfolders this crate makes in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Place {
    pub(crate) base: PathBuf,
    pub(crate) kind: Base,
    pub(crate) subs: Vec<OsString>,
}

impl Place {
    pub(crate) fn dir(dir: PathBuf) -> Place {
        Place {
            base: dir,
            kind: Base::Create,
            subs: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, sub: impl Into<OsString>) {
        self.subs.push(sub.into());
    }

    pub(crate) fn path(&self) -> PathBuf {
        let mut p = self.base.clone();
        p.extend(&self.subs);
        p
    }
}

/// What the Linux folder rule looks at, gathered apart from the rule so
/// that the rule can be tested.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Default, Clone)]
pub(crate) struct LinuxEnv {
    /// `FLATPAK_ID`, inside a Flatpak sandbox (`/.flatpak-info` exists).
    pub(crate) flatpak_id: Option<OsString>,
    /// `SNAP_INSTANCE_NAME` is set.
    pub(crate) snap: bool,
    pub(crate) xdg_runtime_dir: Option<PathBuf>,
    /// The host runs systemd (`/run/systemd/system` is a folder).
    pub(crate) systemd: bool,
    /// `/run/user/<euid>`, if it exists. Whether it is safe is checked when
    /// it is opened (a `RuntimeDir` reason, not `NoSession`).
    pub(crate) run_user: Option<PathBuf>,
    pub(crate) euid: u32,
}

/// The Linux rule, part of the contract between builds. Each launch has
/// one right folder, and never falls back to another: a fallback is how two
/// launches of one user end up with two owners.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_rule(env: &LinuxEnv, id: &AppId) -> Result<Place, Reason> {
    let trusted = |base: PathBuf| Place {
        base,
        kind: Base::Trusted,
        subs: vec![id.as_str().into()],
    };
    if let Some(flatpak) = &env.flatpak_id {
        let xdg = env
            .xdg_runtime_dir
            .as_ref()
            .ok_or(Reason::NoRuntimeDir {})?;
        return Ok(trusted(xdg.join("app").join(flatpak)));
    }
    if env.snap {
        let xdg = env
            .xdg_runtime_dir
            .as_ref()
            .ok_or(Reason::NoRuntimeDir {})?;
        return Ok(trusted(xdg.clone()));
    }
    // Root has one folder, whether or not it is logged in, so every root
    // launch meets one owner. /run/user/0 exists only while root has a
    // session somewhere.
    if env.euid == 0 {
        return Ok(Place {
            base: naming::ROOT_BASE_RUN.into(),
            kind: Base::System,
            subs: vec![id.as_str().into()],
        });
    }
    if env.systemd {
        return env
            .run_user
            .clone()
            .map(trusted)
            .ok_or(Reason::NoSession {});
    }
    // No systemd: elogind and pam_rundir create and remove the runtime
    // folder with sessions, so only /tmp is the same for every launch.
    Ok(Place {
        base: "/tmp".into(),
        kind: Base::Shared,
        subs: vec![format!("{id}-{}", env.euid).into()],
    })
}

#[cfg(target_os = "linux")]
fn linux_env() -> LinuxEnv {
    let var = |name| std::env::var_os(name).filter(|v| !v.is_empty());
    let uid = euid();
    let run_user = PathBuf::from(format!("/run/user/{uid}"));
    let exists = std::fs::symlink_metadata(&run_user).is_ok();
    LinuxEnv {
        flatpak_id: var("FLATPAK_ID").filter(|_| Path::new("/.flatpak-info").exists()),
        snap: var("SNAP_INSTANCE_NAME").is_some(),
        xdg_runtime_dir: var("XDG_RUNTIME_DIR").map(PathBuf::from),
        systemd: std::fs::symlink_metadata("/run/systemd/system").is_ok_and(|m| m.is_dir()),
        run_user: exists.then_some(run_user),
        euid: uid,
    }
}

pub(crate) fn default_place(id: &AppId) -> Result<Place, Reason> {
    #[cfg(target_os = "linux")]
    {
        linux_rule(&linux_env(), id)
    }
    #[cfg(target_os = "android")]
    {
        let tmp = std::env::var_os("TMPDIR").filter(|v| !v.is_empty());
        let base = tmp.ok_or(Reason::NoRuntimeDir {})?;
        Ok(Place {
            base: base.into(),
            kind: Base::Trusted,
            subs: vec![id.as_str().into()],
        })
    }
    #[cfg(target_os = "macos")]
    {
        // The per-user temporary folder, from the user's record rather than
        // from $TMPDIR, so GUI apps, agents, ssh and cron all agree.
        let base = darwin_temp_dir().ok_or(Reason::NoRuntimeDir {})?;
        Ok(Place {
            base,
            kind: Base::Trusted,
            subs: vec![id.as_str().into()],
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        let uid = euid();
        if uid == 0 {
            return Ok(Place {
                base: naming::ROOT_BASE_VAR_RUN.into(),
                kind: Base::System,
                subs: vec![id.as_str().into()],
            });
        }
        Ok(Place {
            base: "/tmp".into(),
            kind: Base::Shared,
            subs: vec![format!("{id}-{uid}").into()],
        })
    }
}

/// Root's own base, where it has one: on Linux, the BSDs and illumos.
const ROOT_BASE: Option<&str> = if cfg!(target_os = "linux") {
    Some(naming::ROOT_BASE_RUN)
} else if cfg!(any(target_os = "android", target_os = "macos")) {
    None
} else {
    Some(naming::ROOT_BASE_VAR_RUN)
};

/// The per-user temporary folder, with its links resolved: the path
/// `confstr` gives goes through `/var`, a link to `/private/var`.
#[cfg(target_os = "macos")]
fn darwin_temp_dir() -> Option<PathBuf> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: the buffer is valid for writes of its length.
    let n = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n == 0 || n > buf.len() {
        return None;
    }
    buf.truncate(n - 1);
    std::fs::canonicalize(OsString::from_vec(buf)).ok()
}

#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStringExt;

// ---------------------------------------------------------------------------
// The folder
// ---------------------------------------------------------------------------

/// An open, checked runtime folder. The lock file is opened through its
/// descriptor, so the folder can't be swapped for another between the
/// check and the lock; the socket is reached by path (absolute, so a change
/// of working directory can't redirect it).
#[derive(Debug)]
pub(crate) struct Folder {
    path: PathBuf,
    fd: OwnedFd,
}

fn open_dir(at: Option<BorrowedFd<'_>>, path: &Path, nofollow: bool) -> io::Result<OwnedFd> {
    let c = cstr(path.as_os_str())?;
    let mut flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    if nofollow {
        flags |= libc::O_NOFOLLOW;
    }
    let dirfd = at.map_or(libc::AT_FDCWD, |fd| fd.as_raw_fd());
    // SAFETY: `c` is a valid C string; the result is a new descriptor.
    let fd = cvt(unsafe { libc::openat(dirfd, c.as_ptr(), flags) }).map_err(|e| {
        match e.raw_os_error() {
            Some(libc::ELOOP | libc::ENOTDIR) => {
                // SAFETY: stat is plain data; fstatat fills it in.
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                let r =
                    unsafe { libc::fstatat(dirfd, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
                if r == 0 && st.st_mode & libc::S_IFMT == libc::S_IFLNK {
                    denied("a symlink, not a folder")
                } else {
                    io::Error::new(io::ErrorKind::NotADirectory, "not a folder")
                }
            }
            _ => e,
        }
    })?;
    // SAFETY: openat returned a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fstat(fd: BorrowedFd<'_>) -> io::Result<libc::stat> {
    // SAFETY: stat is plain data; fstat fills it in.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    cvt(unsafe { libc::fstat(fd.as_raw_fd(), &mut st) })?;
    Ok(st)
}

// The kernel writes all 256 bytes of its struct. A module-level constant,
// so that `cargo check` and clippy evaluate it for every target, not only
// a build.
#[cfg(all(target_os = "linux", any(target_env = "gnu", target_env = "musl")))]
const _: () = assert!(std::mem::size_of::<libc::statx>() == 256);

/// A file's owner and mode, as the kernel reports them. On Linux with glibc
/// or musl they come from the `statx` system call, not from the C library's
/// `fstat`, which fakeroot replaces to report root as the owner. Elsewhere,
/// and where the kernel (before 4.11) or a seccomp filter refuses `statx`,
/// they come from `fstat`.
fn owner_mode(fd: BorrowedFd<'_>) -> io::Result<(libc::uid_t, libc::mode_t)> {
    #[cfg(all(target_os = "linux", any(target_env = "gnu", target_env = "musl")))]
    {
        const WANT: libc::c_uint = libc::STATX_UID | libc::STATX_MODE;
        // SAFETY: statx is plain data; the kernel fills it in.
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        // SAFETY: the empty path with AT_EMPTY_PATH names `fd` itself, and
        // `stx` is valid for writes of the kernel's struct, checked above.
        let r = unsafe {
            libc::syscall(
                libc::SYS_statx,
                fd.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH,
                WANT,
                &mut stx as *mut libc::statx,
            )
        };
        if r == 0 {
            if stx.stx_mask & WANT != WANT {
                return Err(denied("its owner or mode is unknown"));
            }
            return Ok((stx.stx_uid, stx.stx_mode.into()));
        }
        let e = io::Error::last_os_error();
        if !matches!(e.raw_os_error(), Some(libc::ENOSYS | libc::EPERM)) {
            return Err(e);
        }
    }
    let st = fstat(fd)?;
    Ok((st.st_uid, st.st_mode))
}

/// This user's, and writable by nobody else.
fn check_trusted(fd: BorrowedFd<'_>) -> io::Result<()> {
    let (uid, mode) = owner_mode(fd)?;
    if uid != euid() {
        return Err(denied("owned by another user"));
    }
    if mode & 0o022 != 0 {
        return Err(denied("other users can write to it"));
    }
    Ok(())
}

/// This user's alone: nobody else can read it either, or they could lock
/// the lock file.
fn check_private(fd: BorrowedFd<'_>) -> io::Result<()> {
    let (uid, mode) = owner_mode(fd)?;
    if uid != euid() {
        return Err(denied("owned by another user"));
    }
    if mode & 0o077 != 0 {
        return Err(denied("other users can open it"));
    }
    Ok(())
}

/// Makes one folder, private, unless something is there already. Its
/// parent must exist.
fn make_dir(path: &Path) -> io::Result<()> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

/// Opens root's base, creating it when `create` is set. Only root uses it,
/// so the user it must belong to is root.
fn open_system(path: &Path, create: bool) -> io::Result<OwnedFd> {
    if create {
        make_dir(path)?;
    }
    let fd = open_dir(None, path, true)?;
    check_trusted(fd.as_fd())?;
    Ok(fd)
}

/// Opens the runtime folder, creating it when `create` is set. `None` when
/// it doesn't exist and `create` isn't set: nobody owns the app.
pub(crate) fn open_folder(place: &Place, create: bool) -> Result<Option<Folder>, Reason> {
    let mut path = place.base.clone();
    let missing = |e: &io::Error| e.kind() == io::ErrorKind::NotFound && !create;
    let opened = match place.kind {
        Base::Create => {
            if create {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&path)
                    .map_err(|e| Reason::runtime_dir(&path, e))?;
            }
            open_dir(None, &path, true).and_then(|fd| check_private(fd.as_fd()).map(|()| fd))
        }
        Base::Trusted => {
            // On macOS the base's links were resolved, so a link there now
            // is a swap.
            let nofollow = cfg!(target_os = "macos");
            open_dir(None, &path, nofollow).and_then(|fd| check_trusted(fd.as_fd()).map(|()| fd))
        }
        Base::System => open_system(&path, create),
        Base::Shared => open_dir(None, &path, false),
    };
    let mut fd = match opened {
        Ok(fd) => fd,
        Err(e) if missing(&e) => return Ok(None),
        Err(e) => return Err(Reason::runtime_dir(&path, e)),
    };
    for sub in &place.subs {
        path.push(sub);
        let c = cstr(sub).map_err(|e| Reason::runtime_dir(&path, e))?;
        if create {
            // SAFETY: `c` is a valid C string and `fd` an open folder.
            let made = cvt(unsafe { libc::mkdirat(fd.as_raw_fd(), c.as_ptr(), 0o700) });
            if let Err(e) = made {
                if e.kind() != io::ErrorKind::AlreadyExists {
                    return Err(Reason::runtime_dir(&path, e));
                }
            }
        }
        fd = match open_dir(Some(fd.as_fd()), Path::new(sub), true)
            .and_then(|sub| check_private(sub.as_fd()).map(|()| sub))
        {
            Ok(sub) => sub,
            Err(e) if missing(&e) => return Ok(None),
            Err(e) => return Err(Reason::runtime_dir(&path, e)),
        };
    }
    Ok(Some(Folder { path, fd }))
}

/// The held lock: an `flock` on the open file. Closing the last descriptor
/// releases it; nothing ever unlocks it explicitly, so a forked child that
/// keeps a copy keeps the lock.
#[derive(Debug)]
pub(crate) struct Lock(OwnedFd);

fn flock_nb(fd: BorrowedFd<'_>) -> io::Result<bool> {
    loop {
        // SAFETY: flock on an open descriptor.
        match cvt(unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }) {
            Ok(_) => return Ok(true),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

fn stat_key(st: &libc::stat) -> (u64, u64) {
    #[allow(clippy::unnecessary_cast)]
    (st.st_dev as u64, st.st_ino as u64)
}

impl Folder {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn lock_path(&self) -> PathBuf {
        self.path.join(LOCK_FILE)
    }

    fn open_lock(&self, create: bool) -> io::Result<OwnedFd> {
        let c = cstr(OsStr::new(LOCK_FILE))?;
        let mut flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        if create {
            flags |= libc::O_CREAT;
        }
        let mode: libc::c_uint = 0o600;
        // SAFETY: `c` is a valid C string and `self.fd` an open folder.
        let fd = cvt(unsafe { libc::openat(self.fd.as_raw_fd(), c.as_ptr(), flags, mode) })?;
        // SAFETY: openat returned a new descriptor that nothing else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Takes the lock, creating the file. `None` when another process
    /// holds it.
    pub(crate) fn lock(&self) -> io::Result<Option<Lock>> {
        let fd = self.open_lock(true)?;
        Ok(flock_nb(fd.as_fd())?.then_some(Lock(fd)))
    }

    /// Whether another process holds the lock, without creating anything.
    /// The lock is taken and dropped at once to find out.
    pub(crate) fn lock_held(&self) -> io::Result<bool> {
        match self.open_lock(false) {
            Ok(fd) => flock_nb(fd.as_fd()).map(|got| !got),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Whether the path still names the lock file `lock` holds.
    fn holds(&self, lock: &Lock) -> bool {
        let Ok(c) = cstr(self.lock_path().as_os_str()) else {
            return false;
        };
        // SAFETY: stat is plain data; lstat fills it in.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::lstat(c.as_ptr(), &mut st) } != 0 {
            return false;
        }
        fstat(lock.0.as_fd()).is_ok_and(|ours| stat_key(&ours) == stat_key(&st))
    }

    /// Where the socket is bound (`create`: making the short folder a long
    /// path needs) and reached.
    fn address(&self, create: bool) -> io::Result<Address> {
        let direct = self.path.join(SOCKET_FILE);
        if fits(&direct) {
            return Ok(Address::InFolder(direct));
        }
        // Linux reaches a long folder through this process's descriptor.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let short = PathBuf::from(format!(
                "/proc/self/fd/{}/{SOCKET_FILE}",
                self.fd.as_raw_fd()
            ));
            if Path::new("/proc/self/fd").is_dir() && fits(&short) {
                return Ok(Address::InFolder(short));
            }
        }
        let st = fstat(self.fd.as_fd())?;
        let (dev, ino) = stat_key(&st);
        let mut key = dev.to_le_bytes().to_vec();
        key.extend_from_slice(&ino.to_le_bytes());
        let name = format!("{}.sock", naming::hex16(naming::fnv1a64(&key)));
        let path = short_base(create)?.join(name);
        if !fits(&path) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket path too long",
            ));
        }
        Ok(Address::Elsewhere(path))
    }

    /// Removes whatever is at the socket's address.
    fn remove_socket(&self) {
        let result = match self.address(false) {
            Ok(Address::InFolder(_)) => {
                let c = cstr(OsStr::new(SOCKET_FILE)).expect("no NUL");
                // SAFETY: `c` is a valid C string and `self.fd` an open folder.
                cvt(unsafe { libc::unlinkat(self.fd.as_raw_fd(), c.as_ptr(), 0) }).map(drop)
            }
            Ok(Address::Elsewhere(path)) => std::fs::remove_file(path),
            Err(e) => Err(e),
        };
        if let Err(e) = result {
            if e.kind() != io::ErrorKind::NotFound {
                log::debug!(
                    "instance-handoff: removing the socket in {}: {e}",
                    self.path.display()
                );
            }
        }
    }

    /// Removes the socket only if `lock` is still the lock at the path and
    /// the socket there is the one this process bound (`socket`): a new
    /// owner's files are never touched.
    fn remove_own_socket(&self, lock: &Lock, socket: Option<SocketKey>) {
        if socket.is_some() && self.holds(lock) && self.socket_key() == socket {
            self.remove_socket();
        }
    }

    /// Identifies the socket file at the address, if there is one.
    fn socket_key(&self) -> Option<SocketKey> {
        // SAFETY: stat is plain data, filled in by the calls below.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let r = match self.address(false).ok()? {
            Address::InFolder(_) => {
                let c = cstr(OsStr::new(SOCKET_FILE)).ok()?;
                // SAFETY: `c` is a valid C string and `self.fd` an open folder.
                unsafe {
                    libc::fstatat(
                        self.fd.as_raw_fd(),
                        c.as_ptr(),
                        &mut st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                }
            }
            Address::Elsewhere(path) => {
                let c = cstr(path.as_os_str()).ok()?;
                // SAFETY: `c` is a valid C string.
                unsafe { libc::lstat(c.as_ptr(), &mut st) }
            }
        };
        (r == 0).then(|| stat_key(&st))
    }

    /// Binds the socket, replacing a dead owner's, and says which file it
    /// made. Only the lock holder may call this.
    fn listen(&self) -> io::Result<(UnixListener, Option<SocketKey>)> {
        let path = self.address(true)?.into_path();
        self.remove_socket();
        let listener = UnixListener::bind(path)?;
        listener.set_nonblocking(true)?;
        Ok((listener, self.socket_key()))
    }

    /// Connects to the owner's socket and checks it is this user's.
    pub(crate) fn connect(&self, deadline: Option<Instant>) -> Result<Conn, Connect> {
        let path = self.address(false).map_err(Connect::Retry)?.into_path();
        let stream = connect(&path, deadline)?;
        let (uid, pid) = peer_cred(stream.as_fd()).map_err(Connect::Retry)?;
        if uid != euid() {
            return Err(Connect::Peer(denied(&format!("socket peer is user {uid}"))));
        }
        Ok(Conn { stream, pid })
    }

    /// Touches the folder, the lock and the socket, so cleaners that go by
    /// age leave them alone.
    fn touch(&self, lock: &Lock) {
        // SAFETY: futimens with null times sets both to now.
        unsafe {
            libc::futimens(self.fd.as_raw_fd(), std::ptr::null());
            libc::futimens(lock.0.as_raw_fd(), std::ptr::null());
        }
        match self.address(false) {
            Ok(Address::InFolder(_)) => {
                let c = cstr(OsStr::new(SOCKET_FILE)).expect("no NUL");
                // SAFETY: `c` is a valid C string and `self.fd` an open folder.
                unsafe {
                    libc::utimensat(
                        self.fd.as_raw_fd(),
                        c.as_ptr(),
                        std::ptr::null(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
            }
            Ok(Address::Elsewhere(path)) => {
                if let Ok(c) = cstr(path.as_os_str()) {
                    // SAFETY: `c` is a valid C string.
                    unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), std::ptr::null(), 0) };
                }
            }
            Err(_) => {}
        }
    }
}

/// A file's device and inode.
type SocketKey = (u64, u64);

enum Address {
    InFolder(PathBuf),
    /// The folder's path is too long for a socket address, and this Unix
    /// can't reach it through a descriptor.
    Elsewhere(PathBuf),
}

impl Address {
    fn into_path(self) -> PathBuf {
        match self {
            Address::InFolder(p) | Address::Elsewhere(p) => p,
        }
    }
}

fn sun_path_len() -> usize {
    // SAFETY: sockaddr_un is plain data.
    let addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_path.len()
}

fn fits(path: &Path) -> bool {
    path.as_os_str().len() < sun_path_len()
}

/// A short folder for sockets whose folder's path is too long: the
/// per-user temporary folder on macOS, root's own base for root where it
/// has one, and the private `/tmp/ih-<uid>` elsewhere. Only an owner
/// binding its socket creates it.
fn short_base(create: bool) -> io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    if let Some(dir) = darwin_temp_dir() {
        return Ok(dir);
    }
    let uid = euid();
    if let Some(root) = ROOT_BASE.filter(|_| uid == 0) {
        open_system(Path::new(root), create)?;
        return Ok(root.into());
    }
    let base = PathBuf::from(format!("/tmp/ih-{uid}"));
    if create {
        make_dir(&base)?;
    }
    let fd = open_dir(None, &base, true)?;
    check_private(fd.as_fd())?;
    Ok(base)
}

pub(crate) enum Connect {
    /// Nobody listening yet, or the owner went away: try again.
    Retry(io::Error),
    /// The other end isn't this user.
    Peer(io::Error),
}

impl From<io::Error> for Connect {
    fn from(e: io::Error) -> Connect {
        Connect::Retry(e)
    }
}

fn sockaddr(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    // SAFETY: sockaddr_un is plain data, all zeroes is valid.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= addr.sun_path.len() || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path too long",
        ));
    }
    for (d, s) in addr.sun_path.iter_mut().zip(bytes) {
        *d = *s as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
    Ok((addr, len as libc::socklen_t))
}

#[cfg(target_os = "macos")]
fn set_cloexec_nonblock(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on an open descriptor.
    unsafe {
        let fl = cvt(libc::fcntl(fd, libc::F_GETFL))?;
        cvt(libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK))?;
        let fd_fl = cvt(libc::fcntl(fd, libc::F_GETFD))?;
        cvt(libc::fcntl(fd, libc::F_SETFD, fd_fl | libc::FD_CLOEXEC))?;
    }
    Ok(())
}

fn connect(path: &Path, deadline: Option<Instant>) -> Result<UnixStream, Connect> {
    let (addr, len) = sockaddr(path)?;
    // Close-on-exec from the start where the OS can: another thread may
    // fork and exec at any moment.
    #[cfg(not(target_os = "macos"))]
    let kind = libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    #[cfg(target_os = "macos")]
    let kind = libc::SOCK_STREAM;
    // SAFETY: a new socket; the result is checked.
    let fd = cvt(unsafe { libc::socket(libc::AF_UNIX, kind, 0) })?;
    // SAFETY: socket returned a new descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    #[cfg(target_os = "macos")]
    set_cloexec_nonblock(fd.as_raw_fd())?;
    no_sigpipe(fd.as_fd());
    // SAFETY: `addr` is a valid sockaddr_un of length `len`.
    let r = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_un).cast(),
            len,
        )
    };
    if r != 0 {
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EINPROGRESS) => {
                wait(fd.as_fd(), libc::POLLOUT, deadline)?;
                let mut err: libc::c_int = 0;
                let mut n = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                // SAFETY: `err` is valid for writes of `n` bytes.
                cvt(unsafe {
                    libc::getsockopt(
                        fd.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        (&mut err as *mut libc::c_int).cast(),
                        &mut n,
                    )
                })?;
                if err != 0 {
                    return Err(Connect::Retry(io::Error::from_raw_os_error(err)));
                }
            }
            // A socket file someone else's process made: its mode keeps us
            // out. Inside a private folder, only the shared fallback for a
            // long path can get here.
            Some(libc::EACCES) | Some(libc::EPERM) => return Err(Connect::Peer(e)),
            _ => return Err(Connect::Retry(e)),
        }
    }
    Ok(UnixStream::from(fd))
}

/// Writes to a closed socket fail with EPIPE instead of killing the process.
fn no_sigpipe(fd: BorrowedFd<'_>) {
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd"
    ))]
    {
        let on: libc::c_int = 1;
        // SAFETY: `on` is valid for reads of its size.
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&on as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd"
    )))]
    let _ = fd;
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "openbsd",
    target_os = "illumos"
))]
const SEND_FLAGS: libc::c_int = libc::MSG_NOSIGNAL;
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "openbsd",
    target_os = "illumos"
)))]
const SEND_FLAGS: libc::c_int = 0;

fn send(fd: BorrowedFd<'_>, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: `buf` is valid for reads of its length.
    let n = unsafe { libc::send(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len(), SEND_FLAGS) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Waits until `fd` is ready for `events`, or `deadline` passes
/// (`TimedOut`).
fn wait(fd: BorrowedFd<'_>, events: libc::c_short, deadline: Option<Instant>) -> io::Result<()> {
    loop {
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events,
            revents: 0,
        };
        let timeout = poll_timeout(deadline, Instant::now());
        if timeout == 0 && deadline.is_some_and(|d| Instant::now() >= d) {
            // One last look, then give up.
            // SAFETY: one valid pollfd.
            let r = unsafe { libc::poll(&mut pfd, 1, 0) };
            if r > 0 {
                return Ok(());
            }
            return Err(io::ErrorKind::TimedOut.into());
        }
        // SAFETY: one valid pollfd.
        match unsafe { libc::poll(&mut pfd, 1, timeout) } {
            -1 => {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
            0 => {}
            _ => return Ok(()),
        }
    }
}

/// Milliseconds until `deadline`, rounded up, for `poll`; -1 for none.
fn poll_timeout(deadline: Option<Instant>, now: Instant) -> libc::c_int {
    match deadline {
        None => -1,
        Some(d) => {
            let left = d.saturating_duration_since(now);
            let ms = left.as_millis() + u128::from(left.subsec_nanos() % 1_000_000 != 0);
            ms.min(i32::MAX as u128) as libc::c_int
        }
    }
}

/// A launch's connection to the owner.
pub(crate) struct Conn {
    stream: UnixStream,
    pid: Option<u32>,
}

impl Conn {
    /// The owner's process id, as the OS reported it.
    pub(crate) fn peer_pid(&self) -> Option<u32> {
        self.pid
    }

    /// Reads some bytes; `Ok(0)` when the owner closed, `TimedOut` past the
    /// deadline.
    pub(crate) fn read(&mut self, buf: &mut [u8], deadline: Option<Instant>) -> io::Result<usize> {
        loop {
            match self.stream.read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    wait(self.stream.as_fd(), libc::POLLIN, deadline)?
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    pub(crate) fn write_all(
        &mut self,
        mut buf: &[u8],
        deadline: Option<Instant>,
    ) -> io::Result<()> {
        while !buf.is_empty() {
            match send(self.stream.as_fd(), buf) {
                Ok(n) => buf = &buf[n..],
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    wait(self.stream.as_fd(), libc::POLLOUT, deadline)?
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Peer credentials
// ---------------------------------------------------------------------------

/// The peer's effective user id, and its process id where the platform
/// gives one. A pid of 0 (another PID namespace) is `None`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_cred(fd: BorrowedFd<'_>) -> io::Result<(libc::uid_t, Option<u32>)> {
    // SAFETY: ucred is plain data; getsockopt writes at most `len` bytes.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    cvt(unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    })?;
    Ok((cred.uid, u32::try_from(cred.pid).ok().filter(|p| *p != 0)))
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn peer_cred(fd: BorrowedFd<'_>) -> io::Result<(libc::uid_t, Option<u32>)> {
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: both out-pointers are valid for writes.
    cvt(unsafe { libc::getpeereid(fd.as_raw_fd(), &mut uid, &mut gid) })?;
    #[cfg(target_os = "macos")]
    let pid = {
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: `pid` is valid for writes of `len` bytes.
        let r = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast(),
                &mut len,
            )
        };
        if r == 0 {
            u32::try_from(pid).ok().filter(|p| *p != 0)
        } else {
            None
        }
    };
    #[cfg(not(target_os = "macos"))]
    let pid = None;
    Ok((uid, pid))
}

#[cfg(target_os = "illumos")]
fn peer_cred(fd: BorrowedFd<'_>) -> io::Result<(libc::uid_t, Option<u32>)> {
    let mut cred: *mut libc::ucred_t = std::ptr::null_mut();
    // SAFETY: getpeerucred allocates `cred`, freed below.
    cvt(unsafe { libc::getpeerucred(fd.as_raw_fd(), &mut cred) })?;
    // SAFETY: `cred` is valid until ucred_free.
    let (uid, pid) = unsafe { (libc::ucred_geteuid(cred), libc::ucred_getpid(cred)) };
    unsafe { libc::ucred_free(cred) };
    Ok((uid, u32::try_from(pid).ok().filter(|p| *p != 0)))
}

// ---------------------------------------------------------------------------
// The owner's thread
// ---------------------------------------------------------------------------

/// Wakes the crate's thread from `poll`: a pipe whose read end it watches.
pub(crate) struct Waker {
    read: Option<OwnedFd>,
    write: Option<OwnedFd>,
}

impl Waker {
    pub(crate) fn new() -> Waker {
        let mut fds = [0; 2];
        // SAFETY: `fds` is valid for two descriptors.
        #[cfg(not(target_os = "macos"))]
        let r = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        #[cfg(target_os = "macos")]
        let r = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if r != 0 {
            log::warn!(
                "instance-handoff: no wake pipe: {}",
                io::Error::last_os_error()
            );
            return Waker {
                read: None,
                write: None,
            };
        }
        // SAFETY: pipe returned two new descriptors that nothing else owns.
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        #[cfg(target_os = "macos")]
        for fd in [&read, &write] {
            if let Err(e) = set_cloexec_nonblock(fd.as_raw_fd()) {
                log::warn!("instance-handoff: wake pipe: {e}");
            }
        }
        Waker {
            read: Some(read),
            write: Some(write),
        }
    }

    pub(crate) fn wake(&self) {
        if let Some(w) = &self.write {
            // SAFETY: one byte from a valid buffer. A full pipe already
            // wakes the thread.
            unsafe { libc::write(w.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
        }
    }

    fn drain(&self) {
        if let Some(r) = &self.read {
            let mut buf = [0u8; 64];
            // SAFETY: `buf` is valid for writes of its length.
            while unsafe { libc::read(r.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
        }
    }
}

/// The folder, the lock and the socket, as the owner holds them.
#[derive(Debug)]
pub(crate) struct Held {
    pub(crate) folder: Option<Folder>,
    pub(crate) lock: Option<Lock>,
    /// The socket file this process bound.
    socket: Option<SocketKey>,
}

impl Held {
    #[cfg(test)]
    pub(crate) fn detached() -> Held {
        Held {
            folder: None,
            lock: None,
            socket: None,
        }
    }

    /// Removes the socket, if it and the lock at the path are still this
    /// process's.
    pub(crate) fn unlink_socket(&self) {
        if let (Some(folder), Some(lock)) = (&self.folder, &self.lock) {
            folder.remove_own_socket(lock, self.socket);
        }
    }
}

/// What `start` hands over to a `Claim`: the folder, the lock, and the
/// listening socket, bound by this process.
#[derive(Debug)]
pub(crate) struct Claimed {
    pub(crate) folder: Folder,
    pub(crate) lock: Lock,
    pub(crate) listener: io::Result<UnixListener>,
    socket: Option<SocketKey>,
    pid: u32,
}

impl Claimed {
    pub(crate) fn new(folder: Folder, lock: Lock, _app_id: &AppId) -> Claimed {
        let (listener, socket) = match folder.listen() {
            Ok((l, key)) => (Ok(l), key),
            Err(e) => (Err(e), None),
        };
        Claimed {
            folder,
            lock,
            listener,
            socket,
            pid: std::process::id(),
        }
    }

    /// Whether this is a forked copy, in a process other than the one that
    /// called `start`.
    pub(crate) fn forked(&self) -> bool {
        self.pid != std::process::id()
    }

    /// Ready to serve in this process. After a fork, the child binds a
    /// fresh socket, so launches see its process id, not the parent's.
    pub(crate) fn into_parts(self) -> (Held, Option<UnixListener>, Option<io::Error>) {
        let (listener, socket) = if self.forked() {
            match self.folder.listen() {
                Ok((l, key)) => (Ok(l), key),
                Err(e) => (Err(e), None),
            }
        } else {
            (self.listener, self.socket)
        };
        let held = Held {
            folder: Some(self.folder),
            lock: Some(self.lock),
            socket,
        };
        match listener {
            Ok(l) => (held, Some(l), None),
            Err(e) => (held, None, Some(e)),
        }
    }

    /// A forked copy that won't serve: close the socket and the folder, and
    /// keep the lock's descriptor open until the process exits.
    pub(crate) fn abandon(self) {
        std::mem::forget(self.lock);
    }

    /// Gives the lock up without serving. A forked copy only closes its
    /// descriptors: the lock stays with the process that still holds it.
    pub(crate) fn release(self) {
        if !self.forked() {
            self.folder.remove_own_socket(&self.lock, self.socket);
        }
        drop(self.lock);
    }
}

struct Connection<T> {
    stream: UnixStream,
    session: Session<T>,
    shut: bool,
}

/// Runs the owner's thread until the handle closes it or the lock is lost.
pub(crate) fn serve<T: Payload>(
    mut core: Core<T>,
    mut listener: Option<UnixListener>,
    place: Place,
) {
    let app_id = core.ctx.app_id.clone();
    let mut conns: Vec<Connection<T>> = Vec::new();
    let mut accept_pause: Option<Instant> = None;
    let upkeep = core.ctx.upkeep;
    let mut next_check = Instant::now() + upkeep.check;
    let mut next_touch = Instant::now() + upkeep.touch;

    while core.poll_control() {
        let now = Instant::now();
        if accept_pause.is_some_and(|until| now >= until) {
            accept_pause = None;
        }
        let accepting = listener.is_some() && accept_pause.is_none();

        let mut fds = Vec::with_capacity(conns.len() + 2);
        let wake = core.shared.waker.read.as_ref().map(|fd| fd.as_raw_fd());
        fds.push(libc::pollfd {
            fd: wake.unwrap_or(-1),
            events: libc::POLLIN,
            revents: 0,
        });
        fds.push(libc::pollfd {
            fd: match (&listener, accepting) {
                (Some(l), true) => l.as_raw_fd(),
                _ => -1,
            },
            events: libc::POLLIN,
            revents: 0,
        });
        for c in &conns {
            let mut events = libc::POLLIN;
            if !c.session.outgoing().is_empty() {
                events |= libc::POLLOUT;
            }
            fds.push(libc::pollfd {
                fd: c.stream.as_raw_fd(),
                events,
                revents: 0,
            });
        }
        let mut deadline = next_check.min(next_touch);
        for c in &conns {
            deadline = deadline.min(c.session.deadline());
        }
        if let Some(until) = accept_pause {
            deadline = deadline.min(until);
        }
        if wake.is_none() {
            // Without a wake pipe, notice stop and drop within 100 ms.
            deadline = deadline.min(now + Duration::from_millis(100));
        }
        // SAFETY: `fds` is a valid array of its length.
        let r = unsafe {
            libc::poll(
                fds.as_mut_ptr(),
                fds.len() as libc::nfds_t,
                poll_timeout(Some(deadline), now),
            )
        };
        if r == -1 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                log::error!("instance-handoff {app_id}: poll: {e}");
                std::thread::sleep(Duration::from_millis(100));
            }
            continue;
        }
        if fds[0].revents != 0 {
            core.shared.waker.drain();
        }
        // The handle may have asked to stop or close while we slept.
        if !core.poll_control() {
            break;
        }
        let now = Instant::now();

        for (c, pfd) in conns.iter_mut().zip(&fds[2..]) {
            if pfd.revents == 0 {
                continue;
            }
            if pfd.revents & libc::POLLOUT != 0 {
                flush(c);
            }
            if pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                read(c, &mut core, now);
            }
        }

        if fds[1].revents != 0 {
            if let Some(l) = &listener {
                accept(l, &mut conns, &core, &mut accept_pause, now);
            }
        }

        let now = Instant::now();
        for c in &mut conns {
            if !c.session.is_done() && now >= c.session.deadline() {
                c.session.timed_out(now);
            }
            flush(c);
            if c.session.should_shut_write() && !c.shut {
                let _ = c.stream.shutdown(std::net::Shutdown::Write);
                c.shut = true;
            }
        }
        conns.retain(|c| !c.session.is_done());

        if now >= next_touch {
            next_touch = now + upkeep.touch;
            let held = core.shared.held();
            if let (Some(folder), Some(lock)) = (&held.folder, &held.lock) {
                folder.touch(lock);
            }
        }
        if now >= next_check {
            next_check = now + upkeep.check;
            if !check_lock(&mut core, &mut listener, &place) {
                break;
            }
        }
    }
    // Closing: launches find nobody listening and retry the lock.
    drop(listener);
}

/// Every minute: is the lock file still the one held? Re-creates the
/// folder, the lock and the socket when something deleted them. `false`
/// when another process took the lock meanwhile.
fn check_lock<T: Payload>(
    core: &mut Core<T>,
    listener: &mut Option<UnixListener>,
    place: &Place,
) -> bool {
    let app_id = core.ctx.app_id.clone();
    let mut held = core.shared.held();
    if core.shared.close.load(Ordering::SeqCst) {
        return true;
    }
    let (Some(folder), Some(lock)) = (&held.folder, &held.lock) else {
        return true;
    };
    if folder.holds(lock) {
        // Gone, or replaced by a socket that nobody answers on (a forked
        // copy that bound its own and exited). A live one is left alone: it
        // is a fork of this process serving the same lock.
        let current = folder.socket_key();
        let ours = listener.is_some() && current.is_some() && current == held.socket;
        let live = || {
            current.is_some()
                && current != held.socket
                && folder
                    .connect(Some(Instant::now() + Duration::from_millis(200)))
                    .is_ok()
        };
        if !ours && !live() {
            log::warn!(
                "instance-handoff {app_id}: the socket isn't this owner's; binding it again"
            );
            match folder.listen() {
                Ok((l, key)) => {
                    *listener = Some(l);
                    held.socket = key;
                }
                Err(e) => log::warn!("instance-handoff {app_id}: socket: {e}"),
            }
        }
        return true;
    }
    match open_folder(place, true) {
        Ok(Some(new)) => match new.lock() {
            Ok(Some(new_lock)) => {
                log::warn!(
                    "instance-handoff {app_id}: the runtime folder {} was removed; re-created it",
                    new.path().display()
                );
                match new.listen() {
                    Ok((l, key)) => {
                        *listener = Some(l);
                        held.socket = key;
                    }
                    Err(e) => {
                        log::warn!("instance-handoff {app_id}: socket: {e}");
                        *listener = None;
                        held.socket = None;
                    }
                }
                held.folder = Some(new);
                held.lock = Some(new_lock);
                true
            }
            Ok(None) => {
                log::warn!(
                    "instance-handoff {app_id}: the runtime folder was removed, and another \
                     process now holds the lock: this process is no longer the owner"
                );
                drop(held);
                // The files at the path are the new owner's: remove nothing.
                *listener = None;
                core.end(crate::End::LostLock);
                false
            }
            Err(e) => {
                log::warn!("instance-handoff {app_id}: re-creating the lock: {e}");
                true
            }
        },
        // The folder can't be made now (the session's runtime folder is
        // gone until the next login): keep the lock held, and look again.
        Ok(None) => true,
        Err(reason) => {
            log::debug!("instance-handoff {app_id}: re-creating the folder: {reason}");
            true
        }
    }
}

fn accept<T: Payload>(
    listener: &UnixListener,
    conns: &mut Vec<Connection<T>>,
    core: &Core<T>,
    pause: &mut Option<Instant>,
    now: Instant,
) {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                if conns.len() >= MAX_CONNECTIONS {
                    // The launch sees EOF before HELLO and tries again.
                    continue;
                }
                // A launch this owner won't serve is told so at once, in
                // place of HELLO, rather than left to wait out its timeout.
                let session = match peer_cred(stream.as_fd()) {
                    Ok((uid, pid)) if uid == euid() => Session::new(core, pid, now),
                    Ok((uid, _)) => {
                        log::warn!(
                            "instance-handoff {}: refused a connection from user {uid}",
                            core.ctx.app_id
                        );
                        Session::refused(refusal::PEER, now)
                    }
                    Err(e) => {
                        log::warn!("instance-handoff {}: peer check: {e}", core.ctx.app_id);
                        Session::refused(refusal::PEER, now)
                    }
                };
                if let Err(e) = stream.set_nonblocking(true) {
                    log::warn!("instance-handoff {}: {e}", core.ctx.app_id);
                    continue;
                }
                no_sigpipe(stream.as_fd());
                let mut c = Connection {
                    stream,
                    session,
                    shut: false,
                };
                flush(&mut c);
                conns.push(c);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
                ) => {}
            Err(e) => {
                // Out of descriptors or memory: pause accepting rather than
                // spin on an error that won't clear by itself.
                log::warn!("instance-handoff {}: accept: {e}", core.ctx.app_id);
                *pause = Some(now + Duration::from_millis(100));
                return;
            }
        }
    }
}

fn flush<T: Payload>(c: &mut Connection<T>) {
    while !c.session.outgoing().is_empty() {
        match send(c.stream.as_fd(), c.session.outgoing()) {
            Ok(n) => c.session.wrote(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                c.session.broken();
                return;
            }
        }
    }
}

fn read<T: Payload>(c: &mut Connection<T>, core: &mut Core<T>, now: Instant) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match c.stream.read(&mut buf) {
            Ok(0) => {
                c.session.eof(&core.ctx.app_id);
                return;
            }
            Ok(n) => {
                if let Some(request) = c.session.read(&buf[..n], core, now) {
                    match core.deliver(request) {
                        Some(answer) => c.session.answer(answer, Instant::now()),
                        None => c.session.abandon(),
                    }
                }
                flush(c);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                c.session.broken();
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: AppId = AppId::new("app.test");

    fn env() -> LinuxEnv {
        LinuxEnv {
            euid: 1000,
            ..LinuxEnv::default()
        }
    }

    fn base(place: Result<Place, Reason>) -> Result<(PathBuf, Base, Vec<OsString>), String> {
        place
            .map(|p| (p.base, p.kind, p.subs))
            .map_err(|r| r.to_string())
    }

    // One case per launch context. Two launches of one user meet only if
    // they land in the same row.
    #[test]
    fn the_linux_folder_rule() {
        let session = LinuxEnv {
            systemd: true,
            run_user: Some("/run/user/1000".into()),
            xdg_runtime_dir: Some("/run/user/1000".into()),
            ..env()
        };
        assert_eq!(
            base(linux_rule(&session, &ID)),
            Ok((
                "/run/user/1000".into(),
                Base::Trusted,
                vec!["app.test".into()]
            ))
        );

        // Outside a snap or Flatpak, root has one folder, logged in or not,
        // whatever its environment says: sudo -E keeps the user's
        // XDG_RUNTIME_DIR, and a stale one names a folder that is gone.
        let root = LinuxEnv {
            systemd: true,
            euid: 0,
            ..env()
        };
        let sudo = LinuxEnv {
            xdg_runtime_dir: Some("/run/user/1000".into()),
            ..root.clone()
        };
        let stale = LinuxEnv {
            xdg_runtime_dir: Some("/run/user/0".into()),
            ..root.clone()
        };
        let logged_in = LinuxEnv {
            run_user: Some("/run/user/0".into()),
            ..stale.clone()
        };
        let without_systemd = LinuxEnv {
            systemd: false,
            ..root.clone()
        };
        for launch in [root, sudo, stale, logged_in, without_systemd] {
            assert_eq!(
                base(linux_rule(&launch, &ID)),
                Ok((
                    "/run/instance-handoff".into(),
                    Base::System,
                    vec!["app.test".into()]
                )),
                "{launch:?}"
            );
        }

        // cron, @reboot, a system service: no session, no folder, no
        // fallback.
        let cron = LinuxEnv {
            systemd: true,
            ..env()
        };
        assert!(matches!(linux_rule(&cron, &ID), Err(Reason::NoSession {})));
        let cron_with_stale_var = LinuxEnv {
            xdg_runtime_dir: Some("/run/user/1000".into()),
            ..cron
        };
        assert!(matches!(
            linux_rule(&cron_with_stale_var, &ID),
            Err(Reason::NoSession {})
        ));

        // No systemd: always /tmp, whatever else exists.
        let elogind = LinuxEnv {
            xdg_runtime_dir: Some("/run/user/1000".into()),
            run_user: Some("/run/user/1000".into()),
            ..env()
        };
        assert_eq!(
            base(linux_rule(&elogind, &ID)),
            Ok(("/tmp".into(), Base::Shared, vec!["app.test-1000".into()]))
        );

        let flatpak = LinuxEnv {
            flatpak_id: Some("org.example.App".into()),
            xdg_runtime_dir: Some("/run/user/1000".into()),
            systemd: true,
            ..env()
        };
        assert_eq!(
            base(linux_rule(&flatpak, &ID)).unwrap().0,
            PathBuf::from("/run/user/1000/app/org.example.App")
        );
        let flatpak_without_xdg = LinuxEnv {
            xdg_runtime_dir: None,
            ..flatpak
        };
        assert!(matches!(
            linux_rule(&flatpak_without_xdg, &ID),
            Err(Reason::NoRuntimeDir {})
        ));

        let snap = LinuxEnv {
            snap: true,
            xdg_runtime_dir: Some("/run/user/1000/snap.app".into()),
            systemd: true,
            ..env()
        };
        assert_eq!(
            base(linux_rule(&snap, &ID)).unwrap().0,
            PathBuf::from("/run/user/1000/snap.app")
        );

        // The sandboxes set the runtime folder, for root too.
        let root_snap = LinuxEnv {
            xdg_runtime_dir: Some("/run/user/0/snap.app".into()),
            euid: 0,
            ..snap
        };
        assert_eq!(
            base(linux_rule(&root_snap, &ID)).unwrap().0,
            PathBuf::from("/run/user/0/snap.app")
        );
    }

    // Root's base: made only where its parent exists, and refused when it
    // is a link or others can write to it. Any user can run this, since the
    // owner it must have is this process's user.
    #[test]
    fn the_root_base_is_made_and_checked() {
        use std::os::unix::fs::PermissionsExt;
        let set_mode = |path: &Path, mode| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap()
        };
        let system = |base: PathBuf| Place {
            base,
            kind: Base::System,
            subs: vec!["app.test".into()],
        };
        let tmp = tempfile::tempdir().unwrap();
        let err = open_folder(&system(tmp.path().join("no").join("base")), true).unwrap_err();
        assert!(matches!(err, Reason::RuntimeDir { .. }), "{err}");

        let base = tmp.path().join("base");
        assert!(open_folder(&system(base.clone()), false).unwrap().is_none());
        assert!(open_folder(&system(base.clone()), true).unwrap().is_some());
        let mode = std::fs::metadata(&base).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);

        // Others may read it, but not write to it.
        set_mode(&base, 0o755);
        assert!(open_folder(&system(base.clone()), true).unwrap().is_some());
        for mode in [0o775, 0o757] {
            set_mode(&base, mode);
            let err = open_folder(&system(base.clone()), true).unwrap_err();
            assert!(matches!(err, Reason::RuntimeDir { .. }), "{mode:o}: {err}");
        }

        set_mode(&base, 0o700);
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&base, &link).unwrap();
        let err = open_folder(&system(link), true).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_macos_base_is_resolved() {
        let place = default_place(&ID).unwrap();
        assert_eq!(std::fs::canonicalize(&place.base).unwrap(), place.base);
        let base = Place {
            subs: Vec::new(),
            ..place
        };
        assert!(open_folder(&base, false).unwrap().is_some());
    }

    // Outside fakeroot, the system calls and the C library agree.
    #[test]
    fn the_kernel_and_the_c_library_agree() {
        // SAFETY: geteuid has no preconditions and can't fail.
        assert_eq!(euid(), unsafe { libc::geteuid() });
        let tmp = tempfile::tempdir().unwrap();
        let folder = open_folder(&Place::dir(tmp.path().join("run")), true)
            .unwrap()
            .unwrap();
        let lock = folder.lock().unwrap().unwrap();
        for fd in [folder.fd.as_fd(), lock.0.as_fd()] {
            let st = fstat(fd).unwrap();
            assert_eq!(owner_mode(fd).unwrap(), (st.st_uid, st.st_mode));
        }
    }

    #[test]
    fn folders_open_to_others_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("run");
        std::fs::create_dir(&dir).unwrap();
        for mode in [0o777, 0o755, 0o740] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = open_folder(&Place::dir(dir.clone()), true).unwrap_err();
            assert!(matches!(err, Reason::RuntimeDir { .. }), "{mode:o}: {err}");
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            open_folder(&Place::dir(dir.clone()), true)
                .unwrap()
                .is_some()
        );

        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        let err = open_folder(&Place::dir(link), true).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");

        // A scope subfolder someone swapped for a symlink.
        let mut scoped = Place::dir(dir.clone());
        scoped.push("s");
        std::os::unix::fs::symlink("/tmp", dir.join("s")).unwrap();
        assert!(open_folder(&scoped, true).is_err());
    }

    #[test]
    fn without_create_a_missing_folder_means_nobody() {
        let tmp = tempfile::tempdir().unwrap();
        let mut place = Place::dir(tmp.path().join("none"));
        assert!(open_folder(&place, false).unwrap().is_none());
        // tempfile makes 0755 folders: a folder below it is made private.
        let run = tmp.path().join("run");
        open_folder(&Place::dir(run.clone()), true)
            .unwrap()
            .unwrap();
        place = Place::dir(run);
        place.push("sub");
        assert!(open_folder(&place, false).unwrap().is_none());
    }

    #[test]
    fn the_lock_file_is_private_and_exclusive() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let folder = open_folder(&Place::dir(tmp.path().join("run")), true)
            .unwrap()
            .unwrap();
        let lock = folder.lock().unwrap().unwrap();
        let mode = std::fs::metadata(folder.lock_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(folder.lock().unwrap().is_none());
        assert!(folder.lock_held().unwrap());
        assert!(folder.holds(&lock));
        drop(lock);
        assert!(!folder.lock_held().unwrap());
    }

    #[test]
    fn long_folders_still_get_a_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("x".repeat(150)).join("run");
        let folder = open_folder(&Place::dir(dir), true).unwrap().unwrap();
        let _lock = folder.lock().unwrap().unwrap();
        let listener = folder.listen().unwrap();
        let conn = folder.connect(None).ok().expect("connects");
        assert_eq!(conn.peer_pid(), Some(std::process::id()));
        drop(listener);
    }

    #[test]
    fn poll_timeouts_round_up() {
        let now = Instant::now();
        assert_eq!(poll_timeout(None, now), -1);
        assert_eq!(poll_timeout(Some(now), now), 0);
        assert_eq!(poll_timeout(Some(now + Duration::from_micros(10)), now), 1);
        assert_eq!(poll_timeout(Some(now + Duration::from_millis(5)), now), 5);
    }
}
