//! Unix: the runtime folder, an `flock` on `instance.lock`, an AF_UNIX
//! socket beside it, another `flock` on the guard in the state folder, and
//! a `poll` loop on the crate's thread.

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

use crate::level::OwnerLevel;
use crate::naming;
use crate::server::{Core, Peer, Session};
use crate::wire::refusal;
use crate::{AppId, Payload, Reason};

// On 32-bit targets glibc's stat calls fail with EOVERFLOW for a file whose
// inode number doesn't fit in 32 bits, as on XFS with inode64 or overlayfs
// with xino. Its *64 calls can't, and on 64-bit targets they are the same
// calls. musl and bionic count in 64 bits everywhere.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
use libc::{fstat as sys_fstat, fstatat as sys_fstatat, lstat as sys_lstat, stat as Stat};
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use libc::{fstat64 as sys_fstat, fstatat64 as sys_fstatat, lstat64 as sys_lstat, stat64 as Stat};

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

/// `path` with its links resolved: `realpath`.
pub(crate) fn final_path(path: &Path) -> io::Result<PathBuf> {
    std::fs::canonicalize(path)
}

// ---------------------------------------------------------------------------
// Who may own
// ---------------------------------------------------------------------------

/// What tells a raised launch, gathered apart from the rule so that the
/// rule can be tested.
#[derive(Debug)]
pub(crate) struct RaisedEnv {
    pub(crate) euid: u32,
    /// `SUDO_UID`: the user who ran `sudo` or `run0`.
    pub(crate) sudo_uid: Option<u32>,
    /// `PKEXEC_UID`: the user who ran `pkexec`.
    pub(crate) pkexec_uid: Option<u32>,
    /// `DOAS_USER`, the name of the user who ran `doas`, as a user id.
    pub(crate) doas_user: Option<u32>,
    /// On Linux, `/proc/self/loginuid`: the user who logged in, which `su`
    /// and `sudo` keep. `None` when it is unset (4294967295).
    pub(crate) loginuid: Option<u32>,
}

/// Whether a launch's rights were raised from a login: it is root, and the
/// person who logged in is known and isn't root. Root's own login, a
/// service and a container's root name root or nobody. This only keeps
/// launches from owning, so a person it can't see, as after `su` on macOS
/// and the BSDs, leaves the launch free to own.
pub(crate) fn raised_from(env: &RaisedEnv) -> bool {
    env.euid == 0
        && [env.sudo_uid, env.pkexec_uid, env.doas_user, env.loginuid]
            .into_iter()
            .flatten()
            .any(|uid| uid != 0)
}

/// The id of the user named `name`, from the user database.
fn uid_of(name: &OsStr) -> Option<u32> {
    let c = cstr(name).ok()?;
    let mut buf = vec![0u8; 1024];
    loop {
        // SAFETY: passwd is plain data; getpwnam_r fills it in.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `c` is a valid C string, `pwd` and `found` are valid for
        // writes, and `buf` for writes of its length.
        let r = unsafe {
            libc::getpwnam_r(
                c.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut found,
            )
        };
        if r == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        return (r == 0 && !found.is_null()).then_some(pwd.pw_uid);
    }
}

/// The user who logged in, as the kernel keeps it for this process. Only
/// Linux keeps one.
fn loginuid() -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        let text = std::fs::read_to_string("/proc/self/loginuid").ok()?;
        text.trim().parse().ok().filter(|&uid| uid != u32::MAX)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn raised_env() -> RaisedEnv {
    let uid = |name: &str| -> Option<u32> { std::env::var(name).ok()?.parse().ok() };
    RaisedEnv {
        euid: euid(),
        sudo_uid: uid("SUDO_UID"),
        pkexec_uid: uid("PKEXEC_UID"),
        doas_user: std::env::var_os("DOAS_USER").and_then(|name| uid_of(&name)),
        loginuid: loginuid(),
    }
}

/// Whether this launch's rights were raised from a login.
pub(crate) fn raised() -> bool {
    raised_from(&raised_env())
}

/// Whether this launch has more rights than a normal process: it is root.
pub(crate) fn above_normal() -> bool {
    euid() == 0
}

/// This process's integrity level: none, since only Windows has them.
pub(crate) fn level() -> Option<crate::Level> {
    None
}

/// The display variables, gathered apart from the rule so that the rule
/// can be tested.
// macOS asks the login session instead, and Android can't tell.
#[cfg_attr(any(target_os = "macos", target_os = "android"), allow(dead_code))]
#[derive(Debug)]
pub(crate) struct DisplayEnv {
    /// `WAYLAND_DISPLAY`: the Wayland compositor's socket.
    pub(crate) wayland_display: Option<OsString>,
    /// `DISPLAY`: the X server.
    pub(crate) display: Option<OsString>,
}

/// Whether a launch on Linux, the BSDs or illumos can show windows: a
/// display variable is set and not empty. A stale `DISPLAY` says yes, and
/// a compositor that a client would find without `WAYLAND_DISPLAY` says
/// no.
#[cfg_attr(any(target_os = "macos", target_os = "android"), allow(dead_code))]
pub(crate) fn shows_windows_from(env: &DisplayEnv) -> bool {
    [&env.wayland_display, &env.display]
        .into_iter()
        .flatten()
        .any(|value| !value.is_empty())
}

#[cfg_attr(any(target_os = "macos", target_os = "android"), allow(dead_code))]
fn display_env() -> DisplayEnv {
    DisplayEnv {
        wayland_display: std::env::var_os("WAYLAND_DISPLAY"),
        display: std::env::var_os("DISPLAY"),
    }
}

/// Whether this launch can show windows, or `None` where that can't be
/// told.
pub(crate) fn can_show_windows() -> Option<bool> {
    #[cfg(target_os = "macos")]
    {
        session_has_graphics()
    }
    #[cfg(target_os = "android")]
    {
        None
    }
    #[cfg(not(any(target_os = "macos", target_os = "android")))]
    {
        Some(shows_windows_from(&display_env()))
    }
}

/// Whether this process's login session may use the window server:
/// `SessionGetInfo`'s graphic-access bit. A login over `ssh` and a daemon
/// have none. `None` when the session can't be read.
#[cfg(target_os = "macos")]
fn session_has_graphics() -> Option<bool> {
    // From <Security/AuthSession.h>: the caller's own session, and the
    // bit.
    const CALLER_SECURITY_SESSION: u32 = u32::MAX;
    const SESSION_HAS_GRAPHIC_ACCESS: u32 = 0x0010;
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SessionGetInfo(session: u32, session_id: *mut u32, attributes: *mut u32) -> i32;
    }
    let mut attributes = 0u32;
    // SAFETY: `attributes` is valid for writes. The session id may be
    // null, and then isn't written.
    let status = unsafe {
        SessionGetInfo(
            CALLER_SECURITY_SESSION,
            std::ptr::null_mut(),
            &mut attributes,
        )
    };
    (status == 0).then_some(attributes & SESSION_HAS_GRAPHIC_ACCESS != 0)
}

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
                let mut st: Stat = unsafe { std::mem::zeroed() };
                let r =
                    unsafe { sys_fstatat(dirfd, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
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

fn fstat(fd: BorrowedFd<'_>) -> io::Result<Stat> {
    // SAFETY: stat is plain data; fstat fills it in.
    let mut st: Stat = unsafe { std::mem::zeroed() };
    cvt(unsafe { sys_fstat(fd.as_raw_fd(), &mut st) })?;
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
        // The empty path with AT_EMPTY_PATH names `fd` itself.
        if let Some(found) = statx_owner_mode(fd.as_raw_fd(), c"", libc::AT_EMPTY_PATH) {
            return found;
        }
    }
    let st = fstat(fd)?;
    Ok((st.st_uid, st.st_mode))
}

/// The owner of the file at `path`, following links, read as [`owner_mode`]
/// reads it. Unlike opening the file, this needs no right to read it.
fn path_owner(path: &Path) -> io::Result<libc::uid_t> {
    let c = cstr(path.as_os_str())?;
    #[cfg(all(target_os = "linux", any(target_env = "gnu", target_env = "musl")))]
    {
        if let Some(found) = statx_owner_mode(libc::AT_FDCWD, &c, 0) {
            return found.map(|(uid, _)| uid);
        }
    }
    // SAFETY: stat is plain data; fstatat fills it in.
    let mut st: Stat = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid C string, and `st` is valid for writes.
    cvt(unsafe { sys_fstatat(libc::AT_FDCWD, c.as_ptr(), &mut st, 0) })?;
    Ok(st.st_uid)
}

/// A file's owner and mode from the `statx` system call: `path` from
/// `dirfd`, with `flags`. `None` where the kernel (before 4.11) or a
/// seccomp filter refuses the call.
#[cfg(all(target_os = "linux", any(target_env = "gnu", target_env = "musl")))]
fn statx_owner_mode(
    dirfd: libc::c_int,
    path: &std::ffi::CStr,
    flags: libc::c_int,
) -> Option<io::Result<(libc::uid_t, libc::mode_t)>> {
    const WANT: libc::c_uint = libc::STATX_UID | libc::STATX_MODE;
    // SAFETY: statx is plain data; the kernel fills it in.
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: `path` is a valid C string, and `stx` is valid for writes of
    // the kernel's struct, checked above.
    let r = unsafe {
        libc::syscall(
            libc::SYS_statx,
            dirfd,
            path.as_ptr(),
            flags,
            WANT,
            &mut stx as *mut libc::statx,
        )
    };
    if r == 0 {
        if stx.stx_mask & WANT != WANT {
            return Some(Err(denied("its owner or mode is unknown")));
        }
        return Some(Ok((stx.stx_uid, stx.stx_mode.into())));
    }
    let e = io::Error::last_os_error();
    if matches!(e.raw_os_error(), Some(libc::ENOSYS | libc::EPERM)) {
        return None;
    }
    Some(Err(e))
}

/// Whether a launch whose effective user is `euid` may keep its state in a
/// folder that `owner` owns: its own, or root's. Root trusts only its own,
/// so root given the user's home finds it another user's.
fn trusted_owner(owner: libc::uid_t, euid: libc::uid_t) -> bool {
    owner == euid || owner == 0
}

/// Whether the file at `path` belongs to a user this process doesn't
/// trust with its state (see [`trusted_owner`]).
pub(crate) fn is_foreign(path: &Path) -> io::Result<bool> {
    Ok(!trusted_owner(path_owner(path)?, euid()))
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

/// Takes an `flock` without waiting: `op` is `LOCK_EX` or `LOCK_SH`.
/// `false` when another open file holds a lock that conflicts.
fn flock_nb(fd: BorrowedFd<'_>, op: libc::c_int) -> io::Result<bool> {
    loop {
        // SAFETY: flock on an open descriptor.
        match cvt(unsafe { libc::flock(fd.as_raw_fd(), op | libc::LOCK_NB) }) {
            Ok(_) => return Ok(true),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

fn stat_key(st: &Stat) -> (u64, u64) {
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
        Ok(flock_nb(fd.as_fd(), libc::LOCK_EX)?.then_some(Lock(fd)))
    }

    /// Whether another process holds the lock, without creating anything.
    /// The lock is taken and dropped at once to find out.
    pub(crate) fn lock_held(&self) -> io::Result<bool> {
        match self.open_lock(false) {
            Ok(fd) => flock_nb(fd.as_fd(), libc::LOCK_EX).map(|got| !got),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// The level of the owner that holds the lock: always this launch's,
    /// since Unix has no integrity levels.
    pub(crate) fn owner_level(&self) -> io::Result<OwnerLevel> {
        Ok(OwnerLevel::Same)
    }

    /// Whether the path still names the lock file `lock` holds.
    fn holds(&self, lock: &Lock) -> bool {
        let Ok(c) = cstr(self.lock_path().as_os_str()) else {
            return false;
        };
        // SAFETY: stat is plain data; lstat fills it in.
        let mut st: Stat = unsafe { std::mem::zeroed() };
        if unsafe { sys_lstat(c.as_ptr(), &mut st) } != 0 {
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
        let mut st: Stat = unsafe { std::mem::zeroed() };
        let r = match self.address(false).ok()? {
            Address::InFolder(_) => {
                let c = cstr(OsStr::new(SOCKET_FILE)).ok()?;
                // SAFETY: `c` is a valid C string and `self.fd` an open folder.
                unsafe {
                    sys_fstatat(
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
                unsafe { sys_lstat(c.as_ptr(), &mut st) }
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

    /// Connects to the owner's socket and checks it is this user's. Unix
    /// has no integrity levels, so `_level` is always `None`.
    pub(crate) fn connect(
        &self,
        deadline: Option<Instant>,
        _level: Option<crate::Level>,
    ) -> Result<Conn, Connect> {
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
// The state folder and its guard
// ---------------------------------------------------------------------------

/// Creates the canonical `state` folder when nothing is at its path: the
/// folders above it as `create_dir_all` makes them, and the last one
/// private (0700). Whatever is there already is left as it is, for
/// [`take_guard`] to open or refuse.
pub(crate) fn make_state_dir(state: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(state) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = state.parent() {
                std::fs::create_dir_all(parent)?;
            }
            make_dir(state)
        }
        found => found.map(drop),
    }
}

/// The held guard: an `flock` on `.instance-handoff.lock` in the state
/// folder, exclusive or shared. Like [`Lock`], it is released when the
/// last descriptor closes and never unlocked explicitly, so a forked child
/// that keeps a copy keeps the guard.
///
/// The state folder is held open beside the file. An inode that is open
/// stays in use, so no other folder or file gets the device and inode of
/// either while they are held, and the owner's upkeep can tell from them
/// whether the paths still name what it holds ([`Guard::look`]).
#[derive(Debug)]
pub(crate) struct Guard {
    file: OwnedFd,
    dir: OwnedFd,
    /// The canonical state folder.
    state: PathBuf,
    shared: bool,
}

/// What the owner's upkeep found at the guard's paths.
enum GuardFound {
    /// The state folder and the guard file the owner holds.
    InPlace,
    /// The guard file was removed or replaced, and the owner now locks the
    /// file at its path instead.
    Retaken,
    /// The state folder was removed or replaced, or another process holds
    /// the guard file now at its path.
    Lost,
    /// The guard file was removed or replaced, and the one at its path
    /// can't be made, opened or locked now; or a path, or what the guard
    /// holds, can't be looked at. The owner keeps what it holds, and looks
    /// again.
    Unknown(io::Error),
}

/// `LOCK_SH` for a keyed owner's guard, and otherwise `LOCK_EX`.
fn guard_op(shared: bool) -> libc::c_int {
    if shared { libc::LOCK_SH } else { libc::LOCK_EX }
}

/// Takes the guard in the canonical `state` folder, which
/// [`make_state_dir`] has made: `shared` (`LOCK_SH`) for a keyed owner, so
/// keyed owners hold it side by side, and otherwise exclusive (`LOCK_EX`).
/// Each owner opens the file afresh, so its lock is its own: a second
/// `flock` on one open file would only convert the first.
/// [`Reason::StateInUse`] when another owner holds it in a mode that
/// conflicts. `None` on a network file system, or where the file system
/// can't lock files: the owner goes unguarded.
pub(crate) fn take_guard(state: &Path, shared: bool) -> Result<Option<Guard>, Reason> {
    let path = state.join(naming::GUARD_FILE);
    let (dir, file) = match open_guard(state) {
        Ok(Some(opened)) => opened,
        Ok(None) => {
            log::debug!(
                "instance-handoff: {} is on a network file system, so this owner holds no guard",
                state.display()
            );
            return Ok(None);
        }
        Err(source) => return Err(Reason::Lock { path, source }),
    };
    match flock_nb(file.as_fd(), guard_op(shared)) {
        Ok(true) => Ok(Some(Guard {
            file,
            dir,
            state: state.to_owned(),
            shared,
        })),
        Ok(false) => Err(Reason::StateInUse { path }),
        Err(e) if locks_unsupported(&e) => {
            log::warn!(
                "instance-handoff: {} can't be locked, so this owner holds no guard: {e}",
                path.display()
            );
            Ok(None)
        }
        Err(source) => Err(Reason::Lock { path, source }),
    }
}

/// Opens the `state` folder, and the guard file in it ([`open_guard_in`]).
/// `None`, with nothing made, when `state` is on a network file system.
fn open_guard(state: &Path) -> io::Result<Option<(OwnedFd, OwnedFd)>> {
    open_guard_with(state, is_network)
}

/// [`open_guard`], asking `network` whether the folder is on a network
/// file system, so a test can say it is.
fn open_guard_with(
    state: &Path,
    network: fn(BorrowedFd<'_>) -> bool,
) -> io::Result<Option<(OwnedFd, OwnedFd)>> {
    let dir = open_dir(None, state, true)?;
    if network(dir.as_fd()) {
        return Ok(None);
    }
    let file = open_guard_in(dir.as_fd())?;
    Ok(Some((dir, file)))
}

/// Opens the guard file in the state folder open as `dir`, creating it.
/// Read-only, since `flock` needs no more on a local disk, so a guard file
/// that exists can be locked in a folder that is read-only. Non-blocking,
/// so a FIFO in its place can't hold the launch up.
fn open_guard_in(dir: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    let c = cstr(OsStr::new(naming::GUARD_FILE))?;
    let flags =
        libc::O_RDONLY | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    let mode: libc::c_uint = 0o600;
    // SAFETY: `c` is a valid C string and `dir` an open folder.
    let fd = cvt(unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags, mode) })?;
    // SAFETY: openat returned a new descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    if fstat(fd.as_fd())?.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a file"));
    }
    if owner_mode(fd.as_fd())?.0 != euid() {
        return Err(denied("owned by another user"));
    }
    Ok(fd)
}

/// The device and inode of what is at `path`, from the folder open as
/// `at` or else from the working directory, without following a link
/// there.
fn lstat_key(at: Option<BorrowedFd<'_>>, path: &Path) -> io::Result<(u64, u64)> {
    let c = cstr(path.as_os_str())?;
    let dirfd = at.map_or(libc::AT_FDCWD, |fd| fd.as_raw_fd());
    // SAFETY: stat is plain data; fstatat fills it in.
    let mut st: Stat = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid C string, and `st` is valid for writes.
    cvt(unsafe { sys_fstatat(dirfd, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) })?;
    Ok(stat_key(&st))
}

impl Guard {
    /// The guard file's path.
    fn path(&self) -> PathBuf {
        self.state.join(naming::GUARD_FILE)
    }

    /// Whether the state folder's path, then the guard file's path in the
    /// folder held, still name what this guard holds: the same device and
    /// inode, and not a link. A guard file removed (its path names nothing)
    /// or replaced (it names another file) in that folder is opened, made
    /// if missing, and locked again in the same mode, unless another
    /// process holds the new one in a mode that conflicts. Any other error
    /// is [`GuardFound::Unknown`]: a second lock on the file held, were it
    /// still in place, would conflict with this guard's own.
    fn look(&mut self) -> GuardFound {
        let held = |fd: &OwnedFd| fstat(fd.as_fd()).map(|st| stat_key(&st));
        match (lstat_key(None, &self.state), held(&self.dir)) {
            (Ok(found), Ok(ours)) if found == ours => {}
            (Ok(_), Ok(_)) => return GuardFound::Lost,
            (Err(e), _)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                return GuardFound::Lost;
            }
            (Err(e), _) | (_, Err(e)) => return GuardFound::Unknown(e),
        }
        let ours = match held(&self.file) {
            Ok(ours) => ours,
            Err(e) => return GuardFound::Unknown(e),
        };
        let name = Path::new(naming::GUARD_FILE);
        match lstat_key(Some(self.dir.as_fd()), name) {
            Ok(found) if found == ours => return GuardFound::InPlace,
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return GuardFound::Unknown(e),
        }
        let file = match open_guard_in(self.dir.as_fd()) {
            Ok(file) => file,
            Err(e) => return GuardFound::Unknown(e),
        };
        // Put back since the look above: it is the file held.
        match held(&file) {
            Ok(found) if found == ours => return GuardFound::InPlace,
            Ok(_) => {}
            Err(e) => return GuardFound::Unknown(e),
        }
        match flock_nb(file.as_fd(), guard_op(self.shared)) {
            Ok(true) => {
                // Closing the old file gives its lock up.
                self.file = file;
                GuardFound::Retaken
            }
            Ok(false) => GuardFound::Lost,
            Err(e) => GuardFound::Unknown(e),
        }
    }
}

/// Whether `e`, from `flock` on the guard file [`open_guard`] just opened,
/// says that the file system can't lock it. `ENOTSUP` is `EOPNOTSUPP` on
/// Linux and FreeBSD, and a number of its own elsewhere. `EBADF`, on a
/// descriptor just opened, is NFS: its client emulates `flock` with POSIX
/// locks on the server, and an exclusive one needs a descriptor open for
/// writing (flock(2)), which the guard's isn't. A shared one needs only
/// reading, so a keyed owner there holds the guard.
fn locks_unsupported(e: &io::Error) -> bool {
    e.raw_os_error().is_some_and(|code| {
        [libc::ENOLCK, libc::EOPNOTSUPP, libc::ENOTSUP, libc::EBADF].contains(&code)
    })
}

/// Whether the folder open as `fd` is on a network file system, which
/// [`Guard::Local`](crate::Guard::Local) leaves unguarded. One whose file
/// system can't be read counts as local, and the lock decides.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn is_network(fd: BorrowedFd<'_>) -> bool {
    // On 32-bit targets glibc's fstatfs fails with EOVERFLOW when a volume
    // has more than 2^32 blocks or files, as a large share can. Its
    // fstatfs64 can't, and on 64-bit targets it is the same call. musl and
    // bionic count in 64 bits everywhere.
    #[cfg(not(target_env = "gnu"))]
    use libc::{fstatfs, statfs};
    #[cfg(target_env = "gnu")]
    use libc::{fstatfs64 as fstatfs, statfs64 as statfs};
    // SAFETY: statfs is plain data; fstatfs fills it in.
    let mut st: statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is open, and `st` is valid for writes.
    if unsafe { fstatfs(fd.as_raw_fd(), &mut st) } != 0 {
        return false;
    }
    // Its type differs by architecture and C library (signed or unsigned,
    // 32 or 64 bits), but the magic numbers are 32 bits.
    #[allow(clippy::unnecessary_cast)]
    let magic = st.f_type as u32;
    network_magic(magic)
}

/// macOS and these BSDs mark each local file system `MNT_LOCAL`. The
/// flags' type, and the constant's, differ on each.
#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd"
))]
#[allow(clippy::unnecessary_cast)]
fn is_network(fd: BorrowedFd<'_>) -> bool {
    // SAFETY: statfs is plain data; fstatfs fills it in.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is open, and `st` is valid for writes.
    if unsafe { libc::fstatfs(fd.as_raw_fd(), &mut st) } != 0 {
        return false;
    }
    st.f_flags as u64 & libc::MNT_LOCAL as u64 == 0
}

/// NetBSD has no `fstatfs`, but its `fstatvfs` gives the mount flags.
#[cfg(target_os = "netbsd")]
fn is_network(fd: BorrowedFd<'_>) -> bool {
    // SAFETY: statvfs is plain data; fstatvfs fills it in.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is open, and `st` is valid for writes.
    if unsafe { libc::fstatvfs(fd.as_raw_fd(), &mut st) } != 0 {
        return false;
    }
    st.f_flag & libc::MNT_LOCAL as libc::c_ulong == 0
}

/// illumos marks no file system local, so this goes by its type's name.
/// Each NFS version is a file system type of its own there.
#[cfg(target_os = "illumos")]
fn is_network(fd: BorrowedFd<'_>) -> bool {
    // SAFETY: statvfs is plain data; fstatvfs fills it in.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is open, and `st` is valid for writes.
    if unsafe { libc::fstatvfs(fd.as_raw_fd(), &mut st) } != 0 {
        return false;
    }
    #[allow(clippy::unnecessary_cast)]
    let name = st.f_basetype.map(|c| c as u8);
    let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    network_type_name(&name[..len])
}

/// Whether a file system type Linux reports from `statfs` is a network or
/// cluster file system: one whose locks reach other hosts, or that another
/// machine serves. FUSE counts as local, whatever serves it. The numbers
/// are from linux/magic.h and the file systems' sources, written out here
/// since libc lacks some and gives the rest a type that differs by
/// architecture.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn network_magic(magic: u32) -> bool {
    const NETWORK: [u32; 14] = [
        0x6969,      // NFS
        0x517b,      // SMB
        0xfe53_4d42, // SMB2
        0xff53_4d42, // CIFS
        0x0102_1997, // 9P
        0x5346_414f, // AFS
        0x6b41_4653, // kAFS
        0x00c3_6400, // Ceph
        0x7375_7245, // Coda
        0x564c,      // NCP
        0x0bd0_0bd0, // Lustre
        0x0116_1970, // GFS2
        0x7461_636f, // OCFS2
        0x786f_4256, // vboxsf
    ];
    NETWORK.contains(&magic)
}

/// Whether a file system type illumos names in `statvfs` is a network one:
/// NFS, which names its version 3 and 4 mounts `nfs3` and `nfs4`, or SMB.
#[cfg(any(target_os = "illumos", test))]
fn network_type_name(name: &[u8]) -> bool {
    matches!(name, b"nfs" | b"nfs3" | b"nfs4" | b"smbfs")
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

/// The folder, the lock, the guard and the socket, as the owner holds them.
#[derive(Debug)]
pub(crate) struct Held {
    pub(crate) folder: Option<Folder>,
    pub(crate) lock: Option<Lock>,
    pub(crate) guard: Option<Guard>,
    /// The socket file this process bound.
    socket: Option<SocketKey>,
}

impl Held {
    #[cfg(test)]
    pub(crate) fn detached() -> Held {
        Held {
            folder: None,
            lock: None,
            guard: None,
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

/// What `start` hands over to a `Claim`: the folder, the lock, the guard
/// if it took one, and the listening socket, bound by this process.
#[derive(Debug)]
pub(crate) struct Claimed {
    pub(crate) folder: Folder,
    pub(crate) lock: Lock,
    guard: Option<Guard>,
    pub(crate) listener: io::Result<UnixListener>,
    socket: Option<SocketKey>,
    pid: u32,
}

impl Claimed {
    pub(crate) fn new(
        folder: Folder,
        lock: Lock,
        guard: Option<Guard>,
        _app_id: &AppId,
    ) -> Claimed {
        let (listener, socket) = match folder.listen() {
            Ok((l, key)) => (Ok(l), key),
            Err(e) => (Err(e), None),
        };
        Claimed {
            folder,
            lock,
            guard,
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

    pub(crate) fn guarded(&self) -> bool {
        self.guard.is_some()
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
            guard: self.guard,
            socket,
        };
        match listener {
            Ok(l) => (held, Some(l), None),
            Err(e) => (held, None, Some(e)),
        }
    }

    /// A forked copy that won't serve: close the socket and the folder, and
    /// keep the lock's and the guard's descriptors open until the process
    /// exits.
    pub(crate) fn abandon(self) {
        std::mem::forget(self.guard);
        std::mem::forget(self.lock);
    }

    /// Gives the guard and the lock up without serving, the guard first, so
    /// a launch that takes the freed lock finds the guard free too. A forked
    /// copy only closes its descriptors: both stay with the process that
    /// still holds them.
    pub(crate) fn release(self) {
        if !self.forked() {
            self.folder.remove_own_socket(&self.lock, self.socket);
        }
        drop(self.guard);
        drop(self.lock);
    }
}

struct Connection<T> {
    stream: UnixStream,
    session: Session<T>,
    shut: bool,
}

/// Runs the owner's thread until the handle closes it, or the lock or the
/// state folder is lost.
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
    let mut kept_out = None;

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
            match check_lock(&mut core, &mut listener, &place, &mut kept_out) {
                Upkept::Kept => next_check = now + upkeep.check,
                Upkept::Soon => next_check = now + upkeep.check.min(SOON),
                Upkept::Ended => break,
            }
        }
    }
    // Closing: launches find nobody listening and retry the lock.
    drop(listener);
}

/// How soon the owner looks again at a lock that a launch holds in its
/// re-made folder: the launch finds the guard held, and lets go.
const SOON: Duration = Duration::from_secs(1);

/// How long another process may hold the lock in the re-made folder before
/// the owner says so at warn. A launch lets go within about 50 ms of
/// finding the guard held, so one that holds the lock this long is an
/// owner, or an [exclusive](crate::Builder::exclusive) run, under
/// [`Guard::Off`](crate::Guard::Off), and launches can't reach this owner
/// meanwhile.
const KEPT_OUT: Duration = Duration::from_secs(10);

/// Since when another process has held the lock in the re-made folder,
/// and whether the owner has said so at warn.
struct KeptOut {
    since: Instant,
    told: bool,
}

/// What the owner's upkeep did, and when it looks next.
enum Upkept {
    /// All is in place, or in place again: look at the next check.
    Kept,
    /// Another process holds the lock in the re-made folder: look again
    /// [`SOON`].
    Soon,
    /// The owner has ended.
    Ended,
}

/// Every minute: are the state folder and its guard file, while the owner
/// holds the guard, and the lock file still the ones held? Ends the owner
/// with [`End::LostState`] when the state folder isn't, or another process
/// holds the guard file now at its path. Re-creates the guard file when
/// only it was removed, and the folder, the lock and the socket when
/// something deleted them. Ends the owner with
/// [`End::LostLock`] when another process took the lock meanwhile, unless
/// the owner holds the guard alone: it then waits, and `kept_out` says
/// since when.
///
/// [`End::LostState`]: crate::End::LostState
/// [`End::LostLock`]: crate::End::LostLock
fn check_lock<T: Payload>(
    core: &mut Core<T>,
    listener: &mut Option<UnixListener>,
    place: &Place,
    kept_out: &mut Option<KeptOut>,
) -> Upkept {
    let app_id = core.ctx.app_id.clone();
    // Kept only while another process still holds the lock.
    let kept = kept_out.take();
    let mut held = core.shared.held();
    if core.shared.close.load(Ordering::SeqCst) {
        return Upkept::Kept;
    }
    if let Some(guard) = &mut held.guard {
        match guard.look() {
            GuardFound::InPlace => {}
            GuardFound::Retaken => log::warn!(
                "instance-handoff {app_id}: the guard file {} was removed or replaced; \
                 locked it again",
                guard.path().display()
            ),
            GuardFound::Unknown(e) => log::warn!(
                "instance-handoff {app_id}: looking at the state folder {} and its guard \
                 file: {e}",
                guard.state.display()
            ),
            GuardFound::Lost => {
                log::warn!(
                    "instance-handoff {app_id}: the state folder {} was removed or replaced, \
                     or another process holds its guard: this process is no longer the owner",
                    guard.state.display()
                );
                // The socket and the lock go too, so the next launch can own
                // the folder now at the path. The guard first, as `release`
                // gives them up.
                held.unlink_socket();
                held.socket = None;
                drop(held.guard.take());
                drop(held.lock.take());
                drop(held);
                *listener = None;
                core.end(crate::End::LostState);
                return Upkept::Ended;
            }
        }
    }
    let (Some(folder), Some(lock)) = (&held.folder, &held.lock) else {
        return Upkept::Kept;
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
                    .connect(Some(Instant::now() + Duration::from_millis(200)), None)
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
        return Upkept::Kept;
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
                Upkept::Kept
            }
            // A launch that took the lock finds the guard this owner holds
            // alone, and lets go again. An owner with a scope shares the
            // guard, so a launch of its scope would own, and does.
            Ok(None) if held.guard.as_ref().is_some_and(|g| !g.shared) => {
                let now = Instant::now();
                let mut kept = kept.unwrap_or(KeptOut {
                    since: now,
                    told: false,
                });
                let waited = now.duration_since(kept.since);
                if !kept.told && waited >= KEPT_OUT {
                    log::warn!(
                        "instance-handoff {app_id}: another process has held the lock in the \
                         re-made runtime folder {} for {} s, so launches can't reach this \
                         owner; it takes the lock there once that process lets go",
                        new.path().display(),
                        waited.as_secs()
                    );
                    kept.told = true;
                } else {
                    log::debug!(
                        "instance-handoff {app_id}: another process holds the lock in the \
                         re-made runtime folder; looking again soon"
                    );
                }
                *kept_out = Some(kept);
                Upkept::Soon
            }
            Ok(None) => {
                log::warn!(
                    "instance-handoff {app_id}: the runtime folder was removed, and another \
                     process now holds the lock: this process is no longer the owner"
                );
                // An owner told to stop writing the state gives its guard up
                // too, so the launch that holds the lock, or the next one,
                // can own the state folder.
                drop(held.guard.take());
                drop(held);
                // The files at the path are the new owner's: remove nothing.
                *listener = None;
                core.end(crate::End::LostLock);
                Upkept::Ended
            }
            Err(e) => {
                log::warn!("instance-handoff {app_id}: re-creating the lock: {e}");
                Upkept::Kept
            }
        },
        // The folder can't be made now (the session's runtime folder is
        // gone until the next login): keep the lock held, and look again.
        Ok(None) => Upkept::Kept,
        Err(reason) => {
            log::debug!("instance-handoff {app_id}: re-creating the folder: {reason}");
            Upkept::Kept
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
                    Ok((uid, pid)) if uid == euid() => Session::new(core, Peer::new(pid), now),
                    Ok((uid, pid)) => {
                        log::warn!(
                            "instance-handoff {}: refused a connection from user {uid}",
                            core.ctx.app_id
                        );
                        Session::refused(Peer::new(pid), refusal::PEER, now)
                    }
                    Err(e) => {
                        log::warn!("instance-handoff {}: peer check: {e}", core.ctx.app_id);
                        Session::refused(Peer::default(), refusal::PEER, now)
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

    const ID: AppId = AppId::headless("app.test");

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

    // One row per way to reach root, or a launch that looks like one. Only
    // root with a known person who isn't root is raised.
    #[test]
    fn raised_launches() {
        let (user, root, none) = (Some(1000), Some(0), None);
        // (launch, euid, SUDO_UID, PKEXEC_UID, DOAS_USER, loginuid, raised)
        let rows = [
            ("sudo, no login id", 0, user, none, none, none, true),
            ("sudo -i on Linux", 0, user, none, none, user, true),
            // run0's command runs as a service: no login id.
            ("run0", 0, user, none, none, none, true),
            ("su on Linux", 0, none, none, none, user, true),
            ("sudo after su", 0, root, none, none, user, true),
            ("doas", 0, none, none, user, none, true),
            ("pkexec", 0, none, user, none, user, true),
            ("root's own login", 0, none, none, none, root, false),
            ("root login, sudo", 0, root, none, none, root, false),
            // Started by the service manager: no login.
            ("a systemd service", 0, none, none, none, none, false),
            // The user who made the namespace is its root, and a login id
            // the namespace doesn't map reads as unset.
            ("rootless container", 0, none, none, none, root, false),
            // No login id, and su sets no variable.
            ("su on macOS, BSDs", 0, none, none, none, none, false),
            // Not root: no raised rights, whatever the variables say.
            ("a stale SUDO_UID", 1000, user, none, none, user, false),
            ("sudo -u bob", 1001, user, none, none, user, false),
        ];
        for (launch, euid, sudo_uid, pkexec_uid, doas_user, loginuid, raised) in rows {
            let env = RaisedEnv {
                euid,
                sudo_uid,
                pkexec_uid,
                doas_user,
                loginuid,
            };
            assert_eq!(raised_from(&env), raised, "{launch}: {env:?}");
        }
    }

    #[test]
    fn doas_users_are_looked_up() {
        assert_eq!(uid_of(OsStr::new("root")), Some(0));
        assert_eq!(uid_of(OsStr::new("no-such-user-ih")), None);
        assert_eq!(uid_of(OsStr::new("ro\0ot")), None);
        let env = raised_env();
        assert_eq!(env.euid, euid());
        if env.euid != 0 {
            assert!(!raised() && !above_normal());
        }
    }

    // On Linux, the BSDs and illumos: a launch can show windows when a
    // display variable names a display.
    #[test]
    fn who_can_show_windows() {
        let (wayland, x, empty, none) = (Some("wayland-0"), Some(":0"), Some(""), None);
        // (launch, WAYLAND_DISPLAY, DISPLAY, can show windows)
        let rows = [
            ("a Wayland session with Xwayland", wayland, x, true),
            ("a Wayland session alone", wayland, none, true),
            ("an X session", none, x, true),
            ("ssh -X", none, Some("localhost:10.0"), true),
            ("a console, ssh, cron or a service", none, none, false),
            ("emptied variables", empty, empty, false),
            ("an emptied WAYLAND_DISPLAY", empty, x, true),
            ("an emptied DISPLAY", wayland, empty, true),
        ];
        for (launch, wayland_display, display, shows) in rows {
            let env = DisplayEnv {
                wayland_display: wayland_display.map(OsString::from),
                display: display.map(OsString::from),
            };
            assert_eq!(shows_windows_from(&env), shows, "{launch}: {env:?}");
        }
    }

    // A process can read its own login session.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_login_session_says_whether_it_has_graphics() {
        assert!(session_has_graphics().is_some());
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
        let st = fstat(folder.fd.as_fd()).unwrap();
        assert_eq!(path_owner(folder.path()).unwrap(), st.st_uid);
    }

    // Who may keep its state in whose folder: (owner, euid, trusted).
    #[test]
    fn the_state_owner_rule() {
        let table = [
            (1000, 1000, true),
            // Root's folders, such as `/` above a missing state folder.
            (0, 1000, true),
            (1001, 1000, false),
            // A user namespace shows owners it doesn't map as nobody.
            (65534, 1000, false),
            (0, 0, true),
            // Root given the user's home: sudo -E, macOS sudo, su -m.
            (1000, 0, false),
            (65534, 0, false),
        ];
        for (owner, euid, trusted) in table {
            assert_eq!(
                trusted_owner(owner, euid),
                trusted,
                "owner {owner}, euid {euid}"
            );
        }
    }

    #[test]
    fn this_users_folders_are_not_foreign() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!is_foreign(tmp.path()).unwrap());
        let err = is_foreign(&tmp.path().join("missing")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
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

        // An instance folder someone swapped for a symlink.
        let mut scoped = Place::dir(dir.clone());
        scoped.push("i-0123456789abcdef");
        std::os::unix::fs::symlink("/tmp", dir.join("i-0123456789abcdef")).unwrap();
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

    // Frozen with the guard's name: a private file in a state folder made
    // private where that is missing, never written, and an exclusive flock,
    // which no other open file shares.
    #[test]
    fn the_guard_is_private_and_exclusive() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("missing").join("state");
        make_state_dir(&state).unwrap();
        let guard = take_guard(&state, false)
            .unwrap()
            .expect("a local folder locks");
        let file = state.join(".instance-handoff.lock");
        assert_eq!(mode(&state), 0o700);
        assert_eq!(mode(&file), 0o600);
        let other = std::fs::File::open(&file).unwrap();
        // SAFETY: flock on an open file.
        let shared = unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
        assert_eq!(shared, -1);
        let err = take_guard(&state, false).unwrap_err();
        assert!(
            matches!(&err, Reason::StateInUse { path } if *path == file),
            "{err}"
        );
        drop(guard);
        assert!(take_guard(&state, false).unwrap().is_some());
        assert_eq!(std::fs::metadata(&file).unwrap().len(), 0);
    }

    // Frozen with the guard's modes: a keyed owner's flock is shared, so
    // other keyed owners and any other shared flock hold beside it, but no
    // exclusive one. An exclusive guard keeps keyed owners out in turn.
    #[test]
    fn a_keyed_guard_is_shared() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        let file = state.join(".instance-handoff.lock");
        let a = take_guard(state, true).unwrap();
        let b = take_guard(state, true).unwrap();
        assert!(a.is_some() && b.is_some(), "a local folder locks");
        let other = std::fs::File::open(&file).unwrap();
        // SAFETY: flock on an open file.
        let flock = |op| unsafe { libc::flock(other.as_raw_fd(), op | libc::LOCK_NB) };
        assert_eq!(flock(libc::LOCK_EX), -1);
        assert_eq!(flock(libc::LOCK_SH), 0);
        drop(other);
        let err = take_guard(state, false).unwrap_err();
        assert!(
            matches!(&err, Reason::StateInUse { path } if *path == file),
            "{err}"
        );
        drop(a);
        assert!(take_guard(state, false).is_err());
        drop(b);
        let unkeyed = take_guard(state, false).unwrap().unwrap();
        let err = take_guard(state, true).unwrap_err();
        assert!(matches!(err, Reason::StateInUse { .. }), "{err}");
        drop(unkeyed);
        assert!(take_guard(state, true).unwrap().is_some());
    }

    /// What the owner's upkeep finds at `guard`'s paths, by name.
    fn look(guard: &mut Guard) -> &'static str {
        match guard.look() {
            GuardFound::InPlace => "in place",
            GuardFound::Retaken => "retaken",
            GuardFound::Lost => "lost",
            GuardFound::Unknown(e) => panic!("{e}"),
        }
    }

    // A guard file removed or replaced in the state folder the owner holds
    // is made, or opened, and locked again in the owner's mode, so a launch
    // finds it held as before. Keyed owners lock the new one side by side.
    #[test]
    fn a_guard_file_removed_from_its_folder_is_locked_again() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        make_state_dir(&state).unwrap();
        let file = state.join(".instance-handoff.lock");
        let mut guard = take_guard(&state, false).unwrap().unwrap();
        assert_eq!(look(&mut guard), "in place");
        std::fs::remove_file(&file).unwrap();
        assert_eq!(look(&mut guard), "retaken");
        assert!(file.is_file());
        assert_eq!(look(&mut guard), "in place");
        let err = take_guard(&state, true).unwrap_err();
        assert!(matches!(err, Reason::StateInUse { .. }), "{err}");
        let new = tmp.path().join("new");
        std::fs::write(&new, b"").unwrap();
        std::fs::rename(&new, &file).unwrap();
        assert_eq!(look(&mut guard), "retaken");
        let err = take_guard(&state, false).unwrap_err();
        assert!(matches!(err, Reason::StateInUse { .. }), "{err}");
        drop(guard);

        let mut a = take_guard(&state, true).unwrap().unwrap();
        std::fs::remove_file(&file).unwrap();
        let b = take_guard(&state, true).unwrap().unwrap();
        assert_eq!(look(&mut a), "retaken");
        let err = take_guard(&state, false).unwrap_err();
        assert!(matches!(err, Reason::StateInUse { .. }), "{err}");
        drop((a, b));
    }

    // Another owner that locks the new guard file first, in a mode that
    // conflicts, owns the state folder now.
    #[test]
    fn a_new_guard_file_held_by_another_owner_is_lost() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        let file = state.join(".instance-handoff.lock");
        for (ours, theirs) in [(false, false), (false, true), (true, false)] {
            let mut guard = take_guard(state, ours).unwrap().unwrap();
            std::fs::remove_file(&file).unwrap();
            let other = take_guard(state, theirs).unwrap().unwrap();
            assert_eq!(look(&mut guard), "lost", "{ours} {theirs}");
            drop((guard, other));
        }
    }

    // The state folder is looked at by its path, not followed through a
    // link: renamed aside, made anew, or a link to the old one, it isn't
    // the folder the guard is in. Put back, it is again.
    #[test]
    fn a_replaced_state_folder_is_lost() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        let old = tmp.path().join("old");
        make_state_dir(&state).unwrap();
        let mut guard = take_guard(&state, false).unwrap().unwrap();
        std::fs::rename(&state, &old).unwrap();
        assert_eq!(look(&mut guard), "lost");
        make_state_dir(&state).unwrap();
        assert_eq!(look(&mut guard), "lost");
        std::fs::remove_dir(&state).unwrap();
        std::os::unix::fs::symlink(&old, &state).unwrap();
        assert_eq!(look(&mut guard), "lost");
        std::fs::remove_file(&state).unwrap();
        std::fs::rename(&old, &state).unwrap();
        assert_eq!(look(&mut guard), "in place");
    }

    // A lock needs no write, so a guard file that exists is locked in a
    // folder this user can't write to, but one that doesn't can't be made
    // there. Root may write anywhere, so this needs another user.
    #[test]
    fn a_read_only_state_folder_locks_only_a_guard_that_exists() {
        use std::os::unix::fs::PermissionsExt;
        if euid() == 0 {
            return;
        }
        let set_mode = |path: &Path, mode| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap()
        };
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        std::fs::create_dir(&state).unwrap();
        set_mode(&state, 0o500);
        let err = take_guard(&state, false).unwrap_err();
        assert!(matches!(err, Reason::Lock { .. }), "{err}");
        set_mode(&state, 0o700);
        drop(take_guard(&state, false).unwrap().unwrap());
        set_mode(&state, 0o500);
        assert!(take_guard(&state, false).unwrap().is_some());
        set_mode(&state, 0o700);
    }

    // Opened without blocking, a FIFO in the guard's place is refused at
    // once rather than waited on.
    #[test]
    fn a_guard_that_isnt_a_file_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let fifo = cstr(tmp.path().join(".instance-handoff.lock").as_os_str()).unwrap();
        // SAFETY: `fifo` is a valid C string.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let err = take_guard(tmp.path(), false).unwrap_err();
        assert!(
            matches!(err, Reason::Lock { .. }) && err.to_string().contains("not a file"),
            "{err}"
        );
    }

    // A state folder that exists keeps its mode, and whatever is at the
    // path is left for the guard to refuse.
    #[test]
    fn only_a_missing_state_folder_is_made() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
        make_state_dir(&state).unwrap();
        assert_eq!(mode(&state), 0o755);
        let file = tmp.path().join("file");
        std::fs::write(&file, b"").unwrap();
        make_state_dir(&file).unwrap();
        assert!(file.is_file());
        assert!(matches!(take_guard(&file, false), Err(Reason::Lock { .. })));
        assert!(make_state_dir(&file.join("state")).is_err());
    }

    // EBADF is NFS refusing an exclusive lock on a descriptor that isn't
    // open for writing.
    #[test]
    fn file_systems_without_locks_leave_the_owner_unguarded() {
        let error = io::Error::from_raw_os_error;
        for code in [libc::ENOLCK, libc::EOPNOTSUPP, libc::ENOTSUP, libc::EBADF] {
            assert!(locks_unsupported(&error(code)), "{code}");
        }
        for code in [libc::EACCES, libc::EROFS, libc::EIO] {
            assert!(!locks_unsupported(&error(code)), "{code}");
        }
    }

    // A state folder on a network file system gets no guard, and no guard
    // file is made in it.
    #[test]
    fn network_file_systems_go_unguarded() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join(".instance-handoff.lock");
        assert!(open_guard_with(tmp.path(), |_| true).unwrap().is_none());
        assert!(!file.exists());
        assert!(open_guard_with(tmp.path(), |_| false).unwrap().is_some());
        assert!(file.exists());
    }

    // The guard tests need a temporary folder to count as local. This asks
    // directly, so macOS checks MNT_LOCAL itself.
    #[test]
    fn a_temporary_folder_is_local() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = open_dir(None, tmp.path(), true).unwrap();
        assert!(!is_network(dir.as_fd()));
    }

    // The numbers Linux reports for network and cluster file systems, from
    // linux/magic.h, and some local ones. FUSE is local, whatever serves
    // it. WSL 2 mounts the Windows drives as 9p.
    #[test]
    fn network_file_systems_are_known_by_magic_number() {
        let network = [
            ("nfs", 0x6969),
            ("smb", 0x517b),
            ("smb2", 0xfe53_4d42),
            ("cifs", 0xff53_4d42),
            ("9p", 0x0102_1997),
            ("afs", 0x5346_414f),
            ("kafs", 0x6b41_4653),
            ("ceph", 0x00c3_6400),
            ("coda", 0x7375_7245),
            ("ncp", 0x564c),
            ("lustre", 0x0bd0_0bd0),
            ("gfs2", 0x0116_1970),
            ("ocfs2", 0x7461_636f),
            ("vboxsf", 0x786f_4256),
        ];
        for (name, magic) in network {
            assert!(network_magic(magic), "{name}");
        }
        let local = [
            ("ext4", 0xef53),
            ("btrfs", 0x9123_683e),
            ("xfs", 0x5846_5342),
            ("tmpfs", 0x0102_1994),
            ("overlay", 0x794c_7630),
            ("zfs", 0x2fc1_2fc1),
            ("fuse", 0x6573_5546),
        ];
        for (name, magic) in local {
            assert!(!network_magic(magic), "{name}");
        }
    }

    // The same numbers as libc has them, where it has them, so a typo
    // copied into both lists above can't pass.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    #[allow(clippy::unnecessary_cast)]
    fn the_magic_numbers_match_libc() {
        let network = [
            libc::NFS_SUPER_MAGIC,
            libc::SMB_SUPER_MAGIC,
            libc::AFS_SUPER_MAGIC,
            libc::CODA_SUPER_MAGIC,
            libc::NCP_SUPER_MAGIC,
            libc::OCFS2_SUPER_MAGIC,
        ];
        for magic in network {
            assert!(network_magic(magic as u32), "{magic:#x}");
        }
        let local = [
            libc::EXT4_SUPER_MAGIC,
            libc::BTRFS_SUPER_MAGIC,
            libc::XFS_SUPER_MAGIC,
            libc::TMPFS_MAGIC,
            libc::OVERLAYFS_SUPER_MAGIC,
            libc::FUSE_SUPER_MAGIC,
        ];
        for magic in local {
            assert!(!network_magic(magic as u32), "{magic:#x}");
        }
    }

    // illumos names its network file systems, NFS once for each version.
    #[test]
    fn illumos_network_file_systems_are_known_by_name() {
        for name in ["nfs", "nfs3", "nfs4", "smbfs"] {
            assert!(network_type_name(name.as_bytes()), "{name}");
        }
        for name in ["zfs", "ufs", "tmpfs", "lofs", ""] {
            assert!(!network_type_name(name.as_bytes()), "{name}");
        }
    }

    #[test]
    fn long_folders_still_get_a_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("x".repeat(150)).join("run");
        let folder = open_folder(&Place::dir(dir), true).unwrap().unwrap();
        let _lock = folder.lock().unwrap().unwrap();
        let listener = folder.listen().unwrap();
        let conn = folder.connect(None, None).ok().expect("connects");
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
