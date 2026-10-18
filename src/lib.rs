//! One sheaf process per user on each machine.
//!
//! The process holding `instance.lock` in the runtime folder is the
//! *owner*. It opens every window and is the only process that writes
//! sheaf's state. A later launch connects to the owner's socket beside the
//! lock, hands over the files it was given, and exits. The OS releases the
//! lock when the owner exits, crash included, so a lock is never stale.
//!
//! The runtime folder is local and per user ([`default_dir`]). It is never
//! the config folder, which on Windows roams and may sit on a network share:
//! sockets don't work there, and a lock there would span machines.
//!
//! Design and edge cases: `todos/m9.md`, slice 1.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use futures::channel::mpsc::UnboundedSender;
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(windows)]
use uds_windows::{UnixListener, UnixStream};

/// Bumped when a request or reply changes incompatibly.
pub const PROTOCOL: u32 = 1;
const LOCK: &str = "instance.lock";
const SOCKET: &str = "instance.sock";
/// Room for a socket path: `sun_path` holds 108 bytes on Linux and
/// Windows, 104 on macOS.
const MAX_SOCKET_PATH: usize = 100;
/// The longest request read (thousands of paths).
const MAX_REQUEST: u64 = 1 << 20;
/// How long the owner waits for a request once a launch has connected.
const SERVE_TIMEOUT: Duration = Duration::from_secs(2);

/// What a launch hands to the owner.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub v: u32,
    /// Files to open, absolute (the owner's working directory isn't ours).
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    /// The launcher's Wayland activation token, if it was given one. Sent
    /// for when the owner can use it to raise its window; ignored today.
    #[serde(default)]
    pub activation_token: Option<String>,
}

impl Request {
    /// A request for `paths`, made absolute against the current directory.
    pub fn new(paths: impl IntoIterator<Item = PathBuf>) -> Request {
        Request {
            v: PROTOCOL,
            paths: paths
                .into_iter()
                .map(|p| std::path::absolute(&p).unwrap_or(p))
                .collect(),
            activation_token: std::env::var("XDG_ACTIVATION_TOKEN").ok(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Reply {
    ok: bool,
    /// The owner is quitting or can't take requests yet: try the lock
    /// again rather than giving up.
    #[serde(default)]
    retry: bool,
}

/// How a launch joins the running sheaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Become the owner, or hand our files to it.
    Join,
    /// Become the owner if nobody is; otherwise run alone, writing no
    /// state. For `--new-instance`, scripts, self-tests and debug builds.
    Separate,
}

pub enum Started {
    /// We hold the lock: we own sheaf's state and take other launches'
    /// files.
    Owner(Owner),
    /// The owner took our files; this process should exit.
    HandedOff,
    /// Running without the lock, so writing no state. Says why.
    Standalone(String),
}

/// Holding the lock. Dropping it stops taking requests; the lock itself
/// goes when the process ends.
pub struct Owner {
    _lock: File,
    socket: Option<PathBuf>,
    accepting: Arc<AtomicBool>,
}

impl Owner {
    /// Stop taking requests, as the process starts to quit. Launches from
    /// now on wait for the lock instead of handing files to a process that
    /// won't open them.
    pub fn stop(&self) {
        self.accepting.store(false, Ordering::SeqCst);
        if let Some(path) = &self.socket {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Whether other launches can reach this process.
    pub fn listening(&self) -> bool {
        self.socket.is_some()
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The local, per-user runtime folder: `$XDG_RUNTIME_DIR/sheaf` on Linux
/// (or `/tmp/sheaf-<uid>` without one), `$TMPDIR/sheaf` on macOS,
/// `%LOCALAPPDATA%\sheaf\run` on Windows.
pub fn default_dir() -> Option<PathBuf> {
    let var = |name| std::env::var_os(name).filter(|v| !v.is_empty());
    #[cfg(windows)]
    {
        var("LOCALAPPDATA").map(|d| PathBuf::from(d).join("sheaf").join("run"))
    }
    #[cfg(target_os = "macos")]
    {
        Some(
            var("TMPDIR")
                .map(|d| PathBuf::from(d).join("sheaf"))
                .unwrap_or_else(tmp_dir),
        )
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Some(
            var("XDG_RUNTIME_DIR")
                .map(|d| PathBuf::from(d).join("sheaf"))
                .unwrap_or_else(tmp_dir),
        )
    }
}

#[cfg(unix)]
fn tmp_dir() -> PathBuf {
    PathBuf::from(format!("/tmp/sheaf-{}", euid()))
}

#[cfg(unix)]
fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and can't fail.
    unsafe { libc::geteuid() }
}

/// Take the lock in `dir`, or hand `request` to whoever holds it. A
/// request that arrives while we're the owner, from a later launch, goes to
/// `sink`. `wait` bounds how long a launch keeps trying to reach an owner
/// that holds the lock but doesn't answer (starting up, or quitting).
pub fn start(
    dir: &Path,
    mode: Mode,
    request: &Request,
    sink: UnboundedSender<Request>,
    wait: Duration,
) -> Started {
    if let Err(e) = private_dir(dir) {
        return Started::Standalone(format!("runtime folder {}: {e}", dir.display()));
    }
    let socket = socket_path(dir);
    let deadline = Instant::now() + wait;
    loop {
        match try_own(dir, &socket, &sink) {
            Ok(Some(owner)) => return Started::Owner(owner),
            Ok(None) => {}
            Err(e) => {
                return Started::Standalone(format!("{}: {e}", dir.join(LOCK).display()));
            }
        }
        if mode == Mode::Separate {
            return Started::Standalone("another sheaf is running".into());
        }
        let left = deadline.saturating_duration_since(Instant::now());
        match hand_off(&socket, request, left.max(Duration::from_millis(200))) {
            Ok(Handoff::Taken) => return Started::HandedOff,
            Ok(Handoff::Refused) => {
                return Started::Standalone(
                    "the running sheaf is a different version and refused the files".into(),
                );
            }
            // Quitting, or not listening yet.
            Ok(Handoff::Retry) | Err(_) => {}
        }
        if Instant::now() >= deadline {
            return Started::Standalone("a sheaf is running but didn't answer".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `Ok(None)` when another process holds the lock.
fn try_own(
    dir: &Path,
    socket: &Path,
    sink: &UnboundedSender<Request>,
) -> io::Result<Option<Owner>> {
    let mut lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(LOCK))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
        Err(std::fs::TryLockError::Error(e)) => return Err(e),
    }
    // Which process owns it, for anyone looking.
    let _ = lock.set_len(0);
    let _ = writeln!(lock, "{}", std::process::id());
    let accepting = Arc::new(AtomicBool::new(true));
    let socket = match listen(socket, sink.clone(), accepting.clone()) {
        Ok(()) => Some(socket.to_path_buf()),
        Err(e) => {
            // Still the owner (the only state writer); launches just can't
            // reach us, and run alone.
            log::warn!("sheaf instance socket {}: {e}", socket.display());
            None
        }
    };
    Ok(Some(Owner {
        _lock: lock,
        socket,
        accepting,
    }))
}

fn listen(
    path: &Path,
    sink: UnboundedSender<Request>,
    accepting: Arc<AtomicBool>,
) -> io::Result<()> {
    // We hold the lock, so a socket file here is a dead owner's.
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    std::thread::Builder::new()
        .name("sheaf-instance".into())
        .spawn(move || {
            for conn in listener.incoming() {
                match conn {
                    Ok(stream) => {
                        if let Err(e) = serve(stream, &sink, &accepting) {
                            log::warn!("sheaf instance: {e}");
                        }
                    }
                    Err(e) => log::warn!("sheaf instance: accept: {e}"),
                }
            }
        })?;
    Ok(())
}

/// Answer one launch. The reply goes as soon as the request is queued, so
/// a busy window never keeps the launcher waiting.
fn serve(
    mut stream: UnixStream,
    sink: &UnboundedSender<Request>,
    accepting: &AtomicBool,
) -> io::Result<()> {
    #[cfg(unix)]
    check_peer(&stream)?;
    stream.set_read_timeout(Some(SERVE_TIMEOUT))?;
    stream.set_write_timeout(Some(SERVE_TIMEOUT))?;
    let mut line = String::new();
    BufReader::new((&stream).take(MAX_REQUEST)).read_line(&mut line)?;
    let reply = match serde_json::from_str::<Request>(line.trim()) {
        Ok(req) if req.v != PROTOCOL => Reply {
            ok: false,
            retry: false,
        },
        Ok(_) if !accepting.load(Ordering::SeqCst) => Reply {
            ok: false,
            retry: true,
        },
        Ok(req) => match sink.unbounded_send(req) {
            Ok(()) => Reply {
                ok: true,
                retry: false,
            },
            // The app stopped listening: it's on its way out.
            Err(_) => Reply {
                ok: false,
                retry: true,
            },
        },
        Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
    };
    let mut out = serde_json::to_vec(&reply)?;
    out.push(b'\n');
    stream.write_all(&out)
}

enum Handoff {
    Taken,
    Retry,
    Refused,
}

fn hand_off(socket: &Path, request: &Request, timeout: Duration) -> io::Result<Handoff> {
    let mut stream = UnixStream::connect(socket)?;
    #[cfg(unix)]
    check_peer(&stream)?;
    // Let the owner bring its window forward: we were just launched by the
    // user, so we may, and it otherwise may not.
    #[cfg(windows)]
    allow_foreground();
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut out = serde_json::to_vec(request)?;
    out.push(b'\n');
    stream.write_all(&out)?;
    let mut line = String::new();
    BufReader::new((&stream).take(4096)).read_line(&mut line)?;
    let reply: Reply = serde_json::from_str(line.trim())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(match reply {
        Reply { ok: true, .. } => Handoff::Taken,
        Reply { retry: true, .. } => Handoff::Retry,
        _ => Handoff::Refused,
    })
}

/// `dir/instance.sock`, or a hashed name in the temp folder when that's
/// too long for a socket address.
fn socket_path(dir: &Path) -> PathBuf {
    let path = dir.join(SOCKET);
    if path.as_os_str().len() <= MAX_SOCKET_PATH {
        return path;
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in dir.as_os_str().as_encoded_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    std::env::temp_dir().join(format!("sheaf-{h:016x}.sock"))
}

/// Create `dir` if needed, and on Unix refuse one that isn't ours alone:
/// in a shared place like `/tmp`, another user could have made it first
/// and be waiting with a socket of their own.
fn private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let meta = std::fs::symlink_metadata(dir)?;
        let refuse = |why: &str| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                why.to_string(),
            ))
        };
        if !meta.is_dir() {
            return refuse("not a folder");
        }
        if meta.uid() != euid() {
            return refuse("owned by another user");
        }
        if meta.mode() & 0o022 != 0 {
            return refuse("other users can write to it");
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        // Under the user's own profile, which only they can reach.
        std::fs::create_dir_all(dir)
    }
}

/// Refuse a peer that isn't this user: the runtime folder should make that
/// impossible, but the socket may live in the shared temp folder.
#[cfg(unix)]
fn check_peer(stream: &UnixStream) -> io::Result<()> {
    let uid = peer_uid(stream)?;
    if uid != euid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("socket peer is user {uid}"),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    use std::os::fd::AsRawFd;
    // SAFETY: ucred is plain data; getsockopt writes at most `len` bytes.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    use std::os::fd::AsRawFd;
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: both out-pointers are valid for writes.
    let r = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}

#[cfg(windows)]
fn allow_foreground() {
    use windows::Win32::UI::WindowsAndMessaging::{ASFW_ANY, AllowSetForegroundWindow};
    // SAFETY: no preconditions; failure only means the window may not come
    // forward.
    let _ = unsafe { AllowSetForegroundWindow(ASFW_ANY) };
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use futures::channel::mpsc::{UnboundedReceiver, unbounded};

    const WAIT: Duration = Duration::from_millis(500);

    fn launch(dir: &Path, mode: Mode, paths: &[&str]) -> (Started, UnboundedReceiver<Request>) {
        let (tx, rx) = unbounded();
        let req = Request::new(paths.iter().map(PathBuf::from));
        (start(dir, mode, &req, tx, WAIT), rx)
    }

    fn owner(s: Started) -> Owner {
        match s {
            Started::Owner(o) => o,
            Started::HandedOff => panic!("handed off"),
            Started::Standalone(why) => panic!("standalone: {why}"),
        }
    }

    #[test]
    fn a_second_launch_hands_its_files_to_the_first() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("run");
        let (first, mut rx) = launch(&dir, Mode::Join, &["one.pdf"]);
        let first = owner(first);
        assert!(first.listening());
        let (second, _) = launch(&dir, Mode::Join, &["two.pdf", "/abs/three.pdf"]);
        assert!(matches!(second, Started::HandedOff));
        let got = rx.try_recv().unwrap();
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            got.paths,
            vec![cwd.join("two.pdf"), PathBuf::from("/abs/three.pdf")]
        );
        assert_eq!(got.v, PROTOCOL);
        // The owner's own request isn't queued.
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn separate_launches_run_alone_beside_an_owner() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("run");
        let _first = owner(launch(&dir, Mode::Join, &[]).0);
        match launch(&dir, Mode::Separate, &["x.pdf"]).0 {
            Started::Standalone(why) => assert!(why.contains("another sheaf"), "{why}"),
            _ => panic!("expected standalone"),
        }
    }

    #[test]
    fn a_separate_launch_owns_when_nobody_does() {
        let tmp = tempfile::tempdir().unwrap();
        let first = owner(launch(&tmp.path().join("run"), Mode::Separate, &[]).0);
        assert!(first.listening());
    }

    #[test]
    fn the_lock_frees_when_the_owner_goes() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("run");
        let first = owner(launch(&dir, Mode::Join, &[]).0);
        drop(first);
        // Its socket file is gone too, but a stale one wouldn't matter.
        let _second = owner(launch(&dir, Mode::Join, &[]).0);
    }

    #[test]
    fn an_owner_that_stopped_makes_launches_wait_then_run_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("run");
        let first = owner(launch(&dir, Mode::Join, &[]).0);
        first.stop();
        let t = Instant::now();
        match launch(&dir, Mode::Join, &["x.pdf"]).0 {
            Started::Standalone(why) => assert!(why.contains("didn't answer"), "{why}"),
            _ => panic!("expected standalone"),
        }
        assert!(t.elapsed() >= WAIT);
    }

    #[test]
    fn requests_from_a_quitting_owner_say_retry() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("run");
        let (first, rx) = launch(&dir, Mode::Join, &[]);
        let _first = owner(first);
        // The app has gone (its receiver dropped): retry, not refuse.
        drop(rx);
        let r = hand_off(&socket_path(&dir), &Request::new([]), WAIT).unwrap();
        assert!(matches!(r, Handoff::Retry));
    }

    #[test]
    fn another_protocol_version_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("run");
        let (first, mut rx) = launch(&dir, Mode::Join, &[]);
        let _first = owner(first);
        let req = Request {
            v: PROTOCOL + 1,
            ..Request::default()
        };
        let r = hand_off(&socket_path(&dir), &req, WAIT).unwrap();
        assert!(matches!(r, Handoff::Refused));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_folder_others_can_write_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("run");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        match launch(&dir, Mode::Join, &[]).0 {
            Started::Standalone(why) => assert!(why.contains("other users"), "{why}"),
            _ => panic!("expected standalone"),
        }
    }

    #[test]
    fn a_symlinked_folder_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("run");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(matches!(
            launch(&link, Mode::Join, &[]).0,
            Started::Standalone(_)
        ));
    }

    #[test]
    fn a_long_folder_puts_the_socket_in_temp() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("x".repeat(120)).join("run");
        let socket = socket_path(&dir);
        assert!(socket.starts_with(std::env::temp_dir()));
        assert!(socket.as_os_str().len() <= MAX_SOCKET_PATH);
        let (first, mut rx) = launch(&dir, Mode::Join, &[]);
        let _first = owner(first);
        assert!(matches!(
            launch(&dir, Mode::Join, &["a.pdf"]).0,
            Started::HandedOff
        ));
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn the_lock_file_names_the_owner() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("run");
        let _first = owner(launch(&dir, Mode::Join, &[]).0);
        let text = std::fs::read_to_string(dir.join(LOCK)).unwrap();
        assert_eq!(text.trim(), std::process::id().to_string());
    }
}
