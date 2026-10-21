//! Handoffs between real processes: the test binary runs itself as owners
//! and launches, so they can be stopped and killed.

#![cfg(any(unix, windows))]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use instance_handoff::{AppId, Args, Builder, Claim, ElevatedOwner, Kind, Reason, Started, State};

const APP: AppId = AppId::headless("test.process");
const ROLE: &str = "INSTANCE_HANDOFF_TEST_ROLE";
const DIR: &str = "INSTANCE_HANDOFF_TEST_DIR";

/// `Builder::new`, but its launches may own whatever their rights: run as
/// administrator with UAC on, or under `sudo`, the tests and the owners
/// they start are raised, and by default wouldn't own.
fn new_builder(app: AppId, state: impl Into<State>) -> Builder {
    Builder::new(app, state).elevated_owner(ElevatedOwner::Allow)
}

/// Not a test: the owner process the other tests start. It serves as
/// `serve` says, and a request whose first argument is `hang` holds its
/// handler for 30 seconds, after it prints `hanging`.
#[test]
fn owner_process() {
    if std::env::var_os(ROLE).is_none() {
        return;
    }
    let dir = PathBuf::from(std::env::var_os(DIR).unwrap());
    let claim = match new_builder(APP, state(&dir))
        .dir(dir)
        .start(&Args::default())
    {
        Started::Owner(claim) => claim,
        other => panic!("child: {other:?}"),
    };
    serve(claim, true);
}

/// Not a test: an owner that waits its turn. It probes until nobody holds
/// the lock, printing `waiting` once it has found it held, then tries
/// `start`, and serves once it owns. A probe hands nothing over, and a
/// start finds no owner it could hand off to: the one before it is gone,
/// and a launch that took the lock meanwhile never serves.
#[test]
fn next_owner_process() {
    if std::env::var_os(ROLE).is_none() {
        return;
    }
    let dir = PathBuf::from(std::env::var_os(DIR).unwrap());
    let builder = new_builder(APP, state(&dir)).dir(dir);
    let probe = builder.clone().timeout(Duration::from_millis(100));
    let mut waiting = false;
    let claim = loop {
        match probe.probe() {
            Err(Reason::NoOwner { .. }) => {}
            _ => {
                if !waiting {
                    say("waiting");
                    waiting = true;
                }
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
        }
        match builder.start(&Args::default()) {
            Started::Owner(claim) => break claim,
            Started::HandedOff(info) => panic!("child: handed off to {info}"),
            Started::Alone(_) => {}
        }
    };
    serve(claim, false);
}

/// Not a test: an exclusive run of the state folder. It prints `held` once
/// it holds it, or why it couldn't. It holds it until its stdin closes,
/// then releases it and prints `released`.
#[test]
fn exclusive_process() {
    if std::env::var_os(ROLE).is_none() {
        return;
    }
    let dir = PathBuf::from(std::env::var_os(DIR).unwrap());
    match new_builder(APP, state(&dir)).dir(dir).exclusive() {
        Ok(held) => {
            say("held");
            let mut rest = String::new();
            let _ = std::io::stdin().read_line(&mut rest);
            held.release();
            say("released");
        }
        Err(reason) => say(&format!("failed: {reason:?}")),
    }
}

/// Not a test: an owner that forks after `start`, before it serves. The
/// child releases its copy of the Claim when ROLE is `release`, drops it
/// otherwise, and exits. The parent waits for it, then serves.
#[cfg(unix)]
#[test]
fn fork_owner_process() {
    let Some(role) = std::env::var_os(ROLE) else {
        return;
    };
    let dir = PathBuf::from(std::env::var_os(DIR).unwrap());
    let claim = match new_builder(APP, state(&dir))
        .dir(dir)
        .start(&Args::default())
    {
        Started::Owner(claim) => claim,
        other => panic!("child: {other:?}"),
    };
    // SAFETY: the child of a process with threads may make only
    // async-signal-safe calls until it exits. This child calls getpid,
    // closes its copies of the Claim's descriptors and calls _exit, which
    // are, and frees the Claim's memory, which the C library keeps working
    // in a forked child.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // The exit status tells the parent whether this went through. A
        // panic that reached the test harness, whose main thread isn't in
        // this copy, could end the child with status 0.
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if role == "release" {
                claim.release();
            } else {
                drop(claim);
            }
        }))
        .is_err();
        // _exit, not exit: no exit handlers run, and nothing the parent
        // had buffered is written twice.
        // SAFETY: _exit has no preconditions.
        unsafe { libc::_exit(i32::from(failed)) };
    }
    assert!(pid > 0, "fork: {}", std::io::Error::last_os_error());
    let mut status = 0;
    // SAFETY: status is a valid out pointer.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "{status:#x}"
    );
    serve(claim, false);
}

/// Not a test: a launch the test can stop, so that it learns of an owner's
/// death only when the test lets it. It starts with `hang` and a 20 second
/// timeout, and prints how that went.
#[cfg(unix)]
#[test]
fn hang_launch_process() {
    if std::env::var_os(ROLE).is_none() {
        return;
    }
    let dir = PathBuf::from(std::env::var_os(DIR).unwrap());
    let started = match new_builder(APP, state(&dir))
        .dir(dir)
        .timeout(Duration::from_secs(20))
        .start(&Args::new(["hang"]))
    {
        Started::Owner(claim) => {
            claim.release();
            "owner".to_owned()
        }
        Started::HandedOff(info) => {
            format!("handed to {:?}, confirmed {}", info.pid(), info.confirmed())
        }
        Started::Alone(reason) => format!("alone: {reason}"),
    };
    say(&format!("started {started}"));
}

/// Serves `claim` for the test that started this process. It prints
/// `ready`, then one line per request it takes (its arguments,
/// hex-encoded), and returns when its stdin closes. With `hang`, a request
/// whose first argument is `hang` prints `hanging` and holds the handler
/// for 30 seconds.
fn serve(claim: Claim<Args>, hang: bool) {
    let owner = claim.serve(move |request| {
        if hang && request.payload().first().is_some_and(|a| a == "hang") {
            // The handler runs only once the launch has committed.
            say("hanging");
            std::thread::sleep(Duration::from_secs(30));
        }
        let line: Vec<String> = request
            .payload()
            .iter()
            .map(|a| hex(&os_bytes(a)))
            .collect();
        let mut out = std::io::stdout().lock();
        writeln!(out, "took {}", line.join(" ")).is_ok() && out.flush().is_ok()
    });
    say("ready");
    let mut rest = String::new();
    let _ = std::io::stdin().read_line(&mut rest);
    drop(owner);
}

/// One line to the test that started this process.
fn say(line: &str) {
    println!("{line}");
    std::io::stdout().flush().unwrap();
}

/// The test binary, run as one of the roles above: usually an owner,
/// sometimes a launch.
struct Owner {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
}

impl Owner {
    /// An `owner_process`, once it serves.
    fn start(dir: &Path) -> Owner {
        let owner = Owner::spawn(dir, "owner_process", "owner");
        owner.wait_for("ready");
        owner
    }

    /// Runs `test`, one of the roles above, in a child process, with
    /// `role` in ROLE.
    fn spawn(dir: &Path, test: &str, role: &str) -> Owner {
        Owner::run(Owner::command(dir, test, role))
    }

    /// The command `spawn` runs.
    fn command(dir: &Path, test: &str, role: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", test, "--nocapture", "--test-threads=1", "-q"])
            .env(ROLE, role)
            .env(DIR, dir);
        command
    }

    fn run(mut command: Command) -> Owner {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Owner {
            stdin: child.stdin.take(),
            child,
            lines,
        }
    }

    /// Waits for the child to print `line`, skipping the lines before it.
    fn wait_for(&self, line: &str) {
        loop {
            let got = self
                .lines
                .recv_timeout(Duration::from_secs(10))
                .unwrap_or_else(|_| panic!("the child never printed {line}"));
            if got == line {
                return;
            }
        }
    }

    #[cfg(unix)]
    fn signal(&self, sig: libc::c_int) {
        // SAFETY: kill has no memory-safety preconditions.
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, sig) },
            0
        );
    }

    /// SIGSTOP, then wait until every thread has stopped. `kill` returns
    /// before they do, and until then an owner's server thread can still
    /// take a launch, and a launch can still go on.
    #[cfg(unix)]
    fn suspend(&self) {
        self.signal(libc::SIGSTOP);
        let pid = self.child.id() as libc::pid_t;
        let mut status = 0;
        // SAFETY: status is a valid out pointer. WUNTRACED reports the
        // stop, once the whole process has stopped, without reaping it.
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) },
            pid
        );
        assert!(libc::WIFSTOPPED(status), "{status:#x}");
    }

    /// SIGKILL on Unix, TerminateProcess on Windows.
    fn kill(&mut self) {
        self.child.kill().unwrap();
        let _ = self.child.wait();
    }

    /// The rest of the next line the child prints that starts with
    /// `prefix`.
    fn said(&self, prefix: &str, wait: Duration) -> Option<String> {
        loop {
            let line = self.lines.recv_timeout(wait).ok()?;
            if let Some(rest) = line.strip_prefix(prefix) {
                return Some(rest.to_owned());
            }
        }
    }

    fn took(&self, wait: Duration) -> Option<String> {
        self.said("took ", wait)
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn hex(s: &[u8]) -> String {
    s.iter().map(|b| format!("{b:02x}")).collect()
}

/// An argument's bytes as it travels: its bytes on Unix, UTF-16LE on
/// Windows.
fn os_bytes(s: &std::ffi::OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        s.as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        s.encode_wide().flat_map(u16::to_le_bytes).collect()
    }
}

/// A file name that isn't valid Unicode.
fn odd_name() -> std::ffi::OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::OsStr::from_bytes(b"caf\xe9.pdf").to_os_string()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        std::ffi::OsString::from_wide(&[0x63, 0xd800, 0x2e, 0x70])
    }
}

fn dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("run");
    (tmp, path)
}

/// The state folder of the test whose runtime folder is `dir`: beside it,
/// so that children find it from `dir` alone. Nothing makes it.
fn state(dir: &Path) -> State {
    State::dir(dir.with_file_name("state"))
}

#[test]
fn a_launch_hands_off_to_another_process() {
    let (_tmp, dir) = dir();
    let owner = Owner::start(&dir);
    let args = Args::new([odd_name(), "x".into()]);
    match new_builder(APP, state(&dir)).dir(&dir).start(&args) {
        Started::HandedOff(info) => {
            assert!(info.confirmed());
            assert_eq!(info.pid(), Some(owner.pid()));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        owner.took(Duration::from_secs(5)).as_deref(),
        Some(
            format!(
                "{} {}",
                hex(&os_bytes(&odd_name())),
                hex(&os_bytes("x".as_ref()))
            )
            .as_str()
        )
    );
}

#[test]
fn a_launch_of_another_payload_version_is_refused_at_once() {
    let (_tmp, dir) = dir();
    let owner = Owner::start(&dir);
    let t = Instant::now();
    let reason = match new_builder(APP, state(&dir))
        .dir(&dir)
        .payload_version(1)
        .timeout(Duration::from_secs(10))
        .start(&Args::new(["x"]))
    {
        Started::Alone(reason) => reason,
        other => panic!("{other:?}"),
    };
    assert!(
        matches!(
            reason,
            Reason::PayloadVersion {
                ours: 1,
                theirs: 0,
                ..
            }
        ),
        "{reason}"
    );
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(owner.took(Duration::from_millis(500)), None);
}

// A windowed launch beside a headless owner of its id. Not the reverse: a
// windowed owner needs a launch that can show windows, and CI may have no
// display.
#[test]
fn a_launch_of_the_other_kind_is_refused_at_once() {
    let (_tmp, dir) = dir();
    let owner = Owner::start(&dir);
    let t = Instant::now();
    let reason = match new_builder(
        AppId::parse(APP.as_str(), Kind::Windowed).unwrap(),
        state(&dir),
    )
    .dir(&dir)
    .timeout(Duration::from_secs(10))
    .start(&Args::new(["x"]))
    {
        Started::Alone(reason) => reason,
        other => panic!("{other:?}"),
    };
    assert!(matches!(reason, Reason::OtherApp { .. }), "{reason}");
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(owner.took(Duration::from_millis(500)), None);
}

/// Not a test: a launch of `APP` as a windowed app, which
/// `windowed_launch` starts with the display it is given. It serves if it
/// owns, and otherwise prints how it started. When ROLE is `exclusive`, it
/// is an exclusive run instead: it prints `exclusive` and `held`, releasing
/// the state folder at once, or why it failed.
#[cfg(target_os = "linux")]
#[test]
fn windowed_launch_process() {
    let Some(role) = std::env::var_os(ROLE) else {
        return;
    };
    let dir = PathBuf::from(std::env::var_os(DIR).unwrap());
    let app = AppId::parse(APP.as_str(), Kind::Windowed).unwrap();
    let builder = new_builder(app, state(&dir))
        .dir(dir)
        .timeout(Duration::from_secs(20));
    if role == "exclusive" {
        match builder.exclusive() {
            Ok(held) => {
                say("exclusive held");
                held.release();
            }
            Err(reason) => say(&format!("exclusive failed: {reason:?}")),
        }
        return;
    }
    match builder.start(&Args::new(["windowed"])) {
        Started::Owner(claim) => serve(claim, false),
        Started::HandedOff(info) => say(&format!(
            "handed to {:?}, confirmed {}",
            info.pid(),
            info.confirmed()
        )),
        Started::Alone(reason) => say(&format!("alone: {reason:?}")),
    }
}

/// A `windowed_launch_process` in `role`, `windowed` or `exclusive`, whose
/// only display variable is `DISPLAY` set to `display`, or which has none.
#[cfg(target_os = "linux")]
fn windowed_launch(dir: &Path, role: &str, display: Option<&str>) -> Owner {
    let mut command = Owner::command(dir, "windowed_launch_process", role);
    command.env_remove("WAYLAND_DISPLAY").env_remove("DISPLAY");
    if let Some(display) = display {
        command.env("DISPLAY", display);
    }
    Owner::run(command)
}

// Only a launch that can show windows owns a windowed app: on Linux, one
// with a display variable. One without runs alone at once, creating
// nothing, or hands off to the owner. No display server is needed, since
// nothing connects to it. An exclusive run serves no launches, so one
// without a display variable still holds the state folder.
#[cfg(target_os = "linux")]
#[test]
fn only_a_launch_that_can_show_windows_owns_a_windowed_app() {
    let (_tmp, dir) = dir();
    let t = Instant::now();
    let alone = windowed_launch(&dir, "windowed", None);
    assert_eq!(
        alone.said("alone: ", Duration::from_secs(10)).as_deref(),
        Some("MayNotOwn { why: NoWindows }")
    );
    // Child included, well inside its 20 second timeout.
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    assert!(!dir.exists());
    let held = windowed_launch(&dir, "exclusive", None);
    assert_eq!(
        held.said("exclusive ", Duration::from_secs(10)).as_deref(),
        Some("held")
    );
    // It made the state folder, and no runtime folder.
    assert!(dir.with_file_name("state").is_dir() && !dir.exists());
    drop(held);

    let owner = windowed_launch(&dir, "windowed", Some(":99"));
    owner.wait_for("ready");
    let launch = windowed_launch(&dir, "windowed", None);
    assert_eq!(
        launch.said("handed to ", Duration::from_secs(10)),
        Some(format!("{:?}, confirmed true", Some(owner.pid())))
    );
    assert_eq!(owner.took(Duration::from_secs(5)), Some(hex(b"windowed")));
}

/// Not a test: a launch of `APP` as the kind ROLE names, `windowed` or
/// `headless`, on a window station that isn't visible. It prints
/// `station: hidden` once it has moved there, or why it couldn't. Then it
/// serves if it owns, and otherwise prints how it started.
#[cfg(windows)]
#[test]
fn hidden_launch_process() {
    let Some(role) = std::env::var_os(ROLE) else {
        return;
    };
    if let Err(e) = hide() {
        say(&format!("station: {e}"));
        return;
    }
    say("station: hidden");
    let dir = PathBuf::from(std::env::var_os(DIR).unwrap());
    let kind = if role == "windowed" {
        Kind::Windowed
    } else {
        Kind::Headless
    };
    let app = AppId::parse(APP.as_str(), kind).unwrap();
    match new_builder(app, state(&dir))
        .dir(dir)
        .timeout(Duration::from_secs(20))
        .start(&Args::default())
    {
        Started::Owner(claim) => serve(claim, false),
        Started::Alone(reason) => say(&format!("alone: {reason:?}")),
        other => say(&format!("{other:?}")),
    }
}

/// Moves this process to the window station that Windows names after its
/// logon session, as it does for services. Only a session's interactive
/// station is visible, so this one isn't.
#[cfg(windows)]
fn hide() -> std::io::Result<()> {
    use windows_sys::Win32::System::StationsAndDesktops::{
        CreateWindowStationW, SetProcessWindowStation,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::WINSTA_READATTRIBUTES;
    // No name, since only administrators may give one, and no security
    // attributes, so the handle isn't inherited. It stays open while the
    // process uses the station.
    // SAFETY: both pointers may be null.
    let station = unsafe {
        CreateWindowStationW(
            std::ptr::null(),
            0,
            WINSTA_READATTRIBUTES as u32,
            std::ptr::null(),
        )
    };
    if station.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a window station of this session, open.
    if unsafe { SetProcessWindowStation(station) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// A `hidden_launch_process` of the kind `role` names, once it is on its
/// window station.
#[cfg(windows)]
fn hidden_launch(dir: &Path, role: &str) -> Owner {
    let launch = Owner::spawn(dir, "hidden_launch_process", role);
    assert_eq!(
        launch.said("station: ", Duration::from_secs(10)).as_deref(),
        Some("hidden")
    );
    launch
}

// On Windows, a launch on a window station that isn't visible can't show
// windows: a windowed app's runs alone at once, creating nothing, and a
// headless app's owns. Neither needs the test to run where windows show.
#[cfg(windows)]
#[test]
fn a_launch_on_a_hidden_window_station_owns_only_a_headless_app() {
    let (_tmp, dir) = dir();
    let t = Instant::now();
    let windowed = hidden_launch(&dir, "windowed");
    assert_eq!(
        windowed.said("alone: ", Duration::from_secs(10)).as_deref(),
        Some("MayNotOwn { why: NoWindows }")
    );
    // Child included, well inside its 20 second timeout.
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    assert!(!dir.exists());

    let headless = hidden_launch(&dir, "headless");
    headless.wait_for("ready");
}

/// Not a test: a launch that `launch_under_fakeroot` starts. It prints the
/// effective user the C library reports, then hands off and prints the
/// owner's process id, or why it couldn't.
#[cfg(target_os = "linux")]
#[test]
fn launch_process() {
    if std::env::var_os(ROLE).is_none() {
        return;
    }
    let dir = PathBuf::from(std::env::var_os(DIR).unwrap());
    // SAFETY: geteuid has no preconditions and can't fail.
    println!("geteuid {}", unsafe { libc::geteuid() });
    match new_builder(APP, state(&dir))
        .dir(dir)
        .hand_off(&Args::new(["fakeroot"]))
    {
        Ok(info) => println!("handed off to {:?}", info.pid()),
        Err(reason) => println!("ran alone: {reason}"),
    }
}

/// Runs `launch_process` under fakeroot, and returns its output lines.
/// `None`, with a message, when fakeroot isn't installed, unless
/// INSTANCE_HANDOFF_REQUIRE_FAKEROOT is set.
#[cfg(target_os = "linux")]
fn launch_under_fakeroot(dir: &Path) -> Option<Vec<String>> {
    const REQUIRE: &str = "INSTANCE_HANDOFF_REQUIRE_FAKEROOT";
    let run = Command::new("fakeroot")
        .arg("--")
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "launch_process",
            "--nocapture",
            "--test-threads=1",
            "-q",
        ])
        .env(ROLE, "launch")
        .env(DIR, dir)
        .output();
    let out = match run {
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound && std::env::var_os(REQUIRE).is_none() =>
        {
            eprintln!("skipped: fakeroot isn't installed; set {REQUIRE} to fail instead");
            return None;
        }
        run => run.expect("fakeroot starts"),
    };
    assert!(
        out.status.success(),
        "{}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    Some(stdout.lines().map(str::to_owned).collect())
}

// fakeroot tells the C library that this user is root and owns every
// file. The launch reads both from the kernel, so it is still the user's
// and meets the user's owner.
#[cfg(target_os = "linux")]
#[test]
fn a_launch_under_fakeroot_hands_off_to_the_users_owner() {
    let (_tmp, dir) = dir();
    let owner = Owner::start(&dir);
    let Some(lines) = launch_under_fakeroot(&dir) else {
        return;
    };
    assert!(
        lines.iter().any(|l| l == "geteuid 0"),
        "fakeroot had no effect: {lines:?}"
    );
    let handed = format!("handed off to {:?}", Some(owner.pid()));
    assert!(lines.contains(&handed), "{lines:?}");
    assert_eq!(
        owner.took(Duration::from_secs(5)).as_deref(),
        Some(hex(b"fakeroot").as_str())
    );
}

/// Not a test: a launch that `launch_setgid` runs from a setgid copy of
/// the test binary. It prints its real and effective group ids, then the
/// reason `start` ran alone, and `hand_off`, `probe` and `exclusive`
/// failed, if they did.
#[cfg(unix)]
#[test]
fn setgid_launch_process() {
    if std::env::var_os(ROLE).is_none() {
        return;
    }
    let dir = PathBuf::from(std::env::var_os(DIR).unwrap());
    // SAFETY: getgid and getegid have no preconditions and can't fail.
    let (gid, egid) = unsafe { (libc::getgid(), libc::getegid()) };
    println!("gid {gid} egid {egid}");
    let builder = new_builder(APP, state(&dir)).dir(dir);
    let args = Args::new(["setgid"]);
    let alone = match builder.start(&args) {
        Started::Alone(reason) => Some(reason),
        _ => None,
    };
    println!("start {alone:?}");
    println!("hand_off {:?}", builder.hand_off(&args).err());
    println!("probe {:?}", builder.probe().err());
    println!("exclusive {:?}", builder.exclusive().err());
}

/// Runs `setgid_launch_process` from a copy of the test binary that is
/// setgid to another of this user's groups, which needs no root, and
/// returns its output lines. `None`, with a message, when the user has no
/// other group, the copy can't be made setgid, or its file system ignores
/// set-id bits, unless INSTANCE_HANDOFF_REQUIRE_SETGID is set.
#[cfg(unix)]
fn launch_setgid(dir: &Path) -> Option<Vec<String>> {
    use std::os::unix::fs::PermissionsExt;
    const REQUIRE: &str = "INSTANCE_HANDOFF_REQUIRE_SETGID";
    let skip = |why: String| {
        assert!(std::env::var_os(REQUIRE).is_none(), "{why}");
        eprintln!("skipped: {why}; set {REQUIRE} to fail instead");
    };
    // SAFETY: getgid has no preconditions and can't fail.
    let gid = unsafe { libc::getgid() };
    let Some(group) = groups().into_iter().find(|&g| g != gid) else {
        skip("this user has no group but its own".into());
        return None;
    };
    // In the build folder, since /tmp may be mounted nosuid.
    let copy = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let exe = copy.path().join("setgid");
    std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    // The group first: changing it clears the set-id bits.
    let made = std::os::unix::fs::chown(&exe, None, Some(group))
        .and_then(|()| std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o2755)));
    if let Err(e) = made {
        skip(format!(
            "the copy can't be made setgid to group {group}: {e}"
        ));
        return None;
    }
    let mut command = Command::new(&exe);
    command
        .args([
            "--exact",
            "setgid_launch_process",
            "--nocapture",
            "--test-threads=1",
            "-q",
        ])
        .env(ROLE, "setgid")
        .env(DIR, dir);
    let t = Instant::now();
    let out = loop {
        match command.output() {
            // A child that another test forked while the copy was open for
            // writing holds it until it execs.
            Err(e)
                if e.raw_os_error() == Some(libc::ETXTBSY)
                    && t.elapsed() < Duration::from_secs(5) =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            run => break run.expect("the setgid copy starts"),
        }
    };
    assert!(
        out.status.success(),
        "{}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<String> = stdout.lines().map(str::to_owned).collect();
    if !lines.contains(&format!("gid {gid} egid {group}")) {
        skip(format!(
            "the setgid copy ran with its caller's group: {lines:?}"
        ));
        return None;
    }
    Some(lines)
}

/// This process's supplementary groups.
#[cfg(unix)]
fn groups() -> Vec<libc::gid_t> {
    // SAFETY: with a size of 0, getgroups only counts, and writes nothing.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    let mut groups = vec![0; usize::try_from(n).unwrap()];
    // SAFETY: groups has room for n ids.
    let n = unsafe { libc::getgroups(n, groups.as_mut_ptr()) };
    groups.truncate(usize::try_from(n).unwrap());
    groups
}

// A setgid program has rights its caller lacks, in an environment its
// caller chose, so it takes no part: its start runs alone, and its
// hand_off, probe and exclusive fail, all with Excluded, although an owner
// serves. Nothing reaches the owner.
#[cfg(unix)]
#[test]
fn a_setgid_launch_takes_no_part() {
    let (_tmp, dir) = dir();
    let owner = Owner::start(&dir);
    let Some(lines) = launch_setgid(&dir) else {
        return;
    };
    for call in ["start", "hand_off", "probe", "exclusive"] {
        let excluded = format!("{call} Some(Excluded {{ why: SetId }})");
        assert!(lines.contains(&excluded), "{call}: {lines:?}");
    }
    // The first request the owner takes is this one.
    new_builder(APP, state(&dir))
        .dir(&dir)
        .hand_off(&Args::new(["after"]))
        .unwrap();
    assert_eq!(
        owner.took(Duration::from_secs(5)).as_deref(),
        Some(hex(b"after").as_str())
    );
}

#[cfg(unix)]
#[test]
fn a_stopped_owner_never_delivers_a_launch_that_ran_alone() {
    // Sheaf's bug 11, from a suspended owner (Ctrl-Z, SIGSTOP, a debugger).
    let (_tmp, dir) = dir();
    let owner = Owner::start(&dir);
    owner.suspend();
    let reason = match new_builder(APP, state(&dir))
        .dir(&dir)
        .timeout(Duration::from_millis(400))
        .start(&Args::new(["while-stopped"]))
    {
        Started::Alone(reason) => reason,
        other => panic!("{other:?}"),
    };
    assert!(matches!(reason, Reason::Unresponsive { .. }), "{reason}");
    owner.signal(libc::SIGCONT);
    assert_eq!(
        owner.took(Duration::from_secs(1)),
        None,
        "delivered after running alone"
    );

    new_builder(APP, state(&dir))
        .dir(&dir)
        .hand_off(&Args::new(["after"]))
        .unwrap();
    assert_eq!(
        owner.took(Duration::from_secs(5)).as_deref(),
        Some(hex(b"after").as_str())
    );
}

// An exclusive run in another process holds the state folder: a start is
// told at once, well inside its timeout, and lets go of the lock it took.
// Once the run releases it, the launch owns. An exclusive run beside an
// owner in another process fails, naming the guard.
#[test]
fn an_exclusive_run_in_another_process_is_reported_at_once() {
    let (_tmp, dir) = dir();
    let builder = new_builder(APP, state(&dir))
        .dir(&dir)
        .timeout(Duration::from_secs(10));
    let mut held = Owner::spawn(&dir, "exclusive_process", "exclusive");
    held.wait_for("held");
    let t = Instant::now();
    let reason = match builder.start(&Args::new(["x"])) {
        Started::Alone(reason) => reason,
        other => panic!("{other:?}"),
    };
    assert!(matches!(reason, Reason::StateInUse { .. }), "{reason}");
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    let reason = builder.probe().unwrap_err();
    assert!(matches!(reason, Reason::NoOwner { .. }), "{reason}");
    drop(held.stdin.take());
    held.wait_for("released");
    match builder.start(&Args::default()) {
        Started::Owner(claim) => claim.release(),
        other => panic!("{other:?}"),
    }

    let _owner = Owner::start(&dir);
    let refused = Owner::spawn(&dir, "exclusive_process", "exclusive");
    let failed = refused.said("failed: ", Duration::from_secs(10)).unwrap();
    assert!(
        failed.starts_with("StateInUse") && failed.ends_with(r#".instance-handoff.lock" }"#),
        "{failed}"
    );
}

// Another process owns the state folder from another runtime folder: a
// launch is told at once, well inside its timeout, and nothing reaches the
// owner.
#[test]
fn a_guard_held_by_another_process_is_reported_at_once() {
    let (_tmp, dir) = dir();
    let owner = Owner::start(&dir);
    let t = Instant::now();
    let reason = match new_builder(APP, state(&dir))
        .dir(dir.with_file_name("other"))
        .timeout(Duration::from_secs(10))
        .start(&Args::new(["x"]))
    {
        Started::Alone(reason) => reason,
        other => panic!("{other:?}"),
    };
    assert!(matches!(reason, Reason::StateInUse { .. }), "{reason}");
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(owner.took(Duration::from_millis(500)), None);
}

#[test]
fn a_killed_owner_hands_the_lock_to_the_next_launch() {
    let (_tmp, dir) = dir();
    let mut owner = Owner::start(&dir);
    owner.kill();
    match new_builder(APP, state(&dir))
        .dir(&dir)
        .start(&Args::default())
    {
        Started::Owner(claim) => claim.release(),
        other => panic!("{other:?}"),
    }
}

#[test]
fn launches_wait_for_an_owner_that_is_starting() {
    let (_tmp, dir) = dir();
    // The launch starts first and keeps trying while the owner comes up.
    let launch_dir = dir.clone();
    let launch = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        new_builder(APP, state(&launch_dir))
            .dir(&launch_dir)
            .timeout(Duration::from_secs(10))
            .hand_off(&Args::new(["early"]))
    });
    let owner = Owner::start(&dir);
    // hand_off needs an owner when it starts; it may come too early.
    match launch.join().unwrap() {
        Ok(_) => assert_eq!(
            owner.took(Duration::from_secs(5)).as_deref(),
            Some(hex(&os_bytes("early".as_ref())).as_str())
        ),
        Err(reason) => assert!(matches!(reason, Reason::NoOwner { .. }), "{reason}"),
    }
}

#[test]
fn an_owner_killed_after_the_commit_leaves_the_launch_to_take_over() {
    let (_tmp, dir) = dir();
    let mut owner = Owner::start(&dir);
    let launch_dir = dir.clone();
    let launch = std::thread::spawn(move || {
        new_builder(APP, state(&launch_dir))
            .dir(&launch_dir)
            .timeout(Duration::from_secs(5))
            .start(&Args::new(["hang"]))
    });
    // The handler is now holding the request; the owner dies with it.
    owner.wait_for("hanging");
    owner.kill();
    match launch.join().unwrap() {
        // Nobody else holds the lock: the launch owns its own request.
        Started::Owner(claim) => claim.release(),
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_owner_killed_after_the_commit_leaves_a_hand_off_unconfirmed() {
    let (_tmp, dir) = dir();
    let mut owner = Owner::start(&dir);
    let launch_dir = dir.clone();
    let launch = std::thread::spawn(move || {
        new_builder(APP, state(&launch_dir))
            .dir(&launch_dir)
            .timeout(Duration::from_secs(5))
            .hand_off(&Args::new(["hang"]))
    });
    owner.wait_for("hanging");
    owner.kill();
    // A hand_off never takes the lock, and no other owner comes. The dead
    // owner may have acted on the request, so hand_off doesn't fail: it
    // reports the request handed off, unconfirmed.
    let info = launch.join().unwrap().unwrap();
    assert!(!info.confirmed());
}

#[test]
fn a_launch_whose_owner_died_is_delivered_at_most_once() {
    let (_tmp, dir) = dir();
    let mut owner = Owner::start(&dir);
    let launch_dir = dir.clone();
    // Long, so that the launch still waits for the reply when the owner
    // dies, even if the next owner is slow to start.
    let launch = std::thread::spawn(move || {
        new_builder(APP, state(&launch_dir))
            .dir(&launch_dir)
            .timeout(Duration::from_secs(20))
            .start(&Args::new(["hang"]))
    });
    owner.wait_for("hanging");
    // Another owner waits for the lock. Once the first dies, the launch
    // and the next owner race for it, and whichever wins gets the request.
    let next = Owner::spawn(&dir, "next_owner_process", "next");
    next.wait_for("waiting");
    owner.kill();
    let started = launch.join().unwrap();
    let taken: Vec<String> = std::iter::from_fn(|| next.took(Duration::from_secs(2))).collect();
    let hang = hex(&os_bytes("hang".as_ref()));
    assert!(taken.iter().all(|args| *args == hang), "{taken:?}");
    match started {
        // The launch won: the request is its own, and nobody took it.
        Started::Owner(claim) => {
            assert_eq!(taken.len(), 0);
            claim.release();
        }
        // The next owner won, and took the request once.
        Started::HandedOff(info) if info.confirmed() => {
            assert_eq!(info.pid(), Some(next.pid()));
            assert_eq!(taken.len(), 1);
        }
        // No reply in time: taken once, or never.
        Started::HandedOff(_) => assert!(taken.len() <= 1, "{taken:?}"),
        other => panic!("{other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn a_launch_whose_owner_died_hands_off_to_the_next_owner() {
    let (_tmp, dir) = dir();
    let mut owner = Owner::start(&dir);
    let launch = Owner::spawn(&dir, "hang_launch_process", "launch");
    owner.wait_for("hanging");
    // Stopped, the launch can't race the next owner for the lock: it sees
    // the connection close only once the next owner serves.
    launch.suspend();
    owner.kill();
    let next = Owner::spawn(&dir, "next_owner_process", "next");
    next.wait_for("ready");
    launch.signal(libc::SIGCONT);
    assert_eq!(
        launch.said("started ", Duration::from_secs(25)),
        Some(format!("handed to {:?}, confirmed true", Some(next.pid())))
    );
    assert_eq!(
        next.took(Duration::from_secs(5)).as_deref(),
        Some(hex(b"hang").as_str())
    );
    assert_eq!(next.took(Duration::from_secs(1)), None, "taken twice");
}

/// A child forked after `start` that drops or releases its copy of the
/// Claim leaves the lock, the guard and the socket to its parent.
#[cfg(unix)]
fn a_fork_child_leaves_the_lock_to_its_parent(role: &str) {
    let (_tmp, dir) = dir();
    let owner = Owner::spawn(&dir, "fork_owner_process", role);
    owner.wait_for("ready");
    match new_builder(APP, state(&dir))
        .dir(&dir)
        .start(&Args::new(["x"]))
    {
        Started::HandedOff(info) => {
            assert!(info.confirmed());
            assert_eq!(info.pid(), Some(owner.pid()));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        owner.took(Duration::from_secs(5)).as_deref(),
        Some(hex(b"x").as_str())
    );
    // The lock is still held: an exclusive run that takes it, with no
    // guard, can't.
    let reason = new_builder(APP, state(&dir))
        .dir(&dir)
        .guard(instance_handoff::Guard::Off)
        .exclusive()
        .unwrap_err();
    assert!(matches!(reason, Reason::StateInUse { .. }), "{reason}");
    // And so is the guard: a launch in another runtime folder finds the
    // state folder in use.
    let reason = match new_builder(APP, state(&dir))
        .dir(dir.with_file_name("other"))
        .start(&Args::default())
    {
        Started::Alone(reason) => reason,
        other => panic!("{other:?}"),
    };
    assert!(matches!(reason, Reason::StateInUse { .. }), "{reason}");
}

#[cfg(unix)]
#[test]
fn fork_child_dropping_its_claim_keeps_the_parents_lock() {
    a_fork_child_leaves_the_lock_to_its_parent("drop");
}

#[cfg(unix)]
#[test]
fn fork_child_releasing_its_claim_keeps_the_parents_lock() {
    a_fork_child_leaves_the_lock_to_its_parent("release");
}
