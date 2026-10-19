//! Handoffs between real processes: the test binary runs itself as owners
//! and launches, so they can be stopped and killed.

#![cfg(any(unix, windows))]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use instance_handoff::{AppId, Args, Builder, Claim, Mode, Reason, Started};

const APP: AppId = AppId::new("test.process");
const ROLE: &str = "INSTANCE_HANDOFF_TEST_ROLE";
const DIR: &str = "INSTANCE_HANDOFF_TEST_DIR";

/// Not a test: the owner process the other tests start. It serves as
/// `serve` says, and a request whose first argument is `hang` holds its
/// handler for 30 seconds, after it prints `hanging`.
#[test]
fn owner_process() {
    if std::env::var_os(ROLE).is_none() {
        return;
    }
    let dir = PathBuf::from(std::env::var_os(DIR).unwrap());
    let claim = match Builder::new(APP).dir(dir).start(&Args::default()) {
        Started::Owner(claim) => claim,
        other => panic!("child: {other:?}"),
    };
    serve(claim, true);
}

/// Not a test: an owner that waits its turn. It tries `start` until it
/// owns, printing `waiting` once it has found the lock held, then serves.
/// Its launches are separate: while it waits they run alone, and hand
/// nothing to the owner before it.
#[test]
fn next_owner_process() {
    if std::env::var_os(ROLE).is_none() {
        return;
    }
    let dir = PathBuf::from(std::env::var_os(DIR).unwrap());
    let builder = Builder::new(APP).dir(dir).mode(Mode::Separate);
    let mut waiting = false;
    let claim = loop {
        match builder.start(&Args::default()) {
            Started::Owner(claim) => break claim,
            Started::Alone(Reason::OwnerRunning { .. }) if !waiting => {
                say("waiting");
                waiting = true;
            }
            Started::Alone(Reason::OwnerRunning { .. }) => {}
            other => panic!("child: {other:?}"),
        }
    };
    serve(claim, false);
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
    let claim = match Builder::new(APP).dir(dir).start(&Args::default()) {
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
    let started = match Builder::new(APP)
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
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture", "--test-threads=1", "-q"])
            .env(ROLE, role)
            .env(DIR, dir)
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

#[test]
fn a_launch_hands_off_to_another_process() {
    let (_tmp, dir) = dir();
    let owner = Owner::start(&dir);
    let args = Args::new([odd_name(), "x".into()]);
    match Builder::new(APP).dir(&dir).start(&args) {
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

#[cfg(unix)]
#[test]
fn a_stopped_owner_never_delivers_a_launch_that_ran_alone() {
    // Sheaf's bug 11, from a suspended owner (Ctrl-Z, SIGSTOP, a debugger).
    let (_tmp, dir) = dir();
    let owner = Owner::start(&dir);
    owner.suspend();
    let reason = match Builder::new(APP)
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

    Builder::new(APP)
        .dir(&dir)
        .hand_off(&Args::new(["after"]))
        .unwrap();
    assert_eq!(
        owner.took(Duration::from_secs(5)).as_deref(),
        Some(hex(b"after").as_str())
    );
}

#[test]
fn a_killed_owner_hands_the_lock_to_the_next_launch() {
    let (_tmp, dir) = dir();
    let mut owner = Owner::start(&dir);
    owner.kill();
    match Builder::new(APP).dir(&dir).start(&Args::default()) {
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
        Builder::new(APP)
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
        Builder::new(APP)
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
        Builder::new(APP)
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
        Builder::new(APP)
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
/// Claim leaves the lock and the socket to its parent.
#[cfg(unix)]
fn a_fork_child_leaves_the_lock_to_its_parent(role: &str) {
    let (_tmp, dir) = dir();
    let owner = Owner::spawn(&dir, "fork_owner_process", role);
    owner.wait_for("ready");
    match Builder::new(APP).dir(&dir).start(&Args::new(["x"])) {
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
    // The lock is still held: a launch that won't hand off can't own.
    let reason = match Builder::new(APP)
        .dir(&dir)
        .mode(Mode::Separate)
        .start(&Args::default())
    {
        Started::Alone(reason) => reason,
        other => panic!("{other:?}"),
    };
    assert!(matches!(reason, Reason::OwnerRunning { .. }), "{reason}");
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
