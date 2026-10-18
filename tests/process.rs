//! Handoffs between real processes: the test binary runs itself as the
//! owner, so it can be stopped and killed.

#![cfg(any(unix, windows))]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use instance_handoff::{AppId, Args, Builder, Reason, Started};

const APP: AppId = AppId::new("test.process");
const ROLE: &str = "INSTANCE_HANDOFF_TEST_ROLE";
const DIR: &str = "INSTANCE_HANDOFF_TEST_DIR";

/// Not a test: the owner process the other tests start. It prints `ready`,
/// then one line per request it takes (its arguments, hex-encoded), and
/// exits when its stdin closes.
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
    let owner = claim.serve(|request| {
        if request.payload().first().is_some_and(|a| a == "hang") {
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
    println!("ready");
    std::io::stdout().flush().unwrap();
    let mut rest = String::new();
    let _ = std::io::stdin().read_line(&mut rest);
    drop(owner);
}

struct Owner {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
}

impl Owner {
    fn start(dir: &Path) -> Owner {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "owner_process",
                "--nocapture",
                "--test-threads=1",
                "-q",
            ])
            .env(ROLE, "owner")
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
        let owner = Owner {
            stdin: child.stdin.take(),
            child,
            lines,
        };
        loop {
            let line = owner
                .lines
                .recv_timeout(Duration::from_secs(10))
                .expect("the owner starts");
            if line == "ready" {
                return owner;
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

    /// SIGKILL on Unix, TerminateProcess on Windows.
    fn kill(&mut self) {
        self.child.kill().unwrap();
        let _ = self.child.wait();
    }

    fn took(&self, wait: Duration) -> Option<String> {
        loop {
            let line = self.lines.recv_timeout(wait).ok()?;
            if let Some(args) = line.strip_prefix("took ") {
                return Some(args.to_owned());
            }
        }
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
    owner.signal(libc::SIGSTOP);
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
    std::thread::sleep(Duration::from_millis(500));
    owner.kill();
    match launch.join().unwrap() {
        // Nobody else holds the lock: the launch owns its own request.
        Started::Owner(claim) => claim.release(),
        other => panic!("{other:?}"),
    }
}
