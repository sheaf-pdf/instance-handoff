//! Launches in Linux user namespaces, as containers and sandboxes run
//! them: the test binary runs itself under bubblewrap (`bwrap`), as root
//! in the namespace or as the user, with a `/run` and a `/tmp` of its own.
//! The tests skip, with a message, where bwrap can't make a user
//! namespace, unless INSTANCE_HANDOFF_REQUIRE_BWRAP is set.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use instance_handoff::{AppId, Args, Builder, Claim, Started, State};

const APP: AppId = AppId::headless("test.namespaces");
const ROLE: &str = "INSTANCE_HANDOFF_TEST_ROLE";
const STATE: &str = "INSTANCE_HANDOFF_TEST_STATE";
const DIR: &str = "INSTANCE_HANDOFF_TEST_DIR";

/// Not a test: a launch the other tests start, on the host or in a
/// namespace. It starts with the state folder in STATE, in the runtime
/// folder in DIR if that is set and in its own otherwise. It prints
/// `started` and how: `owner <pid> in <runtime folder>`, and then it
/// serves, or how it handed off, or why it ran alone. When ROLE is
/// `exclusive`, it is an exclusive run instead: it prints `exclusive` and
/// `held`, releasing the state folder at once, or why it failed.
#[test]
fn launch_process() {
    let Some(role) = std::env::var_os(ROLE) else {
        return;
    };
    let state = PathBuf::from(std::env::var_os(STATE).unwrap());
    let mut builder = Builder::new(APP, State::dir(state)).timeout(Duration::from_secs(20));
    if let Some(dir) = std::env::var_os(DIR) {
        builder = builder.dir(dir);
    }
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
    match builder.start(&Args::new(["launch"])) {
        Started::Owner(claim) => {
            say(&format!(
                "started owner {} in {}",
                std::process::id(),
                claim.dir().display()
            ));
            serve(claim);
        }
        Started::HandedOff(info) => say(&format!(
            "started handed to {:?}, confirmed {}",
            info.pid(),
            info.confirmed()
        )),
        Started::Alone(reason) => say(&format!("started alone: {reason:?}")),
    }
}

/// Serves `claim`: prints `ready`, then `took` and the arguments of each
/// request, hex-encoded, and returns when stdin closes.
fn serve(claim: Claim<Args>) {
    let owner = claim.serve(|request| {
        let args: Vec<String> = request
            .payload()
            .iter()
            .map(|a| hex(a.as_encoded_bytes()))
            .collect();
        let mut out = std::io::stdout().lock();
        writeln!(out, "took {}", args.join(" ")).is_ok() && out.flush().is_ok()
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

fn hex(s: &[u8]) -> String {
    s.iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether bwrap can make a user namespace here. Where it can't, as where
/// it isn't installed or Ubuntu's AppArmor stops it, the test that asks
/// skips, with a message, unless INSTANCE_HANDOFF_REQUIRE_BWRAP is set.
fn bwrap_works() -> bool {
    let out = Command::new("bwrap")
        .args(["--unshare-user", "--uid", "0"])
        .args(["--ro-bind", "/", "/", "true"])
        .output();
    let why = match out {
        Ok(out) if out.status.success() => return true,
        Ok(out) => format!(
            "bwrap can't make a user namespace: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "bwrap isn't installed".to_owned(),
        Err(e) => format!("bwrap doesn't start: {e}"),
    };
    skip(&why);
    false
}

/// Says why a test skips, or fails with `why` if
/// INSTANCE_HANDOFF_REQUIRE_BWRAP is set. The message goes straight to
/// stderr, which libtest doesn't capture, so a passing test shows it. It
/// is one write, so that it doesn't break into libtest's lines.
fn skip(why: &str) {
    const REQUIRE: &str = "INSTANCE_HANDOFF_REQUIRE_BWRAP";
    assert!(std::env::var_os(REQUIRE).is_none(), "{why}");
    let line = format!("skipped: {why}; set {REQUIRE} to fail instead\n");
    let _ = std::io::stderr().write_all(line.as_bytes());
}

/// Who a launch in a namespace is.
#[derive(Debug, Clone, Copy)]
enum Uid {
    /// Root (`--uid 0`), as in a rootless container. On the host it is
    /// still the user. The user's login user id, where there is one, reads
    /// as root in the namespace too, so it isn't raised.
    Root,
    /// The user, with the same id as on the host, as in distrobox or
    /// Flatpak.
    User,
}

/// A command that runs `launch_process` with the state folder `state`, in
/// a user namespace of its own, as `uid`. It sees the host read-only, but
/// for `run`, its `/run`, and the test's folder `tmp`, both writable and
/// both the host's. With `own_tmp`, the rest of its `/tmp` is its own and
/// empty, as in a container that doesn't share the host's.
fn sandboxed(tmp: &Path, state: &Path, run: &Path, uid: Uid, own_tmp: bool) -> Command {
    let exe = std::env::current_exe().unwrap();
    let mut command = Command::new("bwrap");
    command.arg("--unshare-user");
    if let Uid::Root = uid {
        command.args(["--uid", "0"]);
    }
    command.args(["--ro-bind", "/", "/"]);
    if own_tmp {
        command.args(["--tmpfs", "/tmp"]);
    }
    // After the tmpfs, which would hide them.
    command
        .arg("--bind")
        .args([run, Path::new("/run")])
        .arg("--ro-bind")
        .args([&exe, &exe])
        .arg("--bind")
        .args([tmp, tmp])
        .args(["--chdir", "/", "--"])
        .arg(exe);
    with_role(&mut command, state);
    command
}

/// A command that runs `launch_process` on the host, in the runtime folder
/// `dir`.
fn on_host(state: &Path, dir: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    with_role(&mut command, state);
    command.env(DIR, dir);
    command
}

fn with_role(command: &mut Command, state: &Path) {
    command
        .args([
            "--exact",
            "launch_process",
            "--nocapture",
            "--test-threads=1",
            "-q",
        ])
        .env(ROLE, "launch")
        .env(STATE, state)
        .env_remove(DIR)
        // So that root in a namespace isn't raised, and the folder rule
        // sees neither Flatpak nor snap.
        .env_remove("SUDO_UID")
        .env_remove("PKEXEC_UID")
        .env_remove("DOAS_USER")
        .env_remove("FLATPAK_ID")
        .env_remove("SNAP_INSTANCE_NAME");
}

/// A `launch_process`, and the lines it prints.
struct Launch {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
}

impl Launch {
    fn run(mut command: Command) -> Launch {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // So that an error from bwrap, or a panic, shows. libtest
            // doesn't capture a child's stderr.
            .stderr(Stdio::inherit())
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
        Launch {
            stdin: child.stdin.take(),
            child,
            lines,
        }
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

    /// How the launch started, after `started`.
    fn started(&self) -> String {
        self.said("started ", Duration::from_secs(10))
            .expect("the child never said how it started")
    }

    /// The owner's process id and runtime folder, once it serves. It
    /// panics if the launch didn't own.
    fn owner(&self) -> (u32, PathBuf) {
        let started = self.started();
        let Some((pid, dir)) = started
            .strip_prefix("owner ")
            .and_then(|rest| rest.split_once(" in "))
        else {
            panic!("the child didn't own: {started}");
        };
        self.said("ready", Duration::from_secs(10))
            .expect("the child never served");
        (pid.parse().unwrap(), dir.into())
    }

    fn took(&self, wait: Duration) -> Option<String> {
        self.said("took ", wait)
    }
}

impl Drop for Launch {
    fn drop(&mut self) {
        // Closing stdin ends an owner. Killing bwrap wouldn't end the
        // process it runs, so that comes only after a while.
        drop(self.stdin.take());
        let until = Instant::now() + Duration::from_secs(10);
        while Instant::now() < until && matches!(self.child.try_wait(), Ok(None)) {
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A fresh folder for a test: its state folder will be `state` in it,
/// with its links resolved, and the `/run` folders its namespaces get are
/// made in it. Nothing makes the state folder.
fn setup() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let state = std::fs::canonicalize(tmp.path()).unwrap().join("state");
    (tmp, state)
}

/// A folder in `tmp` for a namespace to have as its `/run`.
fn run_folder(tmp: &Path, name: &str) -> PathBuf {
    let run = tmp.join(name);
    std::fs::create_dir(&run).unwrap();
    run
}

/// How a launch beside an owner of `state` in another runtime folder
/// starts.
fn in_use(state: &Path) -> String {
    format!(
        "alone: StateInUse {{ path: {:?} }}",
        state.join(".instance-handoff.lock")
    )
}

// Root in a user namespace is the user on the host, but root to the crate:
// it owns in root's fixed folder in its own /run. Another namespace's root
// that sees that /run hands off to it.
#[test]
fn root_in_a_user_namespace_owns_in_its_run_folder() {
    if !bwrap_works() {
        return;
    }
    let (tmp, state) = setup();
    let run = run_folder(tmp.path(), "run");
    let owner = Launch::run(sandboxed(tmp.path(), &state, &run, Uid::Root, false));
    let (pid, dir) = owner.owner();
    let instance = dir
        .strip_prefix("/run/instance-handoff")
        .unwrap_or_else(|_| panic!("{}", dir.display()));
    assert!(instance.starts_with(APP.as_str()), "{}", dir.display());
    assert!(run.join("instance-handoff").join(instance).is_dir());

    let launch = Launch::run(sandboxed(tmp.path(), &state, &run, Uid::Root, false));
    assert_eq!(
        launch.started(),
        format!("handed to {:?}, confirmed true", Some(pid))
    );
    assert_eq!(
        owner.took(Duration::from_secs(5)).as_deref(),
        Some(hex(b"launch").as_str())
    );
}

// The host's owner and root in a container see one state folder but two
// runtime folders. The guard turns the container's launch away at once,
// though it takes the lock in its own runtime folder.
#[test]
fn a_host_owner_and_namespace_root_split_over_one_state() {
    if !bwrap_works() {
        return;
    }
    let (tmp, state) = setup();
    let host = Launch::run(on_host(&state, &tmp.path().join("host")));
    host.owner();
    let t = Instant::now();
    let run = run_folder(tmp.path(), "run");
    let launch = Launch::run(sandboxed(tmp.path(), &state, &run, Uid::Root, false));
    assert_eq!(launch.started(), in_use(&state));
    // Child included, well inside its 20 second timeout.
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    assert_eq!(host.took(Duration::from_millis(500)), None);
}

// A container that runs as the user, with the host's state folder but a
// /run and a /tmp of its own: without systemd there, its runtime folder is
// its own /tmp/<id>-<uid>. The guard turns its launch away.
#[test]
fn the_same_user_with_its_own_run_and_tmp_finds_the_state_in_use() {
    if !bwrap_works() {
        return;
    }
    let (tmp, state) = setup();
    let host = Launch::run(on_host(&state, &tmp.path().join("host")));
    host.owner();
    let run = run_folder(tmp.path(), "run");
    let launch = Launch::run(sandboxed(tmp.path(), &state, &run, Uid::User, true));
    assert_eq!(launch.started(), in_use(&state));
    assert_eq!(host.took(Duration::from_millis(500)), None);
}

/// A command that runs `launch_process` as root in a namespace, in the
/// runtime folder `shared`, which the host sees at the same path.
fn root_in_shared(tmp: &Path, state: &Path, shared: &Path) -> Command {
    let run = run_folder(tmp, "run");
    let mut command = sandboxed(tmp, state, &run, Uid::Root, false);
    command.env(DIR, shared);
    command
}

// Root in a container meets the host's owner when both pass the
// bind-mounted folder to Builder::dir.
#[test]
fn namespace_root_hands_off_to_the_hosts_owner_in_a_shared_folder() {
    if !bwrap_works() {
        return;
    }
    let (tmp, state) = setup();
    let shared = tmp.path().join("shared");
    let host = Launch::run(on_host(&state, &shared));
    let (pid, _) = host.owner();
    let launch = Launch::run(root_in_shared(tmp.path(), &state, &shared));
    assert_eq!(
        launch.started(),
        format!("handed to {:?}, confirmed true", Some(pid))
    );
    assert_eq!(
        host.took(Duration::from_secs(5)).as_deref(),
        Some(hex(b"launch").as_str())
    );
}

// And the other way round: the host's launch hands off to root in the
// container.
#[test]
fn the_host_hands_off_to_namespace_roots_owner_in_a_shared_folder() {
    if !bwrap_works() {
        return;
    }
    let (tmp, state) = setup();
    let shared = tmp.path().join("shared");
    let owner = Launch::run(root_in_shared(tmp.path(), &state, &shared));
    let (pid, _) = owner.owner();
    let launch = Launch::run(on_host(&state, &shared));
    assert_eq!(
        launch.started(),
        format!("handed to {:?}, confirmed true", Some(pid))
    );
    assert_eq!(
        owner.took(Duration::from_secs(5)).as_deref(),
        Some(hex(b"launch").as_str())
    );
}

// SUDO_UID names a user who isn't root, so root in the namespace counts
// as raised: with nobody owning, it runs alone at once, creating nothing.
#[test]
fn a_raised_root_in_a_user_namespace_may_not_own() {
    if !bwrap_works() {
        return;
    }
    let (tmp, state) = setup();
    let run = run_folder(tmp.path(), "run");
    let mut command = sandboxed(tmp.path(), &state, &run, Uid::Root, false);
    command.env("SUDO_UID", "1000");
    let t = Instant::now();
    let launch = Launch::run(command);
    assert_eq!(launch.started(), "alone: MayNotOwn { why: Raised }");
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    assert_eq!(std::fs::read_dir(&run).unwrap().count(), 0);
    assert!(!state.exists());
}

// A user namespace shows the folders of users it doesn't map, host root's
// among them, as owned by the overflow user (nobody). That counts as
// another user, whether the launch is root in the namespace or the user:
// a state folder whose nearest folder is `/` gives ForeignState, to a
// start and to an exclusive run alike, before either makes anything.
#[test]
fn host_roots_folders_are_another_users_in_a_user_namespace() {
    use std::os::unix::fs::MetadataExt;
    if !bwrap_works() {
        return;
    }
    // SAFETY: geteuid has no preconditions and can't fail.
    if unsafe { libc::geteuid() } == 0 {
        // bwrap maps root to root, so its folders keep their owner.
        skip("the test runs as root, whose folders a user namespace maps");
        return;
    }
    assert_eq!(std::fs::metadata("/").unwrap().uid(), 0);
    let (tmp, _) = setup();
    // A folder in `/` that is missing, named as the test's own is.
    let name = tmp.path().file_name().unwrap();
    let state = Path::new("/").join(name).join("state");
    for uid in [Uid::Root, Uid::User] {
        let run = run_folder(tmp.path(), &format!("run-{uid:?}"));
        let launch = Launch::run(sandboxed(tmp.path(), &state, &run, uid, false));
        assert_eq!(launch.started(), r#"alone: ForeignState { path: "/" }"#);
        let mut command = sandboxed(tmp.path(), &state, &run, uid, false);
        command.env(ROLE, "exclusive");
        let held = Launch::run(command);
        assert_eq!(
            held.said("exclusive ", Duration::from_secs(10)).as_deref(),
            Some(r#"failed: ForeignState { path: "/" }"#)
        );
        assert_eq!(std::fs::read_dir(&run).unwrap().count(), 0);
    }
}
