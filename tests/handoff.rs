//! Handoffs between launches in one process. Each test uses its own
//! runtime folder, so they run in parallel.

#![cfg(any(unix, windows))]

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(unix)]
use instance_handoff::Guard;
use instance_handoff::{
    AppId, Args, Builder, Claim, ElevatedOwner, End, Kind, Mode, Owner, Reason, Request, Started,
    State,
};

const APP: AppId = AppId::headless("test.handoff");
const SHORT: Duration = Duration::from_millis(300);

struct Dir {
    tmp: tempfile::TempDir,
    path: PathBuf,
}

/// A fresh runtime folder: below the temporary folder, which tempfile
/// makes readable by others.
fn dir() -> Dir {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("run");
    Dir { tmp, path }
}

/// The test's state folder, beside its runtime folder. The test doesn't
/// make it.
fn state(dir: &Dir) -> State {
    State::dir(dir.tmp.path().join("state"))
}

fn builder(dir: &Dir) -> Builder {
    Builder::new(APP, state(dir))
        .dir(&dir.path)
        .timeout(Duration::from_secs(3))
}

/// What the crate makes of a folder that exists: its links resolved, and
/// on Windows without the `\\?\` that `canonicalize` puts first.
fn canonical(path: &Path) -> PathBuf {
    let real = std::fs::canonicalize(path).unwrap();
    if cfg!(windows) {
        PathBuf::from(real.to_str().unwrap().strip_prefix(r"\\?\").unwrap())
    } else {
        real
    }
}

fn claim(started: Started<Args>) -> Claim<Args> {
    match started {
        Started::Owner(claim) => claim,
        other => panic!("expected the owner: {other:?}"),
    }
}

fn alone<T>(started: Started<T>) -> Reason {
    match started {
        Started::Alone(reason) => reason,
        other => panic!("expected to run alone: {other:?}"),
    }
}

fn serve(claim: Claim<Args>) -> (Owner, Receiver<Request<Args>>) {
    let (tx, rx) = mpsc::channel();
    (claim.serve(move |r| tx.send(r).is_ok()), rx)
}

fn args(list: &[&str]) -> Args {
    Args::new(list.iter().copied())
}

#[test]
fn a_second_launch_hands_its_args_to_the_first() {
    let dir = dir();
    let (owner, rx) = serve(claim(builder(&dir).start(&args(&["one.pdf"]))));
    assert!(owner.listen_error().is_none());
    assert_eq!(Some(owner.dir().to_path_buf()), builder(&dir).runtime_dir());

    // Not valid Unicode: bytes on Unix, a lone surrogate on Windows.
    #[cfg(unix)]
    let odd = {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::OsStr::from_bytes(b"caf\xe9.pdf").to_os_string()
    };
    #[cfg(windows)]
    let odd = {
        use std::os::windows::ffi::OsStringExt;
        OsString::from_wide(&[0x63, 0xd800, 0x2e, 0x70])
    };
    let second = Args::new([OsString::from("--flag"), odd.clone()]);
    let info = match builder(&dir).start(&second) {
        Started::HandedOff(info) => info,
        other => panic!("{other:?}"),
    };
    assert!(info.confirmed());
    assert_eq!(info.pid(), Some(std::process::id()));

    let got = rx.recv_timeout(SHORT).unwrap();
    assert_eq!(got.payload(), &second);
    assert!(got.is_remote());
    assert_eq!(got.launcher_pid(), Some(std::process::id()));
    let cwd = std::env::current_dir().unwrap();
    assert_eq!(got.cwd(), Some(cwd.as_path()));
    assert_eq!(got.resolve(&odd), Some(cwd.join(&odd)));
    // The owner's own payload never goes through the handler.
    assert!(rx.try_recv().is_err());
    owner.release();
}

#[test]
fn separate_launches_run_alone_beside_an_owner_and_own_when_nobody_does() {
    let dir = dir();
    let claim = claim(builder(&dir).mode(Mode::Separate).start(&Args::default()));
    let (owner, rx) = serve(claim);
    let t = Instant::now();
    let reason = alone(builder(&dir).mode(Mode::Separate).start(&args(&["x"])));
    assert!(matches!(reason, Reason::OwnerRunning { .. }), "{reason}");
    assert!(t.elapsed() < Duration::from_secs(1));
    assert!(rx.try_recv().is_err());
    owner.release();
}

// The tests don't run raised, so Allow and the default policy both own
// and hand off as launches always have.
#[test]
fn allow_owns_and_hands_off_as_before() {
    let dir = dir();
    let allow = builder(&dir).elevated_owner(ElevatedOwner::Allow);
    let (owner, rx) = serve(claim(allow.start(&args(&["one"]))));
    for launch in [allow, builder(&dir)] {
        let info = match launch.start(&args(&["two"])) {
            Started::HandedOff(info) => info,
            other => panic!("{other:?}"),
        };
        assert!(info.confirmed());
        assert_eq!(rx.recv_timeout(SHORT).unwrap().payload(), &args(&["two"]));
    }
    owner.release();
    claim(builder(&dir).start(&Args::default())).release();
}

#[test]
fn hand_off_and_probe_never_own_and_create_nothing() {
    let dir = dir();
    let reason = builder(&dir).hand_off(&args(&["x"])).unwrap_err();
    assert!(matches!(reason, Reason::NoOwner { .. }), "{reason}");
    let reason = builder(&dir).probe().unwrap_err();
    assert!(matches!(reason, Reason::NoOwner { .. }), "{reason}");
    assert!(!dir.path.exists());

    let (owner, rx) = serve(claim(builder(&dir).start(&Args::default())));
    let info = builder(&dir).probe().unwrap();
    assert!(info.confirmed());
    assert!(rx.try_recv().is_err(), "a probe reaches no handler");
    builder(&dir).hand_off(&args(&["y"])).unwrap();
    assert_eq!(rx.recv_timeout(SHORT).unwrap().payload(), &args(&["y"]));
    owner.release();

    let reason = builder(&dir).probe().unwrap_err();
    assert!(matches!(reason, Reason::NoOwner { .. }), "{reason}");
}

#[test]
fn probe_reports_each_state() {
    let dir = dir();
    let claim = claim(builder(&dir).start(&Args::default()));
    // Not served yet: launches wait in the backlog, and give up.
    let reason = builder(&dir).timeout(SHORT).probe().unwrap_err();
    assert!(matches!(reason, Reason::Unresponsive { .. }), "{reason}");

    let owner = claim.decline_all();
    let reason = builder(&dir).probe().unwrap_err();
    assert!(matches!(reason, Reason::Declined { .. }), "{reason}");
    assert_eq!(owner.ended(), None);
    owner.release();

    let (owner, _rx) = serve(self::claim(builder(&dir).start(&Args::default())));
    builder(&dir).probe().unwrap();
    owner.stop();
    let reason = builder(&dir).timeout(SHORT).probe().unwrap_err();
    assert!(matches!(reason, Reason::Busy { .. }), "{reason}");
    owner.release();
}

#[test]
fn stop_closes_the_channel_and_tells_on_end() {
    let dir = dir();
    let (end_tx, end_rx) = mpsc::channel();
    let (tx, rx) = mpsc::channel::<Request<Args>>();
    let owner = claim(builder(&dir).start(&Args::default()))
        .on_end(move |why| end_tx.send(why).unwrap())
        .serve(move |r| tx.send(r).is_ok());
    owner.stop();
    assert!(owner.is_stopped());
    // The handler (and the sender in it) is dropped with no launch arriving.
    assert!(matches!(
        rx.recv_timeout(Duration::from_secs(2)),
        Err(mpsc::RecvTimeoutError::Disconnected)
    ));
    // Set before the handler is dropped; on_end runs just after the drop.
    assert_eq!(owner.ended(), Some(End::Stopped));
    assert_eq!(
        end_rx.recv_timeout(Duration::from_secs(2)),
        Ok(End::Stopped)
    );

    let t = Instant::now();
    let reason = alone(builder(&dir).timeout(SHORT).start(&args(&["late"])));
    assert!(matches!(reason, Reason::Busy { .. }), "{reason}");
    assert!(t.elapsed() >= SHORT);
    owner.release();
}

#[test]
fn a_dropped_owner_keeps_the_lock_and_release_frees_it() {
    let dir = dir();
    let (owner, _rx) = serve(claim(builder(&dir).start(&Args::default())));
    drop(owner);
    // Nobody serves, but the lock is still held: no second owner.
    let reason = alone(builder(&dir).timeout(SHORT).start(&Args::default()));
    assert!(matches!(reason, Reason::Unresponsive { .. }), "{reason}");

    let dir = self::dir();
    let (owner, _rx) = serve(claim(builder(&dir).start(&Args::default())));
    owner.release();
    let second = claim(builder(&dir).start(&Args::default()));
    second.release();
}

#[test]
fn a_claim_dropped_unserved_turns_launches_away_at_once() {
    let dir = dir();
    drop(claim(builder(&dir).start(&Args::default())));
    let t = Instant::now();
    let reason = alone(builder(&dir).start(&args(&["x"])));
    assert!(matches!(reason, Reason::Declined { .. }), "{reason}");
    assert!(t.elapsed() < Duration::from_secs(1));
}

#[test]
fn mismatches_are_reported_at_once() {
    let dir = dir();
    let owner = claim(builder(&dir).payload_version(2).start(&Args::default()));
    let (owner, rx) = serve(owner);

    let reason = alone(builder(&dir).payload_version(3).start(&Args::default()));
    assert!(
        matches!(
            reason,
            Reason::PayloadVersion {
                ours: 3,
                theirs: 2,
                ..
            }
        ),
        "{reason}"
    );
    let reason = alone(
        Builder::new(AppId::headless("test.other"), state(&dir))
            .dir(&dir.path)
            .start(&Args::default()),
    );
    assert!(matches!(reason, Reason::OtherApp { .. }), "{reason}");
    // The same id of the other kind finds this owner in its folder. Only
    // the kind differs.
    let t = Instant::now();
    let reason = alone(
        Builder::new(
            AppId::parse(APP.as_str(), Kind::Windowed).unwrap(),
            state(&dir),
        )
        .dir(&dir.path)
        .payload_version(2)
        .start(&Args::default()),
    );
    assert!(matches!(reason, Reason::OtherApp { .. }), "{reason}");
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());

    let huge = vec![0u8; 5 << 20];
    let reason = builder(&dir)
        .payload_version(2)
        .hand_off(&huge)
        .unwrap_err();
    assert!(matches!(reason, Reason::TooLarge { .. }), "{reason}");
    // An owner of Args can't read a String that isn't Args.
    let reason = builder(&dir)
        .payload_version(2)
        .hand_off(&"not args".to_string())
        .unwrap_err();
    assert!(matches!(reason, Reason::Undecodable { .. }), "{reason}");
    assert!(rx.try_recv().is_err());
    owner.release();
}

#[test]
fn a_panicking_handler_ends_the_owner_and_declines_later_launches() {
    let dir = dir();
    let owner = claim(builder(&dir).start(&Args::default())).serve(|_| -> bool { panic!("boom") });
    // The handler may have taken the request before it panicked: its launch
    // must not also act on it, so it reports an unconfirmed handoff.
    match builder(&dir).start(&args(&["x"])) {
        Started::HandedOff(info) => assert!(!info.confirmed()),
        other => panic!("{other:?}"),
    }
    assert_eq!(owner.ended(), Some(End::Panicked));
    let reason = alone(builder(&dir).start(&args(&["y"])));
    assert!(matches!(reason, Reason::Declined { .. }), "{reason}");
    owner.release();
}

#[test]
fn a_launch_that_gave_up_is_never_delivered_later() {
    // Sheaf's bug 11: the launch runs alone, and the owner must not open
    // the same files once it gets to them.
    let dir = dir();
    let claim = claim(builder(&dir).start(&Args::default()));
    let reason = alone(builder(&dir).timeout(SHORT).start(&args(&["gave-up"])));
    assert!(matches!(reason, Reason::Unresponsive { .. }), "{reason}");
    let (owner, rx) = serve(claim);
    assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
    builder(&dir).hand_off(&args(&["next"])).unwrap();
    assert_eq!(rx.recv_timeout(SHORT).unwrap().payload(), &args(&["next"]));
    owner.release();
}

/// A raw connection to the owner, as any other program could make.
#[cfg(unix)]
fn socket(dir: &Path) -> std::os::unix::net::UnixStream {
    std::os::unix::net::UnixStream::connect(dir.join("instance.sock")).unwrap()
}

#[cfg(windows)]
fn socket(dir: &Path) -> std::fs::File {
    let address = std::fs::read_to_string(dir.join("instance.pipe")).unwrap();
    let (id, secret) = address.trim_end().split_once(' ').unwrap();
    let name = format!(r"\\.\pipe\instance-handoff.{id}.{secret}");
    // A pipe takes as many clients as it has listening instances; the
    // owner makes the next one a moment later.
    let t = Instant::now();
    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&name)
        {
            Ok(f) => return f,
            Err(e) if e.raw_os_error() == Some(231) && t.elapsed() < Duration::from_secs(5) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("{e}"),
        }
    }
}

#[test]
fn silent_and_trickling_clients_block_nobody() {
    let dir = dir();
    let (owner, rx) = serve(claim(builder(&dir).start(&Args::default())));
    let _silent: Vec<_> = (0..3).map(|_| socket(owner.dir())).collect();
    let mut trickle = socket(owner.dir());
    trickle.write_all(b"IH").unwrap();
    let t = Instant::now();
    builder(&dir).hand_off(&args(&["through"])).unwrap();
    assert!(
        t.elapsed() < Duration::from_millis(500),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(
        rx.recv_timeout(SHORT).unwrap().payload(),
        &args(&["through"])
    );
    owner.release();
}

#[test]
fn an_old_json_launch_is_refused_and_nothing_is_delivered() {
    let dir = dir();
    let (owner, rx) = serve(claim(builder(&dir).start(&Args::default())));
    let mut old = socket(owner.dir());
    #[cfg(unix)]
    old.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    old.write_all(b"{\"v\":1,\"paths\":[\"/x.pdf\"]}\n")
        .unwrap();
    let mut got = Vec::new();
    // A pipe whose owner closed its end reads as "not connected" on Windows.
    if let Err(e) = old.read_to_end(&mut got) {
        assert_eq!(e.raw_os_error(), Some(233), "{e}");
    }
    // HELLO, then a refusal; the connection is closed.
    assert!(got.starts_with(b"IHND\x01"), "{got:?}");
    assert!(rx.try_recv().is_err());
    owner.release();
}

/// An owner played by the test, for `builder(dir)`: the runtime folder,
/// its lock held, and a listener on its socket. The owner is this process,
/// so the launch's own check of the owner passes.
#[cfg(unix)]
fn fake_owner(dir: &Dir) -> (std::fs::File, std::os::unix::net::UnixListener) {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::DirBuilderExt;
    let run = builder(dir).runtime_dir().unwrap();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&run)
        .unwrap();
    let lock = std::fs::File::create(run.join("instance.lock")).unwrap();
    // SAFETY: flock on an open file.
    let locked = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(locked, 0);
    let listener = std::os::unix::net::UnixListener::bind(run.join("instance.sock")).unwrap();
    (lock, listener)
}

// An owner that won't serve the launch's user says so in place of HELLO.
// Only the owner's refusal is left to fail the launch.
#[cfg(unix)]
#[test]
fn an_owner_that_refuses_the_launchs_user_says_so_at_once() {
    let dir = dir();
    let (_lock, listener) = fake_owner(&dir);
    // REPLY: not delivered, refused, cause PEER.
    #[rustfmt::skip]
    let refused = [
        b'I', b'H', b'N', b'D', 5, 18, 0, 0, 0,
        1, 1, 0, 0, 0, 0,
        2, 1, 0, 0, 0, 3,
        3, 1, 0, 0, 0, 10,
    ];
    let owner = std::thread::spawn(move || {
        for stream in listener.incoming().take(2) {
            stream.unwrap().write_all(&refused).unwrap();
        }
    });
    let t = Instant::now();
    let reason = builder(&dir).probe().unwrap_err();
    assert!(matches!(reason, Reason::Peer { .. }), "{reason}");
    let reason = builder(&dir).hand_off(&args(&["x"])).unwrap_err();
    assert!(matches!(reason, Reason::Peer { .. }), "{reason}");
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    owner.join().unwrap();
}

// Two state folders whose instance folders share a name, as a hash
// collision would make them: the owner's HELLO names its state folder, and
// a launch of the other runs alone at once and sends nothing.
#[cfg(unix)]
#[test]
fn an_owner_of_another_state_in_the_same_folder_is_another_app() {
    use std::os::unix::ffi::OsStrExt;
    let dir = dir();
    let (_lock, listener) = fake_owner(&dir);
    let record =
        |tag: u8, bytes: &[u8]| [&[tag][..], &(bytes.len() as u32).to_le_bytes(), bytes].concat();
    // HELLO from an owner of this app, serving, whose state folder is
    // `state` in the temporary folder, and with no scope.
    let hello = |state: &str| {
        let state = canonical(dir.tmp.path()).join(state);
        let body = [
            record(1, &[1, 0, 1, 0]),
            record(2, &[&[1][..], APP.as_str().as_bytes()].concat()),
            record(3, &[7; 8]),
            record(4, &[0; 4]),
            record(5, &(4u32 << 20).to_le_bytes()),
            record(6, &[0]),
            record(9, &record(1, state.as_os_str().as_bytes())),
        ]
        .concat();
        [&b"IHND\x01"[..], &(body.len() as u32).to_le_bytes(), &body].concat()
    };
    // First the launch's own state, which it accepts, then another.
    let hellos = [
        hello("state"),
        hello("elsewhere"),
        hello("elsewhere"),
        hello("elsewhere"),
    ];
    let owner = std::thread::spawn(move || {
        for (hello, stream) in hellos.into_iter().zip(listener.incoming()) {
            let mut stream = stream.unwrap();
            stream.write_all(&hello).unwrap();
            let mut got = Vec::new();
            stream.read_to_end(&mut got).unwrap();
            assert!(got.is_empty(), "the launch sent {got:?}");
        }
    });
    builder(&dir).probe().unwrap();
    let t = Instant::now();
    let reason = builder(&dir).probe().unwrap_err();
    assert!(matches!(reason, Reason::OtherApp { .. }), "{reason}");
    let reason = builder(&dir).hand_off(&args(&["x"])).unwrap_err();
    assert!(matches!(reason, Reason::OtherApp { .. }), "{reason}");
    let reason = alone(builder(&dir).start(&args(&["x"])));
    assert!(matches!(reason, Reason::OtherApp { .. }), "{reason}");
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    owner.join().unwrap();
}

#[test]
fn a_burst_of_launches_is_each_delivered_exactly_once() {
    let dir = Arc::new(dir());
    let (owner, rx) = serve(claim(builder(&dir).start(&Args::default())));
    let launches: Vec<_> = (0..50)
        .map(|i| {
            let dir = dir.clone();
            std::thread::spawn(
                move || match builder(&dir).start(&args(&[&i.to_string()])) {
                    Started::HandedOff(info) => assert!(info.confirmed()),
                    other => panic!("launch {i}: {other:?}"),
                },
            )
        })
        .collect();
    for l in launches {
        l.join().unwrap();
    }
    let mut got: Vec<String> = rx
        .try_iter()
        .map(|r| r.payload()[0].to_string_lossy().into_owned())
        .collect();
    got.sort_by_key(|s| s.parse::<u32>().unwrap());
    let want: Vec<String> = (0..50).map(|i| i.to_string()).collect();
    assert_eq!(got, want);
    owner.release();
}

#[test]
fn a_busy_handler_makes_launches_retry_then_run_alone() {
    let dir = dir();
    let owner = claim(builder(&dir).start(&Args::default())).serve(|_| false);
    let reason = alone(builder(&dir).timeout(SHORT).start(&args(&["x"])));
    assert!(matches!(reason, Reason::Busy { .. }), "{reason}");
    owner.release();
}

// Windows can't delete or open up a folder the owner holds.
#[cfg(unix)]
#[test]
fn a_deleted_folder_is_re_created() {
    let dir = dir();
    let check = Duration::from_millis(100);
    let (owner, rx) = serve(claim(
        builder(&dir)
            .__upkeep(check, Duration::from_secs(3600))
            .start(&Args::default()),
    ));
    std::fs::remove_dir_all(&dir.path).unwrap();
    std::thread::sleep(check * 4);
    let run = builder(&dir).runtime_dir().unwrap();
    assert!(run.join("instance.lock").exists());
    builder(&dir).hand_off(&args(&["after"])).unwrap();
    assert_eq!(rx.recv_timeout(SHORT).unwrap().payload(), &args(&["after"]));
    assert_eq!(owner.ended(), None);
    owner.release();
}

// Windows can't delete or open up a folder the owner holds. Without the
// guard, which would turn the second owner away.
#[cfg(unix)]
#[test]
fn an_owner_whose_lock_was_taken_ends_with_lost_lock() {
    let dir = dir();
    let check = Duration::from_millis(400);
    let (tx, rx) = mpsc::channel::<Result<Request<Args>, End>>();
    let ended = tx.clone();
    let first = claim(
        builder(&dir)
            .guard(Guard::Off)
            .__upkeep(check, Duration::from_secs(3600))
            .start(&Args::default()),
    )
    .on_end(move |why| drop(ended.send(Err(why))))
    .serve(move |r| tx.send(Ok(r)).is_ok());
    std::fs::remove_dir_all(&dir.path).unwrap();
    // A new owner takes the re-made folder before the first one looks.
    let (second, rx2) = serve(claim(
        builder(&dir).guard(Guard::Off).start(&Args::default()),
    ));
    match rx.recv_timeout(check * 4) {
        Ok(Err(End::LostLock)) => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(first.ended(), Some(End::LostLock));
    // The first owner removed nothing: launches reach the second.
    builder(&dir).hand_off(&args(&["x"])).unwrap();
    assert_eq!(rx2.recv_timeout(SHORT).unwrap().payload(), &args(&["x"]));
    drop(first);
    builder(&dir).hand_off(&args(&["y"])).unwrap();
    assert_eq!(rx2.recv_timeout(SHORT).unwrap().payload(), &args(&["y"]));
    second.release();
}

// An owner told to stop writing the state gives its guard up too, so a
// launch in another runtime folder can own the state folder.
#[cfg(unix)]
#[test]
fn an_owner_that_lost_its_lock_gives_the_guard_up() {
    let dir = dir();
    let check = Duration::from_millis(400);
    let (tx, rx) = mpsc::channel();
    let first = claim(
        builder(&dir)
            .__upkeep(check, Duration::from_secs(3600))
            .start(&Args::default()),
    );
    assert!(first.guarded());
    let first = first
        .on_end(move |why| tx.send(why).unwrap())
        .serve(|_: Request<Args>| true);
    std::fs::remove_dir_all(&dir.path).unwrap();
    // An owner without a guard takes the re-made folder before the first
    // one looks.
    let second = claim(builder(&dir).guard(Guard::Off).start(&Args::default()));
    assert_eq!(rx.recv_timeout(check * 4).unwrap(), End::LostLock);
    let other = claim(
        builder(&dir)
            .dir(dir.tmp.path().join("other"))
            .start(&Args::default()),
    );
    assert!(other.guarded());
    other.release();
    second.release();
    drop(first);
}

// The owner holds its folder, its lock and its address open, sharing no
// delete: nothing there can be removed or replaced, so a launch still
// finds it, with the owner's next check an hour away.
#[cfg(windows)]
#[test]
fn a_live_owners_folder_and_address_stay_put() {
    let dir = dir();
    let hour = Duration::from_secs(3600);
    let (owner, rx) = serve(claim(
        builder(&dir).__upkeep(hour, hour).start(&Args::default()),
    ));
    let run = owner.dir();
    let address = run.join("instance.pipe");
    assert!(std::fs::remove_file(&address).is_err());
    let other = run.join("other");
    std::fs::write(&other, "x\n").unwrap();
    assert!(std::fs::rename(&other, &address).is_err());
    assert!(std::fs::remove_dir_all(run).is_err());
    assert!(std::fs::rename(run, run.with_extension("moved")).is_err());
    assert!(address.exists());
    builder(&dir).hand_off(&args(&["after"])).unwrap();
    assert_eq!(rx.recv_timeout(SHORT).unwrap().payload(), &args(&["after"]));
    owner.release();
}

// The temporary folder exists, and the state folder in it doesn't: the
// first is resolved (on macOS it is under /var, a link to /private/var;
// on the Windows runner it is named with 8.3 names), and the rest is kept.
#[test]
fn the_owner_reports_its_state_folder_with_links_resolved() {
    let dir = dir();
    let want = canonical(dir.tmp.path()).join("state");
    let claim = claim(builder(&dir).start(&Args::default()));
    assert_eq!(claim.state_dir(), Some(want.as_path()));
    let (owner, _rx) = serve(claim);
    assert_eq!(owner.state_dir(), Some(want.as_path()));
    owner.release();

    let none = self::claim(
        Builder::new(APP, State::none())
            .dir(&dir.path)
            .start(&Args::default()),
    );
    assert_eq!(none.state_dir(), None);
    none.release();
}

#[cfg(unix)]
#[test]
fn a_state_folder_named_through_a_link_is_reported_where_it_is() {
    let dir = dir();
    let real = dir.tmp.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = dir.tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let claim = claim(
        Builder::new(APP, link.join("app"))
            .dir(&dir.path)
            .start(&Args::default()),
    );
    assert_eq!(
        claim.state_dir(),
        Some(canonical(&real).join("app").as_path())
    );
    claim.release();
}

// The state folder names the runtime folder in the base: `i-` and 16 hex
// digits.
#[test]
fn each_state_folder_has_an_owner_of_its_own() {
    let dir = dir();
    let other = Builder::new(APP, dir.tmp.path().join("other")).dir(&dir.path);
    let a = claim(builder(&dir).start(&Args::default()));
    let b = claim(other.start(&Args::default()));
    assert_ne!(a.dir(), b.dir());
    for owner in [&a, &b] {
        assert_eq!(owner.dir().parent(), Some(dir.path.as_path()));
        let name = owner.dir().file_name().unwrap().to_str().unwrap();
        let hex = name.strip_prefix("i-").unwrap();
        let digit = |c: u8| c.is_ascii_digit() || (b'a'..=b'f').contains(&c);
        assert!(hex.len() == 16 && hex.bytes().all(digit), "{name}");
    }
    a.release();
    b.release();
}

#[cfg(unix)]
#[test]
fn launches_that_name_one_state_folder_through_a_link_meet() {
    let dir = dir();
    let real = dir.tmp.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = dir.tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let (owner, rx) = serve(claim(
        Builder::new(APP, real.join("app"))
            .dir(&dir.path)
            .start(&Args::default()),
    ));
    let info = match Builder::new(APP, link.join("app"))
        .dir(&dir.path)
        .start(&args(&["x"]))
    {
        Started::HandedOff(info) => info,
        other => panic!("{other:?}"),
    };
    assert!(info.confirmed());
    assert_eq!(rx.recv_timeout(SHORT).unwrap().payload(), &args(&["x"]));
    Builder::new(APP, link.join("app"))
        .dir(&dir.path)
        .probe()
        .unwrap();
    owner.release();
}

// Two runtime folders with one state folder, as in two containers: the
// second launch to take its lock finds the guard held, and runs alone at
// once without binding a socket.
#[cfg(unix)]
#[test]
fn a_second_runtime_folder_finds_the_state_folder_in_use() {
    let dir = dir();
    let first = claim(builder(&dir).start(&Args::default()));
    assert!(first.guarded());
    let other = builder(&dir).dir(dir.tmp.path().join("other"));
    let t = Instant::now();
    let reason = alone(other.start(&args(&["x"])));
    let guard = canonical(dir.tmp.path())
        .join("state")
        .join(".instance-handoff.lock");
    assert!(
        matches!(&reason, Reason::StateInUse { path, .. } if *path == guard),
        "{reason}"
    );
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    // It let go of its lock: nobody owns that runtime folder.
    let reason = other.probe().unwrap_err();
    assert!(matches!(reason, Reason::NoOwner { .. }), "{reason}");
    first.release();
    claim(other.start(&Args::default())).release();
}

// Guard::Off takes no guard and makes no guard file, so an owner in
// another runtime folder starts beside it. Like a keyed owner, it still
// makes the missing state folder, private. State::none has no folder to
// guard.
#[cfg(unix)]
#[test]
fn guard_off_keyed_and_no_state_take_no_guard() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    let dir = dir();
    let state = dir.tmp.path().join("state");
    let off = claim(builder(&dir).guard(Guard::Off).start(&Args::default()));
    assert!(!off.guarded());
    assert_eq!(mode(&state), 0o700);
    assert!(!state.join(".instance-handoff.lock").exists());
    let beside = claim(
        builder(&dir)
            .dir(dir.tmp.path().join("other"))
            .start(&Args::default()),
    );
    assert!(beside.guarded());
    assert!(state.join(".instance-handoff.lock").is_file());
    beside.release();
    off.release();

    let keyed_state = dir.tmp.path().join("keyed");
    let keyed = claim(
        Builder::new(APP, keyed_state.as_path())
            .dir(&dir.path)
            .scope("a")
            .start(&Args::default()),
    );
    assert!(!keyed.guarded());
    assert_eq!(mode(&keyed_state), 0o700);
    assert!(!keyed_state.join(".instance-handoff.lock").exists());
    keyed.release();

    let none = claim(
        Builder::new(APP, State::none())
            .dir(&dir.path)
            .start(&Args::default()),
    );
    assert!(!none.guarded());
    none.release();
}

#[test]
fn scopes_make_separate_owners() {
    let dir = dir();
    let a = claim(builder(&dir).scope("a").start(&Args::default()));
    let b = claim(builder(&dir).scope("b").start(&Args::default()));
    assert_ne!(a.dir(), b.dir());
    assert_eq!(
        Some(a.dir().to_path_buf()),
        builder(&dir).scope("a").runtime_dir()
    );
    a.release();
    b.release();
}

// The owner's HELLO names its state folder and scope, and a launch checks
// them against its own, which it resolves itself. A scope of 5000 bytes
// makes a HELLO past the 4096 bytes of its other records: a launch makes
// room for its own STATE, so its owner is still reached.
#[test]
fn launches_of_the_owners_state_and_scope_pass_its_check() {
    let dir = dir();
    for b in [
        builder(&dir),
        builder(&dir).scope("work"),
        builder(&dir).scope("x".repeat(5000)),
        Builder::new(APP, State::none()).dir(&dir.path),
        Builder::new(APP, State::none()).dir(&dir.path).scope(""),
    ] {
        let (owner, rx) = serve(claim(b.start(&Args::default())));
        assert!(b.probe().unwrap().confirmed());
        b.hand_off(&args(&["x"])).unwrap();
        assert_eq!(rx.recv_timeout(SHORT).unwrap().payload(), &args(&["x"]));
        owner.release();
    }
}

#[cfg(unix)]
#[test]
fn a_folder_open_to_others_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = dir();
    std::fs::create_dir(&dir.path).unwrap();
    std::fs::set_permissions(&dir.path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let reason = alone(builder(&dir).start(&Args::default()));
    assert!(matches!(reason, Reason::RuntimeDir { .. }), "{reason}");
}

#[test]
fn a_slow_handler_leaves_the_launch_handed_off_unconfirmed() {
    let dir = dir();
    let (tx, rx) = mpsc::channel();
    let owner = claim(builder(&dir).start(&Args::default())).serve(move |r: Request<Args>| {
        std::thread::sleep(Duration::from_millis(1500));
        tx.send(r).is_ok()
    });
    let t = Instant::now();
    let info = match builder(&dir).timeout(SHORT).start(&args(&["slow"])) {
        Started::HandedOff(info) => info,
        other => panic!("{other:?}"),
    };
    assert!(!info.confirmed());
    // The launch waited at least a second for the reply, not forever.
    let waited = t.elapsed();
    assert!(
        waited >= Duration::from_secs(1) && waited < Duration::from_millis(1500),
        "{waited:?}"
    );
    // Delivered once, late.
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(2)).unwrap().payload(),
        &args(&["slow"])
    );
    assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
    owner.release();
}

#[test]
fn a_relative_folder_is_made_absolute() {
    let dir = Builder::new(APP, State::none())
        .dir("run")
        .runtime_dir()
        .unwrap();
    assert!(dir.is_absolute(), "{}", dir.display());
    assert!(
        dir.starts_with(std::env::current_dir().unwrap().join("run")),
        "{}",
        dir.display()
    );
}

#[test]
fn a_zero_timeout_still_hands_off_to_a_healthy_owner() {
    let dir = dir();
    let (owner, rx) = serve(claim(builder(&dir).start(&Args::default())));
    builder(&dir)
        .timeout(Duration::ZERO)
        .hand_off(&args(&["now"]))
        .unwrap();
    assert_eq!(rx.recv_timeout(SHORT).unwrap().payload(), &args(&["now"]));
    owner.release();
}

#[test]
fn a_handler_that_releases_the_owner_still_confirms_its_request() {
    // The reply to a request already taken must go out, even as the owner
    // closes: otherwise the launch would take the freed lock and run the
    // request a second time.
    let dir = dir();
    let slot: Arc<Mutex<Option<Owner>>> = Arc::new(Mutex::new(None));
    let inside = slot.clone();
    let (tx, rx) = mpsc::channel();
    let owner = claim(builder(&dir).start(&Args::default())).serve(move |r: Request<Args>| {
        let taken = tx.send(r).is_ok();
        if let Some(owner) = inside.lock().unwrap().take() {
            owner.release();
        }
        taken
    });
    *slot.lock().unwrap() = Some(owner);
    match builder(&dir).start(&args(&["last"])) {
        Started::HandedOff(info) => assert!(info.confirmed()),
        other => panic!("{other:?}"),
    }
    assert_eq!(rx.recv_timeout(SHORT).unwrap().payload(), &args(&["last"]));
    // The lock is free again.
    claim(builder(&dir).start(&Args::default())).release();
}
