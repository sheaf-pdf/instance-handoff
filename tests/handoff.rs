//! Handoffs between launches in one process. Each test uses its own
//! runtime folder, so they run in parallel.

#![cfg(any(unix, windows))]

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use instance_handoff::{AppId, Args, Builder, Claim, End, Mode, Owner, Reason, Request, Started};

const APP: AppId = AppId::new("test.handoff");
const SHORT: Duration = Duration::from_millis(300);

struct Dir {
    _tmp: tempfile::TempDir,
    path: PathBuf,
}

/// A fresh runtime folder: below the temporary folder, which tempfile
/// makes readable by others.
fn dir() -> Dir {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("run");
    Dir { _tmp: tmp, path }
}

fn builder(dir: &Dir) -> Builder {
    Builder::new(APP)
        .dir(&dir.path)
        .timeout(Duration::from_secs(3))
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
    assert_eq!(owner.dir(), dir.path);

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
    let ended = Arc::new(Mutex::new(None));
    let seen = ended.clone();
    let (tx, rx) = mpsc::channel::<Request<Args>>();
    let owner = claim(builder(&dir).start(&Args::default()))
        .on_end(move |why| *seen.lock().unwrap() = Some(why))
        .serve(move |r| tx.send(r).is_ok());
    owner.stop();
    assert!(owner.is_stopped());
    // The handler (and the sender in it) is dropped with no launch arriving.
    assert!(matches!(
        rx.recv_timeout(Duration::from_secs(2)),
        Err(mpsc::RecvTimeoutError::Disconnected)
    ));
    assert_eq!(owner.ended(), Some(End::Stopped));
    assert_eq!(*ended.lock().unwrap(), Some(End::Stopped));

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
        Builder::new(AppId::new("test.other"))
            .dir(&dir.path)
            .start(&Args::default()),
    );
    assert!(matches!(reason, Reason::OtherApp { .. }), "{reason}");

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
    let _silent: Vec<_> = (0..3).map(|_| socket(&dir.path)).collect();
    let mut trickle = socket(&dir.path);
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
    let mut old = socket(&dir.path);
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
    assert!(dir.path.join("instance.lock").exists());
    builder(&dir).hand_off(&args(&["after"])).unwrap();
    assert_eq!(rx.recv_timeout(SHORT).unwrap().payload(), &args(&["after"]));
    assert_eq!(owner.ended(), None);
    owner.release();
}

// Windows can't delete or open up a folder the owner holds.
#[cfg(unix)]
#[test]
fn an_owner_whose_lock_was_taken_ends_with_lost_lock() {
    let dir = dir();
    let check = Duration::from_millis(400);
    let (tx, rx) = mpsc::channel::<Result<Request<Args>, End>>();
    let ended = tx.clone();
    let first = claim(
        builder(&dir)
            .__upkeep(check, Duration::from_secs(3600))
            .start(&Args::default()),
    )
    .on_end(move |why| drop(ended.send(Err(why))))
    .serve(move |r| tx.send(Ok(r)).is_ok());
    std::fs::remove_dir_all(&dir.path).unwrap();
    // A new owner takes the re-made folder before the first one looks.
    let (second, rx2) = serve(claim(builder(&dir).start(&Args::default())));
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
    assert!(t.elapsed() >= Duration::from_secs(1) && t.elapsed() < Duration::from_millis(1500));
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
    let dir = Builder::new(APP).dir("run").runtime_dir().unwrap();
    assert!(dir.is_absolute(), "{}", dir.display());
    assert_eq!(dir, std::env::current_dir().unwrap().join("run"));
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
