//! A command-line tool with one daemon per user, which owns the folder the
//! notes are kept in.
//!
//! ```sh
//! cargo run --example cli -- add a.txt b.txt   # starts the daemon, or hands off
//! cargo run --example cli -- status            # never starts one
//! cargo run --example cli -- stop              # needs no rights, so hands down
//! cargo run --example cli -- migrate           # holds the notes; no daemon meanwhile
//! cargo run --example cli -- --detach add c.txt   # Unix: background once owner
//! ```

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc;

use instance_handoff::{AppId, Args, Builder, End, Reason, Request, Started, State};

const APP: AppId = AppId::headless("com.example.notes");

fn main() -> ExitCode {
    let mut args = Args::from_env();
    let detach = args.first().is_some_and(|a| a == "--detach");
    if detach {
        args = Args::new(args.iter().skip(1));
    }
    let Some(notes) = notes_dir() else {
        eprintln!(
            "notes: nowhere to keep the notes: set HOME (LOCALAPPDATA on Windows) to an \
             absolute path"
        );
        return ExitCode::from(2);
    };
    let builder = Builder::new(APP, State::dir(notes));

    // Remote control and batch commands: never become the daemon.
    match args.first().and_then(|a| a.to_str()) {
        Some("status") => {
            return match builder.probe() {
                // Its pid, and on Windows its integrity level.
                Ok(daemon) => {
                    println!("notes: running ({daemon})");
                    ExitCode::SUCCESS
                }
                Err(Reason::NoOwner { .. }) => {
                    println!("notes: not running");
                    ExitCode::from(1)
                }
                Err(why) => fail(&why),
            };
        }
        Some("stop") => {
            // Stopping needs no rights. So a launch with rights the daemon
            // lacks, as from an administrator terminal, gives them up and
            // hands its request down, rather than fail with MoreRights.
            return match builder.clone().hand_down(true).hand_off(&args) {
                Ok(daemon) => {
                    // The daemon's handler is told too, as Request::handed_down.
                    if let Some(rights) = daemon.handed_down() {
                        println!(
                            "notes: stopped the daemon ({daemon}) without this launch's {rights}"
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(Reason::NoOwner { .. }) => {
                    eprintln!("notes: not running");
                    ExitCode::from(1)
                }
                Err(why) => fail(&why),
            };
        }
        // A batch command: hold the notes for this process's own work. No
        // daemon starts until it is done, and none may be running.
        Some("migrate") => {
            return match builder.exclusive() {
                Ok(held) => {
                    if let Some(dir) = held.state_dir() {
                        // ...rewrite the notes in dir here, while held...
                        println!("notes: migrated {}", dir.display());
                    }
                    ExitCode::SUCCESS
                }
                Err(Reason::StateInUse { .. }) => {
                    eprintln!("notes: the daemon, or another migrate, holds the notes");
                    ExitCode::from(2)
                }
                Err(why) => fail(&why),
            };
        }
        _ => {}
    }

    // `add` keeps its rights: a launch with rights the daemon lacks fails
    // with MoreRights, rather than have the daemon act for it without them.
    let claim = match builder.start(&args) {
        Started::Owner(claim) => claim,
        Started::HandedOff(_) => return ExitCode::SUCCESS,
        // A daemon refuses to run beside another: every reason is fatal.
        Started::Alone(why) => return fail(&why),
    };

    // A Claim holds no thread: fork now and serve in the child. The parent
    // leaves with process::exit, so its copy of the Claim is never dropped.
    #[cfg(unix)]
    if detach {
        // SAFETY: this process has one thread so far.
        match unsafe { libc::fork() } {
            -1 => {
                eprintln!("notes: can't fork: {}", std::io::Error::last_os_error());
                return ExitCode::from(2);
            }
            // SAFETY: setsid has no preconditions.
            0 => unsafe {
                libc::setsid();
            },
            _ => std::process::exit(0),
        }
    }
    #[cfg(not(unix))]
    if detach {
        eprintln!("notes: --detach is for Unix; staying in the foreground");
    }

    let (tx, rx) = mpsc::channel();
    let owner = claim.serve(move |request| tx.send(request).is_ok());
    if let Some(e) = owner.listen_error() {
        eprintln!("notes: later launches can't reach this one: {e}");
    }

    handle(&Request::local(args));
    // Ends by itself: the owner drops the handler when it ends (stop(), or a
    // lost lock or state folder), which closes the channel.
    for request in rx {
        if request.payload().first().is_some_and(|a| a == "stop") {
            owner.stop();
            continue;
        }
        handle(&request);
    }
    if matches!(owner.ended(), Some(End::LostLock | End::LostState)) {
        eprintln!("notes: another daemon took over; not saving");
        return ExitCode::from(2);
    }
    // ...save the notes in owner.state_dir() here, still holding the lock...
    ExitCode::SUCCESS
}

/// The folder the notes are kept in. An app passes the folder its storage
/// layer writes, computed by the same function (`dirs::data_dir()` joined
/// with the app's own name, say), so that the daemon owns what the app
/// writes. This example has no storage layer, so it takes a folder under
/// HOME, or on Windows under LOCALAPPDATA.
fn notes_dir() -> Option<PathBuf> {
    let (var, name) = if cfg!(windows) {
        ("LOCALAPPDATA", "example-notes")
    } else {
        ("HOME", ".example-notes")
    };
    let base = PathBuf::from(std::env::var_os(var)?);
    // An empty or relative one would put the notes in the working folder.
    base.is_absolute().then(|| base.join(name))
}

/// Says why this launch can't go on, and gives the exit code for it.
fn fail(reason: &Reason) -> ExitCode {
    match reason {
        // The only rights compared in this release are Windows integrity
        // levels.
        Reason::MoreRights { owner, rights, .. } => eprintln!(
            "notes: the daemon ({owner}) lacks this launch's {rights}: run this from a \
             normal terminal"
        ),
        Reason::OwnerHasMoreRights { owner, rights, .. } => eprintln!(
            "notes: the daemon ({owner}) has {rights}: run this from an administrator terminal"
        ),
        // A daemon in another runtime folder (another container, say), or a
        // migrate.
        Reason::StateInUse { path, .. } => eprintln!(
            "notes: a daemon this launch can't reach, or a migrate, holds {}",
            path.display()
        ),
        // Raised rights, as under sudo: such a launch hands off to a daemon
        // at its own rights (root's, under sudo on Unix), but never starts
        // one, nor migrates.
        Reason::MayNotOwn { why, .. } => {
            eprintln!("notes: this launch may not hold the notes, since {why}")
        }
        _ => eprintln!("notes: {reason}"),
    }
    ExitCode::from(2)
}

fn handle(request: &Request<Args>) {
    let mut args = request.payload().iter();
    if args.next().is_some_and(|a| a == "add") {
        for file in args {
            // Paths mean the launch's working directory, not the daemon's.
            if let Some(path) = request.resolve(file) {
                println!("notes: added {}", path.display());
            }
        }
    }
}
