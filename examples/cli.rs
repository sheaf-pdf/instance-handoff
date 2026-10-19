//! A command-line tool with one daemon per user.
//!
//! ```sh
//! cargo run --example cli -- add a.txt b.txt   # starts the daemon, or hands off
//! cargo run --example cli -- status            # never starts one
//! cargo run --example cli -- stop
//! cargo run --example cli -- --detach add c.txt   # Unix: background once owner
//! ```

use std::process::ExitCode;
use std::sync::mpsc;

use instance_handoff::{AppId, Args, Builder, End, Reason, Request, Started};

const APP: AppId = AppId::new("com.example.notes");

fn main() -> ExitCode {
    let mut args = Args::from_env();
    let detach = args.first().is_some_and(|a| a == "--detach");
    if detach {
        args = Args::new(args.iter().skip(1));
    }
    let builder = Builder::new(APP);

    // Remote control: talk to a running daemon, never become one.
    match args.first().and_then(|a| a.to_str()) {
        Some("status") => {
            return match builder.probe() {
                Ok(daemon) => {
                    match daemon.pid() {
                        Some(pid) => println!("notes: running (pid {pid})"),
                        None => println!("notes: running"),
                    }
                    ExitCode::SUCCESS
                }
                Err(Reason::NoOwner { .. }) => {
                    println!("notes: not running");
                    ExitCode::from(1)
                }
                Err(why) => {
                    eprintln!("notes: {why}");
                    ExitCode::from(2)
                }
            };
        }
        Some("stop") => {
            return match builder.hand_off(&args) {
                Ok(_) => ExitCode::SUCCESS,
                Err(Reason::NoOwner { .. }) => {
                    eprintln!("notes: not running");
                    ExitCode::from(1)
                }
                Err(why) => {
                    eprintln!("notes: {why}");
                    ExitCode::from(2)
                }
            };
        }
        _ => {}
    }

    let claim = match builder.start(&args) {
        Started::Owner(claim) => claim,
        Started::HandedOff(_) => return ExitCode::SUCCESS,
        // A daemon refuses to run beside another: every reason is fatal.
        Started::Alone(why) => {
            eprintln!("notes: {why}");
            return ExitCode::from(2);
        }
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
    // Ends by itself: the owner drops the handler when it ends (stop() or a
    // lost lock), which closes the channel.
    for request in rx {
        if request.payload().first().is_some_and(|a| a == "stop") {
            owner.stop();
            continue;
        }
        handle(&request);
    }
    if owner.ended() == Some(End::LostLock) {
        eprintln!("notes: another daemon took over; not saving");
        return ExitCode::from(2);
    }
    // ...save state here, still holding the lock...
    ExitCode::SUCCESS
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
