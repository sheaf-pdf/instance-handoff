//! A tokio service: decide before the runtime exists, deliver into tokio's
//! own bounded channel (full means busy), and stop without blocking a
//! worker.
//!
//! ```sh
//! cargo run --example tokio -- job-1    # the service, or a handoff to it
//! cargo run --example tokio -- stop
//! ```

#![cfg_attr(not(any(unix, windows)), allow(unused))]

use std::error::Error;
use std::pin::pin;
use std::sync::Arc;

use instance_handoff::{AppId, Args, Builder, End, Request, Started, State};
#[cfg(any(unix, windows))]
use tokio::sync::{Notify, mpsc};

const APP: AppId = AppId::headless("com.example.syncd");

#[cfg(not(any(unix, windows)))]
fn main() {}

#[cfg(any(unix, windows))]
fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::from_env();
    // Blocks for a few milliseconds, and at most the timeout plus a few
    // seconds: before the runtime, not on a worker. Inside a runtime, use
    // spawn_blocking.
    let claim = match Builder::new(APP, State::none()).start(&args) {
        Started::Owner(claim) => claim,
        Started::HandedOff(_) => return Ok(()),
        // A service must not run twice; Reason is an Error.
        Started::Alone(why) => return Err(why.into()),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let (tx, mut rx) = mpsc::channel::<Request<Args>>(64);
        // A `stop` launch skips the queue, so a full queue can't refuse it.
        let stop = Arc::new(Notify::new());
        let stop_requested = stop.clone();
        // try_send never waits: a full queue answers "busy", and the launch
        // retries within its timeout.
        let owner = claim.serve(move |request| {
            if request.payload().first().is_some_and(|a| a == "stop") {
                stop_requested.notify_one();
                true
            } else {
                tx.try_send(request).is_ok()
            }
        });
        tokio::spawn(job(Request::local(args)));
        // One ctrl_c future for the whole loop: a new one on every pass can
        // miss a SIGINT that lands between two passes.
        let mut ctrl_c = pin!(tokio::signal::ctrl_c());
        loop {
            tokio::select! {
                request = rx.recv() => match request {
                    Some(r) => drop(tokio::spawn(job(r))),
                    // The owner ended and dropped the handler; the queue is
                    // drained.
                    None => break,
                },
                // stop() returns at once, so it's fine on a worker.
                _ = stop.notified(), if !owner.is_stopped() => owner.stop(),
                _ = &mut ctrl_c, if !owner.is_stopped() => owner.stop(),
            }
        }
        if owner.ended() != Some(End::LostLock) {
            // ...flush state here, still holding the lock...
        }
    });
    Ok(())
}

#[cfg(any(unix, windows))]
async fn job(request: Request<Args>) {
    println!("syncd: {:?} from {:?}", request.payload(), request.cwd());
}
