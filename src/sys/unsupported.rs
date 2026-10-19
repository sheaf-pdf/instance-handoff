//! Targets this crate has no lock for (the web, WASI, Solaris, iOS and
//! others). No process can own; every launch runs alone with
//! [`Reason::Unsupported`], and every public type still compiles, so shared
//! code needs no `cfg`.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::server::Core;
use crate::{AppId, Payload, Reason};

pub(crate) const SUPPORTED: bool = false;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Place {
    base: PathBuf,
    subs: Vec<OsString>,
}

impl Place {
    pub(crate) fn dir(dir: PathBuf) -> Place {
        Place {
            base: dir,
            subs: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, sub: impl Into<OsString>) {
        self.subs.push(sub.into());
    }

    pub(crate) fn path(&self) -> PathBuf {
        let mut p = self.base.clone();
        p.extend(&self.subs);
        p
    }
}

pub(crate) fn default_place(_: &AppId) -> Result<Place, Reason> {
    Err(Reason::Unsupported {})
}

pub(crate) fn final_path(_: &Path) -> io::Result<PathBuf> {
    Err(io::ErrorKind::Unsupported.into())
}

pub(crate) fn is_foreign(_: &Path) -> io::Result<bool> {
    Err(io::ErrorKind::Unsupported.into())
}

pub(crate) fn raised() -> bool {
    false
}

pub(crate) fn above_normal() -> bool {
    false
}

pub(crate) fn level() -> Option<crate::Level> {
    None
}

pub(crate) fn can_show_windows() -> Option<bool> {
    None
}

pub(crate) fn open_folder(_: &Place, _: bool) -> Result<Option<Folder>, Reason> {
    Err(Reason::Unsupported {})
}

/// Never made: `open_folder` always fails here.
#[derive(Debug)]
pub(crate) struct Folder(());

impl Folder {
    pub(crate) fn path(&self) -> &Path {
        unreachable!()
    }

    pub(crate) fn lock_path(&self) -> PathBuf {
        unreachable!()
    }

    pub(crate) fn lock(&self) -> io::Result<Option<Lock>> {
        unreachable!()
    }

    pub(crate) fn lock_held(&self) -> io::Result<bool> {
        unreachable!()
    }

    pub(crate) fn connect(&self, _: Option<Instant>) -> Result<Conn, Connect> {
        unreachable!()
    }
}

#[derive(Debug)]
pub(crate) struct Lock(());

impl Drop for Lock {
    fn drop(&mut self) {}
}

#[derive(Debug)]
pub(crate) struct Guard(());

impl Drop for Guard {
    fn drop(&mut self) {}
}

pub(crate) fn make_state_dir(_: &Path) -> io::Result<()> {
    Ok(())
}

pub(crate) fn take_guard(_: &Path, _: bool) -> Result<Option<Guard>, Reason> {
    Ok(None)
}

pub(crate) struct Conn(());

impl Conn {
    pub(crate) fn peer_pid(&self) -> Option<u32> {
        unreachable!()
    }

    pub(crate) fn read(&mut self, _: &mut [u8], _: Option<Instant>) -> io::Result<usize> {
        unreachable!()
    }

    pub(crate) fn write_all(&mut self, _: &[u8], _: Option<Instant>) -> io::Result<()> {
        unreachable!()
    }
}

pub(crate) enum Connect {
    Retry(io::Error),
    Peer(io::Error),
}

#[derive(Debug)]
pub(crate) struct Listener(());

pub(crate) fn before_hand_off(_: Option<u32>) {}

pub(crate) struct Waker;

impl Waker {
    pub(crate) fn new() -> Waker {
        Waker
    }

    pub(crate) fn wake(&self) {}
}

#[derive(Debug)]
pub(crate) struct Held {
    pub(crate) lock: Option<Lock>,
    pub(crate) guard: Option<Guard>,
}

impl Held {
    #[cfg(test)]
    pub(crate) fn detached() -> Held {
        Held {
            lock: None,
            guard: None,
        }
    }

    pub(crate) fn unlink_socket(&self) {}
}

#[derive(Debug)]
pub(crate) struct Claimed {
    pub(crate) folder: Folder,
    pub(crate) listener: io::Result<Listener>,
}

impl Claimed {
    pub(crate) fn new(_: Folder, _: Lock, _: Option<Guard>, _: &AppId) -> Claimed {
        unreachable!()
    }

    pub(crate) fn forked(&self) -> bool {
        unreachable!()
    }

    pub(crate) fn guarded(&self) -> bool {
        unreachable!()
    }

    pub(crate) fn into_parts(self) -> (Held, Option<Listener>, Option<io::Error>) {
        unreachable!()
    }

    pub(crate) fn release(self) {
        unreachable!()
    }

    pub(crate) fn abandon(self) {
        unreachable!()
    }
}

pub(crate) fn serve<T: Payload>(_: Core<T>, _: Option<Listener>, _: Place) {
    unreachable!()
}
