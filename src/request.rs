use std::fmt;
use std::path::{Path, PathBuf};

/// Window-activation data a launch was started with, so the owner may
/// raise a window on its behalf.
///
/// Toolkits take it in different ways: winit 0.30 takes either value as
/// `ActivationToken::from_raw(…)` for a new window, GTK takes the startup id
/// as a startup notification id. Tokens are single-use, and a launch from a
/// terminal usually has none. Values over 1 KiB are dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Activation {
    xdg_activation_token: Option<String>,
    startup_id: Option<String>,
}

impl Activation {
    /// This process's activation data: `XDG_ACTIVATION_TOKEN` and
    /// `DESKTOP_STARTUP_ID`, read and left in place.
    pub fn from_env() -> Activation {
        let var = |name| std::env::var(name).ok().filter(|v: &String| !v.is_empty());
        Activation {
            xdg_activation_token: var("XDG_ACTIVATION_TOKEN"),
            startup_id: var("DESKTOP_STARTUP_ID"),
        }
    }

    /// The same data with a Wayland activation token, for activations that
    /// arrive by another route (a D-Bus `Activate` call's `activation-token`).
    #[must_use]
    pub fn with_xdg_activation_token(mut self, token: impl Into<String>) -> Activation {
        self.xdg_activation_token = Some(token.into());
        self
    }

    /// The same data with an X11 startup-notification id.
    #[must_use]
    pub fn with_startup_id(mut self, id: impl Into<String>) -> Activation {
        self.startup_id = Some(id.into());
        self
    }

    /// The Wayland `XDG_ACTIVATION_TOKEN`.
    pub fn xdg_activation_token(&self) -> Option<&str> {
        self.xdg_activation_token.as_deref()
    }

    /// The X11 `DESKTOP_STARTUP_ID`. The owner should also end the launch's
    /// startup sequence with it, or the busy cursor runs until it times out.
    pub fn startup_id(&self) -> Option<&str> {
        self.startup_id.as_deref()
    }

    /// The Wayland token, or else the X11 startup id: the one value a
    /// toolkit that takes either wants (winit).
    pub fn token(&self) -> Option<&str> {
        self.xdg_activation_token().or(self.startup_id())
    }

    /// Whether there's no activation data.
    pub fn is_empty(&self) -> bool {
        self.xdg_activation_token.is_none() && self.startup_id.is_none()
    }

    pub(crate) fn from_parts(
        xdg_activation_token: Option<String>,
        startup_id: Option<String>,
    ) -> Activation {
        Activation {
            xdg_activation_token,
            startup_id,
        }
    }
}

/// A launch's payload as the owner receives it, with what the crate sends
/// beside every payload: the launch's working directory and activation data.
pub struct Request<T> {
    payload: T,
    cwd: Option<PathBuf>,
    activation: Activation,
    launcher_pid: Option<u32>,
    remote: bool,
}

impl<T> Request<T> {
    /// A request made in this process, so the owner's own payload and opens
    /// that arrive by other routes (macOS open-file events, D-Bus
    /// activation, a menu) can go down the same channel as later launches.
    /// Its working directory is this process's, read now; it has no
    /// activation data. For the owner's own launch, when the toolkit doesn't
    /// read the token from the environment itself, add it:
    /// `Request::local(args).with_activation(Activation::from_env())`.
    pub fn local(payload: T) -> Request<T> {
        Request {
            payload,
            cwd: std::env::current_dir().ok(),
            activation: Activation::default(),
            launcher_pid: None,
            remote: false,
        }
    }

    pub(crate) fn remote(
        payload: T,
        cwd: Option<PathBuf>,
        activation: Activation,
        launcher_pid: Option<u32>,
    ) -> Request<T> {
        Request {
            payload,
            cwd,
            activation,
            launcher_pid,
            remote: true,
        }
    }

    /// The same request with `cwd` as its working directory.
    #[must_use]
    pub fn with_cwd(mut self, cwd: Option<PathBuf>) -> Request<T> {
        self.cwd = cwd;
        self
    }

    /// The same request with `activation`.
    #[must_use]
    pub fn with_activation(mut self, activation: Activation) -> Request<T> {
        self.activation = activation;
        self
    }

    /// What the launch handed over.
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// What the launch handed over, mutably.
    pub fn payload_mut(&mut self) -> &mut T {
        &mut self.payload
    }

    /// The payload, dropping the rest.
    pub fn into_payload(self) -> T {
        self.payload
    }

    /// The same request with its payload converted.
    #[must_use]
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Request<U> {
        Request {
            payload: f(self.payload),
            cwd: self.cwd,
            activation: self.activation,
            launcher_pid: self.launcher_pid,
            remote: self.remote,
        }
    }

    /// The launch's working directory, if it had one it could name (it may
    /// have been deleted). It is a path in the launch's view of the file
    /// system, which a container or another Windows logon session may not
    /// share.
    pub fn cwd(&self) -> Option<&Path> {
        self.cwd.as_deref()
    }

    /// The path `arg` names, as the launch meant it: an absolute path as it
    /// is, a relative one joined to the launch's working directory. `None`
    /// for a relative path when that directory is unknown, and on Windows
    /// for a drive-relative path (`D:file`) on another drive than it.
    ///
    /// Any string is a relative path, a flag such as `--verbose` included:
    /// call this only for the arguments your parser says are paths.
    pub fn resolve(&self, arg: impl AsRef<Path>) -> Option<PathBuf> {
        resolve(self.cwd.as_deref(), arg.as_ref())
    }

    /// The launch's activation data.
    pub fn activation(&self) -> &Activation {
        &self.activation
    }

    /// The launch's process id, as the OS reported it for the connection.
    /// `None` where the platform doesn't say, and where the launch is in a
    /// PID namespace this process can't see (every Flatpak instance has its
    /// own). The launch has usually exited by the time a request is handled,
    /// so don't signal it.
    pub fn launcher_pid(&self) -> Option<u32> {
        self.launcher_pid
    }

    /// Whether another process sent this request (not [`Request::local`]).
    pub fn is_remote(&self) -> bool {
        self.remote
    }
}

impl<T: Clone> Clone for Request<T> {
    fn clone(&self) -> Request<T> {
        Request {
            payload: self.payload.clone(),
            cwd: self.cwd.clone(),
            activation: self.activation.clone(),
            launcher_pid: self.launcher_pid,
            remote: self.remote,
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for Request<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("payload", &self.payload)
            .field("cwd", &self.cwd)
            .field("activation", &self.activation)
            .field("launcher_pid", &self.launcher_pid)
            .field("remote", &self.remote)
            .finish()
    }
}

fn resolve(cwd: Option<&Path>, arg: &Path) -> Option<PathBuf> {
    if arg.is_absolute() {
        return Some(arg.to_path_buf());
    }
    let cwd = cwd?;
    #[cfg(windows)]
    {
        use std::path::Component;
        let mut parts = arg.components();
        match parts.next() {
            // `D:file`: relative to that drive's own directory, which only
            // the launch's own drive has here.
            Some(Component::Prefix(p)) => {
                let ours = match cwd.components().next() {
                    Some(Component::Prefix(c)) => c,
                    _ => return None,
                };
                if !p.as_os_str().eq_ignore_ascii_case(ours.as_os_str()) {
                    return None;
                }
                return Some(cwd.join(parts.as_path()));
            }
            // `\dir\file`: the root of the launch's drive.
            Some(Component::RootDir) => {
                let mut out = PathBuf::new();
                if let Some(Component::Prefix(c)) = cwd.components().next() {
                    out.push(c.as_os_str());
                }
                out.push(arg);
                return Some(out);
            }
            _ => {}
        }
    }
    Some(cwd.join(arg))
}

/// The handler's answer to one launch.
///
/// A handler can return `bool` instead: `true` is [`Answer::Take`] and
/// `false` is [`Answer::Busy`], so a channel's `send(..).is_ok()` is a
/// handler.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The app has the request: the launch gets [`Started::HandedOff`] and
    /// exits.
    ///
    /// [`Started::HandedOff`]: crate::Started::HandedOff
    Take,
    /// Not now (a full queue, a receiver that's gone while the app quits).
    /// The launch keeps trying, the lock included, until its timeout, so it
    /// takes over if this process exits, and otherwise runs alone with
    /// [`Reason::Busy`]. For a state that won't pass (a consumer that died
    /// while the app runs on), [`Answer::Decline`] spares launches the wait.
    ///
    /// [`Reason::Busy`]: crate::Reason::Busy
    Busy,
    /// Never: the launch runs alone at once with [`Reason::Declined`].
    ///
    /// [`Reason::Declined`]: crate::Reason::Declined
    Decline,
}

mod sealed {
    pub trait Sealed {
        fn into_answer(self) -> super::Answer;
    }
    impl Sealed for super::Answer {
        fn into_answer(self) -> super::Answer {
            self
        }
    }
    impl Sealed for bool {
        fn into_answer(self) -> super::Answer {
            if self {
                super::Answer::Take
            } else {
                super::Answer::Busy
            }
        }
    }
}

/// What a handler may return: an [`Answer`], or a `bool` (`true` takes,
/// `false` is busy). Sealed.
#[diagnostic::on_unimplemented(
    message = "a handler returns an `Answer` or a `bool`, not `{Self}`",
    label = "this handler returns `{Self}`",
    note = "for a channel, return whether the send worked: `tx.send(request).is_ok()`, or `tx.try_send(request).is_ok()` for a bounded one"
)]
pub trait IntoAnswer: sealed::Sealed {}

impl IntoAnswer for Answer {}
impl IntoAnswer for bool {}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;

    #[test]
    fn resolve_joins_relative_paths_to_the_launch_cwd() {
        #[cfg(unix)]
        {
            let cwd = Path::new("/home/u/docs");
            assert_eq!(
                resolve(Some(cwd), Path::new("a.pdf")),
                Some(PathBuf::from("/home/u/docs/a.pdf"))
            );
            assert_eq!(
                resolve(Some(cwd), Path::new("/etc/x")),
                Some(PathBuf::from("/etc/x"))
            );
            assert_eq!(resolve(None, Path::new("a.pdf")), None);
            assert_eq!(
                resolve(None, Path::new("/a.pdf")),
                Some(PathBuf::from("/a.pdf"))
            );
        }
        #[cfg(windows)]
        {
            let cwd = Path::new(r"C:\Users\u");
            assert_eq!(
                resolve(Some(cwd), Path::new("a.pdf")),
                Some(PathBuf::from(r"C:\Users\u\a.pdf"))
            );
            assert_eq!(
                resolve(Some(cwd), Path::new(r"\x\a.pdf")),
                Some(PathBuf::from(r"C:\x\a.pdf"))
            );
            assert_eq!(
                resolve(Some(cwd), Path::new("c:a.pdf")),
                Some(PathBuf::from(r"C:\Users\u\a.pdf"))
            );
            assert_eq!(resolve(Some(cwd), Path::new("D:a.pdf")), None);
        }
    }
}
