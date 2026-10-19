//! The state folder's canonical path, so that launches naming one folder
//! through different links agree on it, and whether it is another user's.

use std::ffi::OsStr;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::sys;

/// `path` with its links resolved. A relative path is made absolute
/// against the working directory. Then the nearest folder on it that
/// exists is resolved (`realpath` on Unix, the final path on Windows), and
/// the part that doesn't exist yet is appended with its `..` folded. A path
/// that can't be resolved, such as one through a folder this user can't
/// search or on a Windows volume that reports no final paths, is kept as
/// given, and so is one that can't be made absolute.
pub(crate) fn canonical(path: &Path) -> PathBuf {
    let absolute = match std::path::absolute(path) {
        Ok(absolute) => absolute,
        Err(e) => {
            log::warn!(
                "instance-handoff: can't make the state folder {} absolute, so it is used as given: {e}",
                path.display()
            );
            return path.to_path_buf();
        }
    };
    match resolve(&absolute) {
        Ok(resolved) => resolved,
        Err(e) => {
            log::warn!(
                "instance-handoff: can't resolve the links of the state folder {}, so it is used as given: {e}",
                absolute.display()
            );
            absolute
        }
    }
}

fn resolve(path: &Path) -> io::Result<PathBuf> {
    let (resolved, missing) = nearest(path)?;
    let folded = fold(resolved, &missing);
    if !missing.contains(&Component::ParentDir) {
        return Ok(folded);
    }
    // Folding can bring a folder that exists back onto the path, as
    // `<real>/new/../link` brings `link`, so resolve it again. No `..` is
    // left this time.
    let (resolved, missing) = nearest(&folded)?;
    Ok(fold(resolved, &missing))
}

/// The nearest folder on the absolute `path` that exists, resolved, and the
/// parts after it, which don't exist yet.
fn nearest(path: &Path) -> io::Result<(PathBuf, Vec<Component<'_>>)> {
    let mut missing = Vec::new();
    let mut existing = path;
    loop {
        match sys::final_path(existing) {
            Ok(resolved) => {
                missing.reverse();
                return Ok((resolved, missing));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut components = existing.components();
                match components.next_back() {
                    // Even the root is missing.
                    None | Some(Component::Prefix(_) | Component::RootDir) => return Err(e),
                    Some(last) => {
                        missing.push(last);
                        existing = components.as_path();
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// `resolved` with the missing `tail` appended. Each `..` in the tail drops
/// the part before it, as it will once those folders are created, so a
/// folder has one canonical form before and after it exists. A `..` with
/// no missing part before it drops the last part of `resolved`, whose links
/// are already resolved.
fn fold(mut resolved: PathBuf, tail: &[Component<'_>]) -> PathBuf {
    let mut parts: Vec<&OsStr> = Vec::new();
    for part in tail {
        match part {
            Component::ParentDir => {
                if parts.pop().is_none() {
                    resolved.pop();
                }
            }
            Component::CurDir => {}
            _ => parts.push(part.as_os_str()),
        }
    }
    resolved.extend(parts);
    resolved
}

/// The folder that makes the canonical `state` another user's, if one
/// does: `state` itself or, while it is missing, the nearest folder above
/// it that exists, which is where it would be created. A folder whose
/// owner can't be read passes, with a warning in the log, as a path whose
/// links can't be resolved does.
pub(crate) fn foreign(state: &Path) -> Option<PathBuf> {
    foreign_with(state, sys::is_foreign)
}

/// [`foreign`], asking `is_foreign` about each folder in turn.
fn foreign_with(state: &Path, is_foreign: impl Fn(&Path) -> io::Result<bool>) -> Option<PathBuf> {
    let mut path = state;
    loop {
        match is_foreign(path) {
            Ok(true) => return Some(path.to_path_buf()),
            Ok(false) => return None,
            Err(e) if e.kind() == io::ErrorKind::NotFound => path = path.parent()?,
            Err(e) => {
                log::warn!(
                    "instance-handoff: can't read who owns {}, so the state folder isn't checked: {e}",
                    path.display()
                );
                return None;
            }
        }
    }
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;

    /// A name nothing in the temporary folder's parent has.
    fn missing_name() -> String {
        format!("ih-missing-{}", std::process::id())
    }

    #[test]
    fn an_existing_folder_is_resolved() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(canonical(tmp.path()), sys::final_path(tmp.path()).unwrap());
    }

    #[test]
    fn a_missing_tail_is_kept_as_given() {
        let tmp = tempfile::tempdir().unwrap();
        let real = sys::final_path(tmp.path()).unwrap();
        assert_eq!(
            canonical(&tmp.path().join("a").join("b")),
            real.join("a").join("b")
        );
    }

    #[test]
    fn a_relative_path_is_made_absolute() {
        let name = missing_name();
        let cwd = sys::final_path(&std::env::current_dir().unwrap()).unwrap();
        assert_eq!(canonical(Path::new(&name)), cwd.join(&name));
    }

    // `mkdir -p a/../b` makes `b` beside `a`, so that is the folder's form
    // before it exists too. On Windows, making the path absolute already
    // folds it.
    #[test]
    fn a_missing_tail_folds_its_dot_dots() {
        let tmp = tempfile::tempdir().unwrap();
        let real = sys::final_path(tmp.path()).unwrap();
        let path = tmp.path().join("a").join("..").join("b");
        assert_eq!(canonical(&path), real.join("b"));
        std::fs::create_dir_all(&path).unwrap();
        assert_eq!(canonical(&path), real.join("b"));
    }

    #[test]
    fn a_dot_dot_past_the_missing_tail_leaves_the_resolved_folder() {
        let tmp = tempfile::tempdir().unwrap();
        let real = sys::final_path(tmp.path()).unwrap();
        let name = missing_name();
        let path = tmp.path().join("a").join("..").join("..").join(&name);
        assert_eq!(canonical(&path), real.parent().unwrap().join(&name));
    }

    #[test]
    fn folding_a_tail_that_starts_with_dot_dot() {
        fn fold_str(resolved: &str, tail: &str) -> PathBuf {
            let tail: Vec<_> = Path::new(tail).components().collect();
            fold(PathBuf::from(resolved), &tail)
        }
        let x = Path::new("x");
        assert_eq!(fold_str("x/y", "../b"), x.join("b"));
        assert_eq!(fold_str("x/y", "../../b/c/../d"), Path::new("b").join("d"));
        assert_eq!(fold_str("x/y", "a/../../b"), x.join("b"));
        assert_eq!(fold_str("/", "../b"), Path::new("/").join("b"));
    }

    #[cfg(unix)]
    #[test]
    fn links_are_resolved() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, tmp.path().join("link")).unwrap();
        assert_eq!(
            canonical(&tmp.path().join("link").join("state")),
            sys::final_path(&real).unwrap().join("state")
        );
    }

    // Folding `new/..` brings `link` onto the path: it is resolved as if it
    // had been named directly.
    #[cfg(unix)]
    #[test]
    fn a_folded_tail_resolves_the_links_it_reaches() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, tmp.path().join("link")).unwrap();
        let path = tmp.path().join("new").join("..").join("link").join("state");
        let want = sys::final_path(&real).unwrap().join("state");
        assert_eq!(canonical(&path), want);
        std::fs::create_dir_all(&path).unwrap();
        assert_eq!(canonical(&path), want);
    }

    // A file where a folder should be: realpath fails with ENOTDIR, not
    // ENOENT, so nothing on the path counts as missing.
    #[cfg(unix)]
    #[test]
    fn a_path_that_cant_be_resolved_is_kept_as_given() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("file"), "").unwrap();
        let path = tmp.path().join("file").join("state");
        assert_eq!(canonical(&path), path);
    }

    #[test]
    fn an_empty_path_is_kept_as_given() {
        assert_eq!(canonical(Path::new("")), Path::new(""));
    }

    // Which folders exist, and whether each is another user's: root given
    // greg's home.
    #[test]
    fn the_nearest_folder_that_exists_decides() {
        let disk = [("/", false), ("/home", false), ("/home/greg", true)];
        let is_foreign = |path: &Path| match disk.iter().find(|(p, _)| Path::new(p) == path) {
            Some(&(_, foreign)) => Ok(foreign),
            None => Err(io::ErrorKind::NotFound.into()),
        };
        let foreign = |state: &str| foreign_with(Path::new(state), is_foreign);
        let greg = Some(PathBuf::from("/home/greg"));
        assert_eq!(foreign("/home/greg"), greg);
        assert_eq!(foreign("/home/greg/.config/app"), greg);
        assert_eq!(foreign("/home/other/app"), None);
        assert_eq!(foreign("/srv/app"), None);
        // Nothing exists, not even the root.
        assert_eq!(
            foreign_with(Path::new("/a"), |_| Err(io::ErrorKind::NotFound.into())),
            None
        );
        assert_eq!(foreign_with(Path::new(""), is_foreign), None);
    }

    // The walk stops there, though the folder above it is another user's.
    #[test]
    fn a_folder_whose_owner_cant_be_read_passes() {
        let is_foreign = |path: &Path| match path.to_str() {
            Some("/home/greg") => Ok(true),
            _ => Err(io::ErrorKind::PermissionDenied.into()),
        };
        assert_eq!(foreign_with(Path::new("/home/greg/app"), is_foreign), None);
    }

    #[test]
    fn this_users_temporary_folder_is_its_own() {
        let tmp = tempfile::tempdir().unwrap();
        let state = canonical(tmp.path());
        assert_eq!(foreign(&state), None);
        assert_eq!(foreign(&state.join(missing_name()).join("app")), None);
    }
}
