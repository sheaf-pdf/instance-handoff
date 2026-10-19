//! Windows: the runtime folder under Local AppData, one per integrity
//! level, `LockFileEx` on `instance.lock`, and a named pipe whose random
//! name is published in `instance.pipe` beside the lock. The crate's thread
//! runs overlapped I/O on every pipe instance at once.
//!
//! A launch hands off only to an owner of its own user at its own integrity
//! level: handed up, a request would gain rights; handed down, it would
//! lose the ones the user elevated for. Each level's folder is labelled at
//! that level, so lower levels can neither read it nor squat its lock.
//!
//! A launch refuses a Local AppData that resolves into the profiles folder
//! (`C:\Users`) but outside its user's profile (into another user's
//! profile or Public, say): its folders would sit where another user keeps
//! files. One redirected outside the profiles folder is used.
//!
//! Each folder from the base down gets an access list of its own, for this
//! user and SYSTEM, whatever its parent hands down; the missing parents of
//! a `Builder::dir` base are made as Windows makes any folder. In Local
//! AppData, the app's folder has no label, so it counts as medium. The
//! instance folder in it, which every level shares, is labelled medium by
//! whichever level makes it, and the label isn't handed down. Each level's
//! folder in it is labelled at that level, and hands the label down to what
//! is made in it. So each of these folders carries at most one label, its
//! own. A `Builder::dir` base and its instance folder are labelled at the
//! process's level, as a level's folder is. No label is protected (`S:P`):
//! that needs a privilege the crate never enables. A launch refuses an
//! instance folder in Local AppData labelled other than medium (none counts
//! as medium), and a level's folder labelled at another level.
//! `instance.lock` gets an access list of its own too, and takes its label
//! from its folder.
//!
//! The owner locks two bytes of `instance.lock`, both exclusively and
//! through one handle: byte 0, which is owning, then the byte at its
//! integrity level's RID (0x2000 at medium, 0x3000 at high), the level
//! marker. So the owner's level can be read from the kernel's lock state,
//! not from a file someone could write. An owner that can't take its
//! marker within about 100 ms gives byte 0 back, so no launch waits on an
//! owner without one. Closing the handle releases both.
//!
//! The pipe's controls, each against a threat:
//! - its name is 128 random bits, published only after the pipe exists, in
//!   a folder only this user can read: another user on a terminal server
//!   can't create it first;
//! - `FILE_FLAG_FIRST_PIPE_INSTANCE`: nobody else's instance can be joined;
//! - a protected access list for this user's SID alone, with this user as
//!   owner;
//! - a mandatory label at the owner's integrity level, so a launch at a
//!   lower level can't open it;
//! - `PIPE_REJECT_REMOTE_CLIENTS`;
//! - the launch connects for identification only, and checks that the pipe
//!   is its own user's, at its own level, before it sends anything;
//! - the owner checks the launch's token by impersonation: the same user at
//!   the same level.

use std::ffi::{OsStr, OsString, c_void};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_BROKEN_PIPE, ERROR_IO_PENDING,
    ERROR_LOCK_VIOLATION, ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, GENERIC_ALL,
    GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree, WAIT_FAILED,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetLengthSid, GetSidSubAuthority,
    GetSidSubAuthorityCount, GetTokenInformation, IsWellKnownSid, LABEL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSID, RevertToSelf, SECURITY_ATTRIBUTES, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY, TOKEN_USER, TokenIntegrityLevel, TokenSessionId, TokenUser,
    WinBuiltinAdministratorsSid, WinCreatorOwnerRightsSid, WinCreatorOwnerSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, DELETE, FILE_ADD_FILE,
    FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED,
    FILE_READ_ATTRIBUTES, FILE_READ_EA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_ATTRIBUTES, FILE_WRITE_EA, GetFileInformationByHandle, GetFinalPathNameByHandleW,
    GetVolumeInformationByHandleW, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
    OPEN_ALWAYS, PIPE_ACCESS_DUPLEX, READ_CONTROL, ReadFile, SECURITY_IDENTIFICATION, SYNCHRONIZE,
    UnlockFileEx, VOLUME_NAME_DOS, WRITE_DAC, WRITE_OWNER, WriteFile,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    WaitNamedPipeW,
};
use windows_sys::Win32::System::StationsAndDesktops::{
    GetProcessWindowStation, GetUserObjectInformationW, UOI_FLAGS, USEROBJECTFLAGS,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, FILE_PERSISTENT_ACLS,
    SECURITY_MANDATORY_MEDIUM_RID, SYSTEM_MANDATORY_LABEL_ACE_TYPE,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetCurrentThread, INFINITE, OpenProcessToken, OpenThreadToken,
    SetEvent, WaitForMultipleObjects, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_LocalAppData, GetProfilesDirectoryW, GetUserProfileDirectoryW, KF_FLAG_DEFAULT,
    SHGetKnownFolderPath,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{AllowSetForegroundWindow, WSF_VISIBLE};

use crate::id::valid_id;
use crate::naming::{OWNER_BYTE, level_folder, level_marker};
use crate::server::{Core, Peer, Session};
use crate::wire::refusal;
use crate::{AppId, Payload, Reason};

pub(crate) const SUPPORTED: bool = true;

pub(crate) type Listener = PipeListener;

const LOCK_FILE: &str = "instance.lock";
const ADDRESS_FILE: &str = "instance.pipe";
/// Two waits per connection, plus the wake event and the listening
/// instance, within `WaitForMultipleObjects`' 64.
const MAX_CONNECTIONS: usize = 30;
const STATUS_PENDING: usize = 0x103;
/// What a launch asks of the pipe: read and write, but not the right to
/// create instances of it.
const CLIENT_ACCESS: u32 = (FILE_GENERIC_READ | FILE_GENERIC_WRITE) & !FILE_APPEND_DATA;
/// Rights on a folder that let someone change what's in it.
const CHANGES: u32 = FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_WRITE_EA
    | FILE_DELETE_CHILD
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;
/// Rights on a folder that let someone read what's in it, such as the
/// pipe's name.
const READS: u32 = FILE_LIST_DIRECTORY | FILE_READ_EA | GENERIC_READ | GENERIC_ALL;
/// The normal integrity level, and an object's level when it has no label.
const MEDIUM: u32 = SECURITY_MANDATORY_MEDIUM_RID as u32;
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

fn denied(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, why.to_owned())
}

fn win32(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

fn is(e: &io::Error, code: u32) -> bool {
    e.raw_os_error() == Some(code as i32)
}

/// Owns a block that `LocalFree` releases.
struct Local(*mut c_void);

impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the block came from an API documented to be freed so.
            unsafe { LocalFree(self.0) };
        }
    }
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut s: *mut u16 = null_mut();
    // SAFETY: `sid` is a valid SID; `s` receives a LocalAlloc'd string.
    if unsafe { ConvertSidToStringSidW(sid, &mut s) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _free = Local(s.cast());
    // SAFETY: a NUL-terminated string from the call above.
    let len = (0..).take_while(|&i| unsafe { *s.add(i) } != 0).count();
    let units = unsafe { std::slice::from_raw_parts(s, len) };
    Ok(String::from_utf16_lossy(units))
}

/// A token's user SID and integrity level.
struct Identity {
    sid: Vec<u8>,
    sid_string: String,
    integrity: u32,
}

impl Identity {
    fn sid(&self) -> PSID {
        self.sid.as_ptr() as PSID
    }
}

fn token_info(token: HANDLE, class: i32) -> io::Result<Vec<u64>> {
    let mut len = 0;
    // SAFETY: a size query; nothing is written.
    unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut len) };
    let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
    // SAFETY: `buf` holds `len` bytes, aligned for the structures it holds.
    if unsafe { GetTokenInformation(token, class, buf.as_mut_ptr().cast(), len, &mut len) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buf)
}

fn identity(token: HANDLE) -> io::Result<Identity> {
    let user = token_info(token, TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER whose SID points into it.
    let sid = unsafe { (*(user.as_ptr() as *const TOKEN_USER)).User.Sid };
    let len = unsafe { GetLengthSid(sid) } as usize;
    let bytes = unsafe { std::slice::from_raw_parts(sid as *const u8, len) }.to_vec();
    let label = token_info(token, TokenIntegrityLevel)?;
    // SAFETY: the buffer holds a TOKEN_MANDATORY_LABEL whose SID points into
    // it; its last sub-authority is the integrity level.
    let integrity = unsafe {
        let sid = (*(label.as_ptr() as *const TOKEN_MANDATORY_LABEL))
            .Label
            .Sid;
        let count = *GetSidSubAuthorityCount(sid);
        *GetSidSubAuthority(sid, u32::from(count.saturating_sub(1)))
    };
    let mut id = Identity {
        sid: bytes,
        sid_string: String::new(),
        integrity,
    };
    id.sid_string = sid_string(id.sid())?;
    Ok(id)
}

/// This process's user and integrity level.
fn me() -> io::Result<&'static Identity> {
    static ME: OnceLock<Result<Identity, i32>> = OnceLock::new();
    let me = ME.get_or_init(|| {
        let mut token: HANDLE = null_mut();
        // SAFETY: the current-process pseudo handle; `token` receives a
        // handle that `OwnedHandle` closes.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error().raw_os_error().unwrap_or(0));
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        identity(token.as_raw_handle()).map_err(|e| e.raw_os_error().unwrap_or(0))
    });
    me.as_ref()
        .map_err(|&code| io::Error::from_raw_os_error(code))
}

/// Whether this launch's rights were raised from a login. Elevation isn't
/// read here, so no launch is: an elevated one owns in its level's folder.
pub(crate) fn raised() -> bool {
    false
}

/// Whether this launch has more rights than a normal process. Integrity
/// levels aren't compared here, so no launch has: each level owns in its
/// own folder.
pub(crate) fn above_normal() -> bool {
    false
}

/// This process's integrity level, or `None` when its token can't be
/// read.
pub(crate) fn level() -> Option<crate::Level> {
    me().ok().map(|me| crate::Level::from_rid(me.integrity))
}

/// Where this process would show its windows, gathered apart from the rule
/// so that the rule can be tested. `None` where a fact couldn't be read.
#[derive(Debug)]
struct Station {
    /// The token's session. Services run in session 0, whose windows
    /// nobody sees.
    session: Option<u32>,
    /// Whether the process's window station is visible (`WSF_VISIBLE`).
    /// Only a session's interactive station, `WinSta0`, is.
    visible: Option<bool>,
}

/// Whether a launch on Windows can show windows: not in session 0, and on
/// a visible window station. Either fact alone can say no. A visible
/// station says yes only outside session 0, so with the session unread
/// it is unknown.
fn shows_windows_from(station: &Station) -> Option<bool> {
    match (station.session, station.visible) {
        (Some(0), _) | (_, Some(false)) => Some(false),
        (Some(_), Some(true)) => Some(true),
        _ => None,
    }
}

fn station() -> Station {
    Station {
        session: session_id().ok(),
        visible: visible_station().ok(),
    }
}

/// Whether this launch can show windows, or `None` where that can't be
/// told. A launch in session 0, as services and OpenSSH logins are, or on
/// a window station that isn't visible, can't.
pub(crate) fn can_show_windows() -> Option<bool> {
    shows_windows_from(&station())
}

/// This process's session, from its token.
fn session_id() -> io::Result<u32> {
    let mut token: HANDLE = null_mut();
    // SAFETY: the current-process pseudo handle; `token` receives a handle
    // that `OwnedHandle` closes.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut session = 0u32;
    let mut len = 0;
    // SAFETY: a token open for query. The class's information is one u32,
    // and `session` is valid for writes of its size.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenSessionId,
            (&mut session as *mut u32).cast(),
            std::mem::size_of::<u32>() as u32,
            &mut len,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(session)
}

/// Whether this process's window station is visible.
fn visible_station() -> io::Result<bool> {
    // SAFETY: no arguments. The handle it returns is never to be closed,
    // and isn't.
    let station = unsafe { GetProcessWindowStation() };
    if station.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut flags = USEROBJECTFLAGS::default();
    let mut len = 0;
    // SAFETY: an open window station, and `flags` is valid for writes of
    // the size given.
    let ok = unsafe {
        GetUserObjectInformationW(
            station,
            UOI_FLAGS,
            (&mut flags as *mut USEROBJECTFLAGS).cast(),
            std::mem::size_of::<USEROBJECTFLAGS>() as u32,
            &mut len,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags.dwFlags & WSF_VISIBLE as u32 != 0)
}

fn trusted(sid: PSID, me: &Identity) -> bool {
    // SAFETY: both are valid SIDs.
    let known = unsafe {
        EqualSid(sid, me.sid()) != 0
            || IsWellKnownSid(sid, WinLocalSystemSid) != 0
            || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
            || IsWellKnownSid(sid, WinCreatorOwnerSid) != 0
            || IsWellKnownSid(sid, WinCreatorOwnerRightsSid) != 0
    };
    known || sid_string(sid).is_ok_and(|s| s == TRUSTED_INSTALLER)
}

fn random_hex() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    // SAFETY: `bytes` is valid for writes of its length.
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            bytes.as_mut_ptr(),
            16,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(io::Error::other(format!("BCryptGenRandom: {status:#x}")));
    }
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

// ---------------------------------------------------------------------------
// Where the folder is
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
    /// Local AppData: exists already.
    Known,
    /// [`Builder::dir`](crate::Builder::dir): created when missing.
    Create,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Place {
    base: PathBuf,
    kind: Base,
    /// The folders this crate makes in the base. Every integrity level
    /// shares them when there is a level folder below them. Without one,
    /// they belong to this process's level, and so does the base.
    subs: Vec<OsString>,
    /// The folder of this process's integrity level, last in the path.
    level: Option<OsString>,
}

impl Place {
    pub(crate) fn dir(dir: PathBuf) -> Place {
        Place {
            base: dir,
            kind: Base::Create,
            subs: Vec::new(),
            level: None,
        }
    }

    pub(crate) fn push(&mut self, sub: impl Into<OsString>) {
        self.subs.push(sub.into());
    }

    pub(crate) fn path(&self) -> PathBuf {
        let mut p = self.base.clone();
        p.extend(&self.subs);
        p.extend(&self.level);
        p
    }

    /// Each folder this crate makes in the base, with its role. Above a
    /// level folder, the last is the instance folder, and any before it
    /// (the app's folder) are shared. Without a level folder, each belongs
    /// to this process's level.
    fn folders(&self) -> impl Iterator<Item = (&OsString, Role)> {
        let key = self.subs.len().saturating_sub(1);
        let shared = self.level.is_some();
        let subs = self.subs.iter().enumerate().map(move |(i, sub)| {
            let role = match (shared, i == key) {
                (false, _) => Role::Level,
                (true, true) => Role::Key,
                (true, false) => Role::Shared,
            };
            (sub, role)
        });
        subs.chain(self.level.iter().map(|sub| (sub, Role::Level)))
    }
}

pub(crate) fn default_place(id: &AppId) -> Result<Place, Reason> {
    let mut path: *mut u16 = null_mut();
    // SAFETY: `path` receives a CoTaskMemAlloc'd string, freed below.
    let hr = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_LocalAppData,
            KF_FLAG_DEFAULT as u32,
            null_mut(),
            &mut path,
        )
    };
    if hr < 0 || path.is_null() {
        return Err(Reason::NoRuntimeDir {});
    }
    // SAFETY: a NUL-terminated string from the call above.
    let len = (0..).take_while(|&i| unsafe { *path.add(i) } != 0).count();
    let base = PathBuf::from(OsString::from_wide(unsafe {
        std::slice::from_raw_parts(path, len)
    }));
    unsafe { CoTaskMemFree(path.cast()) };
    let level = me().map_err(|e| Reason::runtime_dir(&base, e))?.integrity;
    Ok(Place {
        base,
        kind: Base::Known,
        subs: vec![id.as_str().into()],
        level: Some(level_folder(level).into()),
    })
}

/// `path` with its links and junctions resolved, from
/// `GetFinalPathNameByHandleW`. A `SUBST` letter becomes the real drive and
/// a mapped drive the share it maps, so launches in every logon session
/// agree on it.
pub(crate) fn final_path(path: &Path) -> io::Result<PathBuf> {
    // No access asked and all sharing allowed, so nothing the app holds open
    // gets in the way.
    let file = OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    final_path_of(&file)
}

/// The final path of the open `file`, as [`final_path`] gives it.
fn final_path_of(file: &File) -> io::Result<PathBuf> {
    let mut buf = vec![0u16; 260];
    loop {
        // SAFETY: an open handle, and a buffer valid for writes of its
        // length.
        let n = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        } as usize;
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        if n < buf.len() {
            buf.truncate(n);
            return Ok(plain_path(buf));
        }
        // Too small: `n` is the length it needs, the NUL included.
        buf.resize(n, 0);
    }
}

/// Whether the file at `path` belongs to a user this process doesn't trust
/// with its state: its owner isn't this user, SYSTEM, Administrators (which
/// owns what an elevated process makes) or TrustedInstaller. On a volume
/// that keeps no owners, such as FAT, nothing does.
pub(crate) fn is_foreign(path: &Path) -> io::Result<bool> {
    let file = OpenOptions::new()
        .access_mode(READ_CONTROL)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let handle = file.as_raw_handle();
    let mut flags = 0;
    // SAFETY: an open handle; the other out-parameters are null, which asks
    // for nothing.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            handle,
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            null_mut(),
            0,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & FILE_PERSISTENT_ACLS == 0 {
        return Ok(false);
    }
    let mut owner: PSID = null_mut();
    let mut sd: *mut c_void = null_mut();
    // SAFETY: a handle opened with READ_CONTROL; `owner` points into `sd`,
    // freed by `Local`.
    let err = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        )
    };
    if err != 0 {
        return Err(win32(err));
    }
    let _sd = Local(sd);
    if owner.is_null() {
        return Err(denied("its owner is unknown"));
    }
    Ok(!trusted(owner, me()?))
}

/// A final path in the form launches compare: `C:\…` on a drive and
/// `\\server\share\…` on a share, without the `\\?\` that
/// `GetFinalPathNameByHandleW` puts before both. Other forms are kept.
fn plain_path(mut path: Vec<u16>) -> PathBuf {
    if starts_with(&path, r"\\?\UNC\") {
        // `\\?\UNC\server` becomes `\\server`.
        path.drain(2..8);
    } else if starts_with(&path, r"\\?\") && is_drive(&path[4..]) {
        path.drain(..4);
    }
    PathBuf::from(OsString::from_wide(&path))
}

/// Whether `path` starts with the ASCII `prefix`.
fn starts_with(path: &[u16], prefix: &str) -> bool {
    path.len() >= prefix.len()
        && path
            .iter()
            .zip(prefix.bytes())
            .all(|(&u, b)| u == u16::from(b))
}

/// Whether `path` starts with a drive: a letter, a colon and a backslash.
fn is_drive(path: &[u16]) -> bool {
    path.first()
        .is_some_and(|&l| u8::try_from(l).is_ok_and(|l| l.is_ascii_alphabetic()))
        && starts_with(&path[1..], r":\")
}

/// Refuses Local AppData, open as `dir`, if its final path is in the
/// profiles folder but outside this user's profile ([`in_another_profile`]).
/// Only final paths are compared: where its own or a profile folder's
/// can't be read, nothing is refused.
fn check_profile(dir: &File) -> io::Result<()> {
    match final_path_of(dir).and_then(|path| Ok((path, profile_folders()?))) {
        Ok((path, (profiles, mine))) if in_another_profile(&path, &profiles, &mine) => {
            Err(denied(&format!(
                "{} is in the profiles folder, outside this user's profile",
                path.display()
            )))
        }
        Ok(_) => Ok(()),
        Err(e) => {
            log::warn!(
                "instance-handoff: can't read the final paths of Local AppData and the profile folders, so they aren't compared: {e}"
            );
            Ok(())
        }
    }
}

/// The profiles folder (`C:\Users`) and this user's profile, each with its
/// links resolved. An error if either can't be read or resolved.
fn profile_folders() -> io::Result<(PathBuf, PathBuf)> {
    // SAFETY: `written_path` passes a buffer valid for writes of `*len` units.
    let profiles = written_path(|buf, len| unsafe { GetProfilesDirectoryW(buf, len) })?;
    let mut token: HANDLE = null_mut();
    // SAFETY: the current-process pseudo handle; `token` receives a handle
    // that `OwnedHandle` closes.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    // SAFETY: a token opened with TOKEN_QUERY, as the call needs, and a
    // buffer valid for writes of `*len` units.
    let mine = written_path(|buf, len| unsafe {
        GetUserProfileDirectoryW(token.as_raw_handle(), buf, len)
    })?;
    Ok((final_path(&profiles)?, final_path(&mine)?))
}

/// The absolute path that `call` writes to a buffer of `*len` UTF-16
/// units. A call that fails and asks for a longer buffer gets one.
fn written_path(mut call: impl FnMut(*mut u16, *mut u32) -> i32) -> io::Result<PathBuf> {
    let mut buf = vec![0u16; 260];
    loop {
        let mut len = buf.len() as u32;
        if call(buf.as_mut_ptr(), &mut len) != 0 {
            break;
        }
        let e = io::Error::last_os_error();
        if len as usize <= buf.len() {
            return Err(e);
        }
        buf.resize(len as usize, 0);
    }
    let n = buf.iter().position(|&u| u == 0).unwrap_or(buf.len());
    let path = PathBuf::from(OsString::from_wide(&buf[..n]));
    if !path.is_absolute() {
        return Err(io::Error::other(format!(
            "not absolute: {}",
            path.display()
        )));
    }
    Ok(path)
}

/// Whether the folder `path` is in the profiles folder `profiles`, or is
/// that folder, but isn't in `mine`, this user's profile: it is then in
/// another user's profile, in Public, or where one may be made. Names are
/// compared whole and without case, and a verbatim prefix or a trailing
/// separator makes no difference.
fn in_another_profile(path: &Path, profiles: &Path, mine: &Path) -> bool {
    let names = |path: &Path| -> Vec<Vec<u16>> {
        plain_path(path.as_os_str().encode_wide().collect())
            .components()
            .map(|name| upper(name.as_os_str()))
            .collect()
    };
    let path = names(path);
    path.starts_with(&names(profiles)) && !path.starts_with(&names(mine))
}

/// `name` with each UTF-16 unit made upper case on its own, as NTFS
/// compares names, near enough. A letter whose capital isn't one unit,
/// such as `ß`, is kept.
fn upper(name: &OsStr) -> Vec<u16> {
    name.encode_wide()
        .map(|unit| {
            let mut up = char::from_u32(u32::from(unit))
                .into_iter()
                .flat_map(char::to_uppercase);
            match (up.next(), up.next()) {
                (Some(c), None) => u16::try_from(u32::from(c)).unwrap_or(unit),
                _ => unit,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The folder
// ---------------------------------------------------------------------------

/// An open, checked runtime folder. Its handle doesn't share delete, so
/// while it is open nobody can rename or remove it, or anything above it.
#[derive(Debug)]
pub(crate) struct Folder {
    path: PathBuf,
    _handle: File,
    /// `instance.pipe`, held open while this process publishes it, so that
    /// a delete can't leave launches unable to find the pipe.
    address: Mutex<Option<File>>,
}

fn open_dir(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(FILE_LIST_DIRECTORY | READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// What a folder this crate makes is for, which sets its label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// The app's folder in Local AppData, which every level shares:
    /// unlabelled, so it counts as medium.
    Shared,
    /// The instance folder in Local AppData, which every level shares:
    /// labelled medium, whatever level makes it, and the label isn't handed
    /// down. One with no label counts as medium too.
    Key,
    /// A folder of this process's integrity level: labelled at that level,
    /// and the label is handed down to everything made in it.
    Level,
}

/// A real folder, owned by this user (or SYSTEM, Administrators,
/// TrustedInstaller), that nobody else may change. A folder this crate
/// makes (one with a `role`) must also be one nobody else may read. An
/// instance folder in Local AppData must be labelled medium or not at all,
/// and a level's folder at this process's level (no label counts as
/// medium).
fn check_dir(dir: &File, role: Option<Role>) -> io::Result<()> {
    let handle = dir.as_raw_handle();
    // SAFETY: plain data, filled in by the call.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(denied("a link or junction, not a folder"));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(io::Error::new(io::ErrorKind::NotADirectory, "not a folder"));
    }
    let me = me()?;
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut sacl: *mut ACL = null_mut();
    let mut sd: *mut c_void = null_mut();
    // SAFETY: the out-pointers point into `sd`, freed by `Local`.
    let err = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            &mut sacl,
            &mut sd,
        )
    };
    if err != 0 {
        return Err(win32(err));
    }
    let _sd = Local(sd);
    if owner.is_null() || !trusted(owner, me) {
        return Err(denied("owned by another user"));
    }
    // SAFETY: a valid (or null) SACL from the call above.
    let labelled = unsafe { label(sacl) };
    match role {
        Some(Role::Key) if labelled.is_some_and(|l| l != MEDIUM) => {
            return Err(denied("labelled at an integrity level other than medium"));
        }
        Some(Role::Level) if labelled.unwrap_or(MEDIUM) != me.integrity => {
            return Err(denied("made for another integrity level"));
        }
        _ => {}
    }
    if dacl.is_null() {
        return Err(denied("no access list: anyone may change it"));
    }
    // SAFETY: a valid ACL from the call above.
    let count = unsafe { (*dacl).AceCount };
    for i in 0..u32::from(count) {
        let mut ace: *mut c_void = null_mut();
        // SAFETY: `i` is below the ACL's count.
        if unsafe { GetAce(dacl, i, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: every ACE starts with its header; an allow ACE, plain or
        // conditional, is the header, a mask and the SID.
        let ace = unsafe { &*(ace as *const AllowedAce) };
        let kind = u32::from(ace.header.ace_type);
        if kind != ACCESS_ALLOWED_ACE_TYPE && kind != ACCESS_ALLOWED_CALLBACK_ACE_TYPE {
            continue;
        }
        let sid = &ace.sid_start as *const u32 as PSID;
        if trusted(sid, me) {
            continue;
        }
        if ace.mask & CHANGES != 0 {
            return Err(denied("other users can change it"));
        }
        if role.is_some() && ace.mask & READS != 0 {
            return Err(denied("other users can read it"));
        }
    }
    Ok(())
}

#[repr(C)]
struct AceHeader {
    ace_type: u8,
    ace_flags: u8,
    ace_size: u16,
}

#[repr(C)]
struct AllowedAce {
    header: AceHeader,
    mask: u32,
    sid_start: u32,
}

/// Creates a folder that only this user (and SYSTEM) can open, whatever
/// its parent would hand down, labelled as its `role` wants. A level's
/// folder is labelled at this process's integrity level, and so is
/// everything made in it, so that lower levels can't open any of it. An
/// instance folder is labelled medium, which a process may set at medium
/// or above, and nothing made in it takes that label. An existing folder
/// is left as it is.
fn create_private_dir(path: &Path, role: Role) -> io::Result<()> {
    let me = me()?;
    let mut sddl = format!("D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY)", me.sid_string);
    match role {
        Role::Shared => {}
        Role::Key => sddl += "S:(ML;;NWNR;;;ME)",
        Role::Level => sddl += &format!("S:(ML;OICI;NWNR;;;S-1-16-{})", me.integrity),
    }
    create_dir_with_sd(path, &sddl)
}

/// Creates the folder `path` with the security `sddl` describes. An
/// existing folder is left as it is.
fn create_dir_with_sd(path: &Path, sddl: &str) -> io::Result<()> {
    let sd = SecurityDescriptor::from_sddl(sddl)?;
    let sa = sd.attributes();
    let wide_path = wide(path.as_os_str());
    // SAFETY: a NUL-terminated path and valid security attributes.
    if unsafe { CreateDirectoryW(wide_path.as_ptr(), &sa) } == 0 {
        let e = io::Error::last_os_error();
        if !is(&e, ERROR_ALREADY_EXISTS) {
            return Err(e);
        }
    }
    Ok(())
}

/// Opens the file `path` to read and write, creating it with the security
/// `sddl` describes when it is missing; an existing file keeps its own. A
/// link at `path` is opened as itself, not followed. While it is open,
/// others may open it to read and write, but not to delete or rename it.
fn create_file_with_sd(path: &Path, sddl: &str) -> io::Result<File> {
    let sd = SecurityDescriptor::from_sddl(sddl)?;
    let sa = sd.attributes();
    let wide_path = wide(path.as_os_str());
    // SAFETY: a NUL-terminated path, valid security attributes and no
    // template file.
    let h = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sa,
            OPEN_ALWAYS,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new handle that nothing else owns.
    Ok(unsafe { File::from_raw_handle(h) })
}

pub(crate) fn open_folder(place: &Place, create: bool) -> Result<Option<Folder>, Reason> {
    let mut path = place.base.clone();
    let missing = |e: &io::Error| e.kind() == io::ErrorKind::NotFound && !create;
    // Local AppData isn't the crate's, so it need only be safe, and not in
    // the profiles folder outside this user's profile. A `Builder::dir`
    // base is the crate's, and belongs to this process's level.
    let made = (place.kind == Base::Create).then_some(Role::Level);
    if let (Some(role), true) = (made, create) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Reason::runtime_dir(&path, e))?;
        }
        create_private_dir(&path, role).map_err(|e| Reason::runtime_dir(&path, e))?;
    }
    let checked = |dir: File| {
        check_dir(&dir, made)?;
        if place.kind == Base::Known {
            check_profile(&dir)?;
        }
        Ok(dir)
    };
    let mut dir = match open_dir(&path).and_then(checked) {
        Ok(dir) => dir,
        Err(e) if missing(&e) => return Ok(None),
        Err(e) => return Err(Reason::runtime_dir(&path, e)),
    };
    for (sub, role) in place.folders() {
        path.push(sub);
        if create {
            create_private_dir(&path, role).map_err(|e| Reason::runtime_dir(&path, e))?;
        }
        dir = match open_dir(&path).and_then(|d| check_dir(&d, Some(role)).map(|()| d)) {
            Ok(dir) => dir,
            Err(e) if missing(&e) => return Ok(None),
            Err(e) => return Err(Reason::runtime_dir(&path, e)),
        };
    }
    Ok(Some(Folder {
        path,
        _handle: dir,
        address: Mutex::new(None),
    }))
}

/// The held lock: exclusive `LockFileEx` locks on two bytes of the open
/// file, byte 0 and the marker of this process's integrity level. Both are
/// released when the handle closes. The file can't be deleted while it is
/// open.
#[derive(Debug)]
pub(crate) struct Lock(#[allow(dead_code)] File);

/// How long an owner that holds byte 0 tries for its marker. A launch's
/// shared probe holds the marker's byte only for a moment.
const MARKER_RETRY: Duration = Duration::from_millis(100);

/// An `OVERLAPPED` that names `offset`, for a call on a synchronous handle.
fn at(offset: u64) -> OVERLAPPED {
    // SAFETY: plain data, for which all zeros is valid.
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.Anonymous.Anonymous.Offset = offset as u32;
    ov.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
    ov
}

/// Locks `len` bytes of `file` from `offset`, exclusively or shared, and
/// never waits. `false` when another lock is in the way.
fn try_lock(file: &File, offset: u64, len: u64, exclusive: bool) -> io::Result<bool> {
    let mut flags = LOCKFILE_FAIL_IMMEDIATELY;
    if exclusive {
        flags |= LOCKFILE_EXCLUSIVE_LOCK;
    }
    let mut ov = at(offset);
    // SAFETY: a synchronous handle; with FAIL_IMMEDIATELY it never waits,
    // and the call is done with `ov` when it returns.
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle(),
            flags,
            0,
            len as u32,
            (len >> 32) as u32,
            &mut ov,
        )
    };
    if ok != 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    if is(&e, ERROR_LOCK_VIOLATION) {
        Ok(false)
    } else {
        Err(e)
    }
}

/// Gives back the range that `try_lock` took through `file`, at once
/// rather than when the handle closes.
fn unlock(file: &File, offset: u64, len: u64) -> io::Result<()> {
    let mut ov = at(offset);
    // SAFETY: a synchronous handle, so the call is done with `ov` when it
    // returns.
    let ok = unsafe {
        UnlockFileEx(
            file.as_raw_handle(),
            0,
            len as u32,
            (len >> 32) as u32,
            &mut ov,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Takes the lock through `file`: byte 0, then `marker`, both exclusive.
/// `false` when another handle holds byte 0, or when the marker can't be
/// taken within `MARKER_RETRY`. When the marker isn't taken, after the
/// retry or on an error, byte 0 is given back at once.
fn take(file: &File, marker: u64) -> io::Result<bool> {
    if !try_lock(file, OWNER_BYTE, 1, true)? {
        return Ok(false);
    }
    let until = Instant::now() + MARKER_RETRY;
    loop {
        match try_lock(file, marker, 1, true) {
            Ok(true) => return Ok(true),
            Ok(false) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(5));
            }
            failed => {
                // Closing the handle would free it too, but maybe not at
                // once.
                if let Err(e) = unlock(file, OWNER_BYTE, 1) {
                    log::debug!("instance-handoff: giving back {LOCK_FILE}: {e}");
                }
                return failed;
            }
        }
    }
}

/// The state folder's guard. Windows owners take none, so there is never
/// one to hold.
#[derive(Debug)]
pub(crate) enum Guard {}

// Owners drop or forget a guard as they do a lock.
impl Drop for Guard {
    fn drop(&mut self) {}
}

/// Makes nothing yet: a missing state folder is made with its access list
/// once Windows owners take the guard.
pub(crate) fn make_state_dir(_state: &Path) -> io::Result<()> {
    Ok(())
}

/// Windows owners take no guard: nothing is made or locked in the state
/// folder.
pub(crate) fn take_guard(_state: &Path, _shared: bool) -> Result<Option<Guard>, Reason> {
    Ok(None)
}

/// Where a launch connects.
struct Address {
    pipe: OsString,
}

impl Folder {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn lock_path(&self) -> PathBuf {
        self.path.join(LOCK_FILE)
    }

    /// Opens `instance.lock`, creating it when `create` is set. A new one
    /// gets an access list of its own, for this user and SYSTEM, and no
    /// label of its own: it takes its folder's.
    fn open_lock(&self, create: bool) -> io::Result<File> {
        let path = self.lock_path();
        if create {
            let sddl = format!("D:P(A;;FA;;;{})(A;;FA;;;SY)", me()?.sid_string);
            return create_file_with_sd(&path, &sddl);
        }
        OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }

    /// Takes the lock, creating the file: byte 0, then the marker at this
    /// process's level, both exclusive and through one handle. `None` when
    /// another handle holds byte 0. If the marker can't be taken within
    /// `MARKER_RETRY`, byte 0 is given back and the answer is `None` too,
    /// so that no launch waits on an owner without a marker. If taking it
    /// fails with an error, byte 0 is given back as well, and the error
    /// returned. An untrusted process (RID 0) would mark byte 0 itself, so
    /// its lock fails at once.
    pub(crate) fn lock(&self) -> io::Result<Option<Lock>> {
        let marker = level_marker(me()?.integrity);
        if marker == OWNER_BYTE {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "an untrusted process can't mark its level",
            ));
        }
        let file = self.open_lock(true)?;
        Ok(take(&file, marker)?.then_some(Lock(file)))
    }

    /// Whether another handle holds byte 0. If this check takes the byte,
    /// it gives it back at once, as `take` does, so a starting owner never
    /// finds it in its way.
    pub(crate) fn lock_held(&self) -> io::Result<bool> {
        let file = match self.open_lock(false) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        if !try_lock(&file, OWNER_BYTE, 1, true)? {
            return Ok(true);
        }
        if let Err(e) = unlock(&file, OWNER_BYTE, 1) {
            log::debug!("instance-handoff: giving back {LOCK_FILE}: {e}");
        }
        Ok(false)
    }

    /// Writes `instance.pipe` in one step: written beside it, then renamed
    /// over it. Then holds it open.
    fn publish(&self, app_id: &AppId, secret: &str) -> io::Result<()> {
        // Held, it can't be renamed over.
        self.let_go_of_address();
        let tmp = self.path.join(format!("{ADDRESS_FILE}.{secret}.tmp"));
        std::fs::write(&tmp, format!("{app_id} {secret}\n"))?;
        std::fs::rename(&tmp, self.path.join(ADDRESS_FILE)).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })?;
        self.hold_address();
        Ok(())
    }

    /// Opens `instance.pipe` to read, sharing only reads, unless this
    /// process already holds it. Nothing else can then delete it, rename
    /// over it or write to it, and launches can still read it. A failure
    /// leaves it as before; the owner's upkeep tries again.
    fn hold_address(&self) {
        let mut held = self.address.lock().unwrap_or_else(|e| e.into_inner());
        if held.is_some() {
            return;
        }
        match OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(self.path.join(ADDRESS_FILE))
        {
            Ok(file) => *held = Some(file),
            Err(e) => log::debug!("instance-handoff: holding {ADDRESS_FILE}: {e}"),
        }
    }

    fn let_go_of_address(&self) {
        *self.address.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    fn published(&self) -> io::Result<Option<String>> {
        match std::fs::read_to_string(self.path.join(ADDRESS_FILE)) {
            Ok(text) => Ok(Some(text)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn unpublish(&self) {
        self.let_go_of_address();
        if let Err(e) = std::fs::remove_file(self.path.join(ADDRESS_FILE)) {
            if e.kind() != io::ErrorKind::NotFound {
                log::debug!("instance-handoff: removing {ADDRESS_FILE}: {e}");
            }
        }
    }

    /// The pipe the address file names, checked character by character, so
    /// it can't point anywhere but a local pipe of this crate.
    fn address(&self) -> io::Result<Option<Address>> {
        let Some(text) = self.published()? else {
            return Ok(None);
        };
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "a malformed instance.pipe");
        let line = text.strip_suffix('\n').ok_or_else(bad)?;
        let (id, secret) = line.split_once(' ').ok_or_else(bad)?;
        if !valid_id(id.as_bytes())
            || secret.len() != 32
            || !secret
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(bad());
        }
        Ok(Some(Address {
            pipe: pipe_name(id, secret),
        }))
    }

    /// Creates the pipe, then publishes its name. A failed publish (another
    /// program holding the file) is retried by the owner's upkeep.
    pub(crate) fn listen(&self, app_id: &AppId) -> io::Result<PipeListener> {
        let secret = random_hex()?;
        let name = pipe_name(app_id.as_str(), &secret);
        let sd = SecurityDescriptor::for_pipe()?;
        let first = create_instance(&name, &sd, true)?;
        let published = match self.publish(app_id, &secret) {
            Ok(()) => true,
            Err(e) => {
                log::warn!(
                    "instance-handoff {app_id}: writing {ADDRESS_FILE}: {e}; trying again soon"
                );
                false
            }
        };
        Ok(PipeListener {
            name,
            secret,
            sd,
            first: Some(first),
            published,
        })
    }

    pub(crate) fn connect(&self, deadline: Option<Instant>) -> Result<Conn, Connect> {
        let address = match self.address() {
            Ok(Some(a)) => a,
            Ok(None) => return Err(Connect::Retry(io::ErrorKind::NotFound.into())),
            Err(e) => return Err(Connect::Retry(e)),
        };
        let file = loop {
            let opened = OpenOptions::new()
                .access_mode(CLIENT_ACCESS)
                .security_qos_flags(SECURITY_IDENTIFICATION)
                .custom_flags(FILE_FLAG_OVERLAPPED)
                .open(&address.pipe);
            match opened {
                Ok(file) => break file,
                Err(e) if is(&e, ERROR_PIPE_BUSY) => {
                    if super_past(deadline) {
                        return Err(Connect::Retry(e));
                    }
                    let name = wide(&address.pipe);
                    // SAFETY: a NUL-terminated name.
                    unsafe { WaitNamedPipeW(name.as_ptr(), wait_ms(deadline).min(100)) };
                }
                // The pipe's label keeps a launch at a lower integrity level
                // out of a higher owner's pipe.
                Err(e) if is(&e, ERROR_ACCESS_DENIED) => return Err(Connect::Peer(e)),
                Err(e) => return Err(Connect::Retry(e)),
            }
        };
        check_pipe_owner(&file).map_err(Connect::Peer)?;
        let mut pid = 0;
        // SAFETY: `pid` is valid for writes.
        let pid = (unsafe { GetNamedPipeServerProcessId(file.as_raw_handle(), &mut pid) } != 0
            && pid != 0)
            .then_some(pid);
        Conn::new(file, pid).map_err(Connect::Retry)
    }
}

fn super_past(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|d| Instant::now() >= d)
}

fn wait_ms(deadline: Option<Instant>) -> u32 {
    match deadline {
        None => INFINITE,
        Some(d) => {
            let left = d.saturating_duration_since(Instant::now());
            let ms = left.as_millis() + u128::from(left.subsec_nanos() % 1_000_000 != 0);
            ms.min(u128::from(INFINITE - 1)) as u32
        }
    }
}

fn pipe_name(id: &str, secret: &str) -> OsString {
    format!(r"\\.\pipe\instance-handoff.{id}.{secret}").into()
}

/// The pipe a launch opened must be this user's, labelled at the launch's
/// own integrity level, or it isn't an owner this launch may hand off to.
/// A process can't label an object above its own level, so a lower
/// process of the same user can't pass for the owner.
fn check_pipe_owner(pipe: &File) -> io::Result<()> {
    let me = me()?;
    let mut owner: PSID = null_mut();
    let mut sacl: *mut ACL = null_mut();
    let mut sd: *mut c_void = null_mut();
    // SAFETY: the out-pointers point into `sd`, freed by `Local`.
    let err = unsafe {
        GetSecurityInfo(
            pipe.as_raw_handle(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            &mut sacl,
            &mut sd,
        )
    };
    if err != 0 {
        return Err(win32(err));
    }
    let _sd = Local(sd);
    // SAFETY: both are valid SIDs.
    if owner.is_null() || unsafe { EqualSid(owner, me.sid()) } == 0 {
        return Err(denied("the pipe belongs to another user"));
    }
    // SAFETY: a valid (or null) SACL from the call above.
    if unsafe { label(sacl) }.unwrap_or(MEDIUM) != me.integrity {
        return Err(denied("the owner runs at another integrity level"));
    }
    Ok(())
}

/// The integrity level a mandatory-label ACE in `sacl` names.
///
/// # Safety
///
/// `sacl` is null or a valid ACL.
unsafe fn label(sacl: *mut ACL) -> Option<u32> {
    if sacl.is_null() {
        return None;
    }
    // SAFETY: a valid ACL, per the contract.
    let count = unsafe { (*sacl).AceCount };
    for i in 0..u32::from(count) {
        let mut ace: *mut c_void = null_mut();
        // SAFETY: `i` is below the ACL's count.
        if unsafe { GetAce(sacl, i, &mut ace) } == 0 {
            return None;
        }
        // SAFETY: a label ACE is the header, a mask and the SID.
        let ace = unsafe { &*(ace as *const AllowedAce) };
        if u32::from(ace.header.ace_type) == SYSTEM_MANDATORY_LABEL_ACE_TYPE {
            let sid = &ace.sid_start as *const u32 as PSID;
            // SAFETY: a valid SID; its last sub-authority is the level.
            return Some(unsafe {
                let n = *GetSidSubAuthorityCount(sid);
                *GetSidSubAuthority(sid, u32::from(n.saturating_sub(1)))
            });
        }
    }
    None
}

/// The owner's check of a launch, once it has read from it: the same user
/// at the same integrity level (the pipe's label already keeps lower levels
/// out).
fn check_client(pipe: HANDLE) -> io::Result<()> {
    let me = me()?;
    // SAFETY: impersonation lasts until RevertToSelf below, on this thread.
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut token: HANDLE = null_mut();
    // SAFETY: the current-thread pseudo handle; `token` is closed below.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0;
    let opened_err = io::Error::last_os_error();
    // SAFETY: ends the impersonation started above.
    if unsafe { RevertToSelf() } == 0 {
        // Running on as the launch would be worse than stopping.
        std::process::abort();
    }
    if !opened {
        return Err(opened_err);
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let them = identity(token.as_raw_handle())?;
    // SAFETY: both are valid SIDs.
    if unsafe { EqualSid(them.sid(), me.sid()) } == 0 {
        return Err(denied(&format!("the launch is {}", them.sid_string)));
    }
    if them.integrity != me.integrity {
        return Err(denied("the launch runs at another integrity level"));
    }
    Ok(())
}

/// The security a new pipe, folder or file gets, made from SDDL.
struct SecurityDescriptor(Local);

// SAFETY: an immutable block, only read by the calls that create objects
// with it.
unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl std::fmt::Debug for SecurityDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecurityDescriptor")
    }
}

impl SecurityDescriptor {
    /// The pipe's: owned by this user, open to this user alone, and
    /// labelled at this process's integrity level.
    fn for_pipe() -> io::Result<SecurityDescriptor> {
        let me = me()?;
        SecurityDescriptor::from_sddl(&format!(
            "O:{sid}D:P(A;;{access:#x};;;{sid})S:(ML;;NWNR;;;S-1-16-{il})",
            sid = me.sid_string,
            access = FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            il = me.integrity,
        ))
    }

    fn from_sddl(sddl: &str) -> io::Result<SecurityDescriptor> {
        let sddl = wide(OsStr::new(sddl));
        let mut sd: *mut c_void = null_mut();
        // SAFETY: a NUL-terminated string; `sd` receives a LocalAlloc'd block.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(SecurityDescriptor(Local(sd)))
    }

    /// Attributes that give a new object this security, and a handle that
    /// child processes don't inherit. They point into `self`, so they are
    /// valid only while it lives.
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: (self.0).0,
            bInheritHandle: 0,
        }
    }
}

fn create_instance(name: &OsStr, sd: &SecurityDescriptor, first: bool) -> io::Result<OwnedHandle> {
    let sa = sd.attributes();
    let mut open = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if first {
        open |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    let name = wide(name);
    // SAFETY: a NUL-terminated name and valid security attributes.
    let h = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            open,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            &sa,
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new handle that nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(h) })
}

/// The pipe's name and what's needed to make more instances of it.
#[derive(Debug)]
pub(crate) struct PipeListener {
    name: OsString,
    secret: String,
    sd: SecurityDescriptor,
    first: Option<OwnedHandle>,
    /// Whether `instance.pipe` names this pipe yet.
    published: bool,
}

impl PipeListener {
    /// Another instance. `alone`: no instance of ours is open, so the name
    /// may have lapsed and must be ours alone again.
    fn instance(&mut self, alone: bool) -> io::Result<OwnedHandle> {
        match self.first.take() {
            Some(h) => Ok(h),
            None => create_instance(&self.name, &self.sd, alone),
        }
    }

    /// The name was taken while none of our instances held it: start over
    /// with a new one, published again.
    fn renew(&mut self, folder: &Folder, app_id: &AppId) -> io::Result<()> {
        let secret = random_hex()?;
        let name = pipe_name(app_id.as_str(), &secret);
        self.first = Some(create_instance(&name, &self.sd, true)?);
        self.name = name;
        self.secret = secret;
        self.published = folder.publish(app_id, &self.secret).is_ok();
        Ok(())
    }
}

pub(crate) enum Connect {
    Retry(io::Error),
    Peer(io::Error),
}

pub(crate) fn before_hand_off(owner_pid: Option<u32>) {
    if let Some(pid) = owner_pid {
        // SAFETY: no preconditions; failing only means the owner's window
        // may not come forward.
        unsafe { AllowSetForegroundWindow(pid) };
    }
}

// ---------------------------------------------------------------------------
// Overlapped operations
// ---------------------------------------------------------------------------

/// One overlapped read or write, boxed so it never moves while the system
/// may write to it.
struct Op {
    ov: OVERLAPPED,
    event: OwnedHandle,
    buf: Vec<u8>,
    pending: bool,
}

impl Op {
    fn new(size: usize) -> io::Result<Box<Op>> {
        // SAFETY: a new manual-reset event, unnamed and unsignalled.
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Box::new(Op {
            // SAFETY: plain data.
            ov: unsafe { std::mem::zeroed() },
            event: unsafe { OwnedHandle::from_raw_handle(event) },
            buf: vec![0; size],
            pending: false,
        }))
    }

    fn reset(&mut self) {
        // SAFETY: plain data.
        self.ov = unsafe { std::mem::zeroed() };
        self.ov.hEvent = self.event.as_raw_handle();
    }

    /// Starts a read of up to the buffer's size. `Err(BrokenPipe)` when the
    /// other end has closed.
    fn read(&mut self, h: HANDLE, len: usize) -> io::Result<()> {
        self.reset();
        let len = len.min(self.buf.len()) as u32;
        // SAFETY: the buffer and OVERLAPPED live in this box until the
        // operation completes or is cancelled.
        let ok = unsafe { ReadFile(h, self.buf.as_mut_ptr(), len, null_mut(), &mut self.ov) };
        self.started(ok)
    }

    fn write(&mut self, h: HANDLE, bytes: &[u8]) -> io::Result<()> {
        self.reset();
        self.buf.clear();
        self.buf.extend_from_slice(bytes);
        // SAFETY: as for `read`.
        let ok = unsafe {
            WriteFile(
                h,
                self.buf.as_ptr(),
                self.buf.len() as u32,
                null_mut(),
                &mut self.ov,
            )
        };
        self.started(ok)
    }

    fn connect(&mut self, h: HANDLE) -> io::Result<bool> {
        self.reset();
        // SAFETY: as for `read`.
        if unsafe { ConnectNamedPipe(h, &mut self.ov) } != 0 {
            return Ok(true);
        }
        let e = io::Error::last_os_error();
        if is(&e, ERROR_IO_PENDING) {
            self.pending = true;
            Ok(false)
        } else if is(&e, ERROR_PIPE_CONNECTED) {
            Ok(true)
        } else {
            Err(e)
        }
    }

    fn started(&mut self, ok: i32) -> io::Result<()> {
        if ok != 0 {
            // Done already; the result is collected like any other.
            self.pending = true;
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if is(&e, ERROR_IO_PENDING) {
            self.pending = true;
            Ok(())
        } else {
            Err(e)
        }
    }

    fn done(&self) -> bool {
        // SAFETY: the system may be writing this word; read it as it is now.
        self.pending && unsafe { std::ptr::read_volatile(&self.ov.Internal) } != STATUS_PENDING
    }

    /// The finished operation's byte count.
    fn result(&mut self, h: HANDLE) -> io::Result<usize> {
        let mut n = 0;
        // SAFETY: the operation has completed; nothing waits.
        let ok = unsafe { GetOverlappedResult(h, &self.ov, &mut n, 0) };
        self.pending = false;
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Cancels the operation and waits until the system is done with the
    /// buffer and the OVERLAPPED.
    fn cancel(&mut self, h: HANDLE) {
        if self.pending {
            let mut n = 0;
            // SAFETY: cancels this operation only, then waits for it.
            unsafe {
                CancelIoEx(h, &self.ov);
                GetOverlappedResult(h, &self.ov, &mut n, 1);
            }
            self.pending = false;
        }
    }
}

/// Waits for `op` until `deadline`; `TimedOut` cancels it. A wait counts
/// its timeout in clock ticks and can end a little before the deadline, so
/// it waits again until the deadline has passed.
fn wait_op(op: &mut Op, h: HANDLE, deadline: Option<Instant>) -> io::Result<usize> {
    loop {
        // SAFETY: a valid event handle.
        match unsafe { WaitForSingleObject(op.event.as_raw_handle(), wait_ms(deadline)) } {
            WAIT_TIMEOUT if deadline.is_some_and(|d| Instant::now() < d) => {}
            WAIT_TIMEOUT => {
                op.cancel(h);
                return Err(io::ErrorKind::TimedOut.into());
            }
            WAIT_FAILED => {
                let e = io::Error::last_os_error();
                op.cancel(h);
                return Err(e);
            }
            _ => return op.result(h),
        }
    }
}

/// A launch's connection to the owner.
pub(crate) struct Conn {
    pipe: File,
    read: Box<Op>,
    write: Box<Op>,
    pid: Option<u32>,
}

impl Conn {
    fn new(pipe: File, pid: Option<u32>) -> io::Result<Conn> {
        Ok(Conn {
            pipe,
            read: Op::new(16 * 1024)?,
            write: Op::new(0)?,
            pid,
        })
    }

    pub(crate) fn peer_pid(&self) -> Option<u32> {
        self.pid
    }

    pub(crate) fn read(&mut self, buf: &mut [u8], deadline: Option<Instant>) -> io::Result<usize> {
        let h = self.pipe.as_raw_handle();
        let started = self.read.read(h, buf.len());
        match started {
            Err(e) if is(&e, ERROR_BROKEN_PIPE) => return Ok(0),
            Err(e) => return Err(e),
            Ok(()) => {}
        }
        match wait_op(&mut self.read, h, deadline) {
            Ok(n) => {
                buf[..n].copy_from_slice(&self.read.buf[..n]);
                Ok(n)
            }
            Err(e) if is(&e, ERROR_BROKEN_PIPE) => Ok(0),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn write_all(
        &mut self,
        mut buf: &[u8],
        deadline: Option<Instant>,
    ) -> io::Result<()> {
        let h = self.pipe.as_raw_handle();
        while !buf.is_empty() {
            self.write.write(h, buf)?;
            let n = wait_op(&mut self.write, h, deadline)?;
            buf = &buf[n..];
        }
        Ok(())
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        let h = self.pipe.as_raw_handle();
        self.read.cancel(h);
        self.write.cancel(h);
    }
}

// ---------------------------------------------------------------------------
// The owner's thread
// ---------------------------------------------------------------------------

/// Wakes the crate's thread from its wait.
pub(crate) struct Waker(Option<OwnedHandle>);

impl Waker {
    pub(crate) fn new() -> Waker {
        // SAFETY: a new auto-reset event, unnamed and unsignalled.
        let h = unsafe { CreateEventW(null(), 0, 0, null()) };
        if h.is_null() {
            log::warn!(
                "instance-handoff: no wake event: {}",
                io::Error::last_os_error()
            );
            return Waker(None);
        }
        Waker(Some(unsafe { OwnedHandle::from_raw_handle(h) }))
    }

    pub(crate) fn wake(&self) {
        if let Some(h) = &self.0 {
            // SAFETY: a valid event handle.
            unsafe { SetEvent(h.as_raw_handle()) };
        }
    }
}

/// The folder and the lock, as the owner holds them. `guard` stays `None`:
/// Windows owners take no guard.
#[derive(Debug)]
pub(crate) struct Held {
    pub(crate) folder: Option<Folder>,
    pub(crate) lock: Option<Lock>,
    pub(crate) guard: Option<Guard>,
}

impl Held {
    #[cfg(test)]
    pub(crate) fn detached() -> Held {
        Held {
            folder: None,
            lock: None,
            guard: None,
        }
    }

    /// Withdraws the address, if this process still holds the lock.
    pub(crate) fn unlink_socket(&self) {
        if let (Some(folder), Some(_)) = (&self.folder, &self.lock) {
            folder.unpublish();
        }
    }
}

#[derive(Debug)]
pub(crate) struct Claimed {
    pub(crate) folder: Folder,
    pub(crate) lock: Lock,
    pub(crate) listener: io::Result<PipeListener>,
}

impl Claimed {
    pub(crate) fn new(
        folder: Folder,
        lock: Lock,
        _guard: Option<Guard>,
        app_id: &AppId,
    ) -> Claimed {
        let listener = folder.listen(app_id);
        Claimed {
            folder,
            lock,
            listener,
        }
    }

    /// Windows has no fork.
    pub(crate) fn forked(&self) -> bool {
        false
    }

    pub(crate) fn guarded(&self) -> bool {
        false
    }

    pub(crate) fn abandon(self) {
        std::mem::forget(self.lock);
    }

    pub(crate) fn into_parts(self) -> (Held, Option<PipeListener>, Option<io::Error>) {
        let held = Held {
            folder: Some(self.folder),
            lock: Some(self.lock),
            guard: None,
        };
        match self.listener {
            Ok(l) => (held, Some(l), None),
            Err(e) => (held, None, Some(e)),
        }
    }

    pub(crate) fn release(self) {
        self.folder.unpublish();
        drop(self.listener);
        drop(self.lock);
    }
}

/// A pipe instance waiting for a launch.
struct Accept {
    pipe: Option<OwnedHandle>,
    op: Box<Op>,
}

impl Accept {
    /// Listens on `pipe`. `true`: a launch is connected already.
    fn start(pipe: OwnedHandle) -> io::Result<(Accept, bool)> {
        let mut a = Accept {
            pipe: Some(pipe),
            op: Op::new(0)?,
        };
        let now = a.listen()?;
        Ok((a, now))
    }

    fn handle(&self) -> HANDLE {
        self.pipe.as_ref().map_or(null_mut(), |p| p.as_raw_handle())
    }

    /// Waits for a launch on this instance. A launch that connected and
    /// left already (`ERROR_NO_DATA`) is cleared off and the same instance
    /// listens again, so the pipe's name never lapses.
    fn listen(&mut self) -> io::Result<bool> {
        let h = self.handle();
        for _ in 0..8 {
            match self.op.connect(h) {
                Err(e) if is(&e, ERROR_NO_DATA) => {
                    // SAFETY: a valid pipe handle.
                    unsafe { DisconnectNamedPipe(h) };
                }
                other => return other,
            }
        }
        Err(io::Error::other("launches keep leaving as they connect"))
    }

    /// After a launch left while connecting: clear it off and listen again.
    fn relisten(&mut self) -> io::Result<bool> {
        // SAFETY: a valid pipe handle with no I/O pending.
        unsafe { DisconnectNamedPipe(self.handle()) };
        self.listen()
    }
}

impl Drop for Accept {
    fn drop(&mut self) {
        if let Some(pipe) = &self.pipe {
            self.op.cancel(pipe.as_raw_handle());
        }
    }
}

struct PipeConn<T> {
    pipe: OwnedHandle,
    read: Box<Op>,
    write: Box<Op>,
    session: Session<T>,
    /// The launch has been checked, and refused if it failed.
    checked: bool,
}

impl<T> PipeConn<T> {
    fn handle(&self) -> HANDLE {
        self.pipe.as_raw_handle()
    }
}

impl<T> Drop for PipeConn<T> {
    /// Closes without `DisconnectNamedPipe`, which would throw away a reply
    /// the launch hasn't read yet.
    fn drop(&mut self) {
        let h = self.handle();
        self.read.cancel(h);
        self.write.cancel(h);
    }
}

/// Keeps a read going while the session listens, and starts a write as
/// soon as it has something to say.
fn pump<T: Payload>(c: &mut PipeConn<T>, app_id: &AppId) {
    let h = c.handle();
    if !c.write.pending && !c.session.outgoing().is_empty() {
        let out = c.session.outgoing().to_vec();
        if c.write.write(h, &out).is_err() {
            c.session.broken();
            return;
        }
    }
    if !c.read.pending && !c.session.is_done() {
        if let Err(e) = c.read.read(h, 16 * 1024) {
            if is(&e, ERROR_BROKEN_PIPE) {
                c.session.eof(app_id);
            } else {
                c.session.broken();
            }
        }
    }
}

/// Runs the owner's thread until the handle closes it.
pub(crate) fn serve<T: Payload>(
    mut core: Core<T>,
    mut listener: Option<PipeListener>,
    _place: Place,
) {
    let app_id = core.ctx.app_id.clone();
    let mut accept: Option<Accept> = None;
    let mut conns: Vec<PipeConn<T>> = Vec::new();
    let upkeep = core.ctx.upkeep;
    let soon = Duration::from_secs(1);
    let mut next_check = Instant::now()
        + if listener.as_ref().is_some_and(|l| !l.published) {
            soon
        } else {
            upkeep.check
        };
    let mut next_listen: Option<Instant> = None;

    while core.poll_control() {
        let now = Instant::now();
        // One instance always waits for the next launch.
        if accept.is_none() && conns.len() < MAX_CONNECTIONS && next_listen.is_none_or(|t| now >= t)
        {
            next_listen = None;
            if let Some(l) = listener.as_mut() {
                let alone = conns.is_empty();
                match l.instance(alone).and_then(Accept::start) {
                    Ok((a, true)) => {
                        connected(a, &mut conns, &core, now);
                        continue;
                    }
                    Ok((a, false)) => accept = Some(a),
                    // With no instance of ours open, someone else made the
                    // name: move to a new one.
                    Err(e) if alone && (is(&e, ERROR_ACCESS_DENIED) || is(&e, ERROR_PIPE_BUSY)) => {
                        log::warn!(
                            "instance-handoff {app_id}: the pipe's name was taken; using a new one"
                        );
                        let renewed = {
                            let held = core.shared.held();
                            let closing =
                                core.shared.close.load(std::sync::atomic::Ordering::SeqCst);
                            match (&held.folder, &held.lock) {
                                // As check_address: never publish for an
                                // owner that is closing.
                                (Some(folder), Some(_)) if !closing => l.renew(folder, &app_id),
                                _ => Err(e),
                            }
                        };
                        match renewed {
                            Ok(()) => {
                                if !l.published {
                                    next_check = now + soon;
                                }
                                // Listen on the new pipe at once.
                                continue;
                            }
                            Err(e) => {
                                log::warn!("instance-handoff {app_id}: a new pipe: {e}");
                                next_listen = Some(now + Duration::from_millis(100));
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("instance-handoff {app_id}: another pipe instance: {e}");
                        next_listen = Some(now + Duration::from_millis(100));
                    }
                }
            }
        }
        for c in &mut conns {
            pump(c, &app_id);
        }

        let mut handles: Vec<HANDLE> = Vec::with_capacity(2 + 2 * conns.len());
        if let Some(w) = &core.shared.waker.0 {
            handles.push(w.as_raw_handle());
        }
        if let Some(a) = &accept {
            handles.push(a.op.event.as_raw_handle());
        }
        for c in &conns {
            if c.read.pending {
                handles.push(c.read.event.as_raw_handle());
            }
            if c.write.pending {
                handles.push(c.write.event.as_raw_handle());
            }
        }
        let mut deadline = next_check;
        for c in &conns {
            deadline = deadline.min(c.session.deadline());
        }
        if let Some(t) = next_listen {
            deadline = deadline.min(t);
        }
        if core.shared.waker.0.is_none() {
            deadline = deadline.min(now + Duration::from_millis(100));
        }
        let timeout = wait_ms(Some(deadline));
        if handles.is_empty() {
            std::thread::sleep(Duration::from_millis(u64::from(timeout)));
        } else {
            // SAFETY: valid handles, at most 64 of them.
            let r = unsafe {
                WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, timeout)
            };
            if r == WAIT_FAILED {
                log::error!(
                    "instance-handoff {app_id}: wait: {}",
                    io::Error::last_os_error()
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        if !core.poll_control() {
            break;
        }
        let now = Instant::now();

        if accept.as_ref().is_some_and(|a| a.op.done()) {
            let mut a = accept.take().expect("checked");
            let h = a.handle();
            let listening = match a.op.result(h) {
                Ok(_) => Ok(true),
                Err(e) => {
                    log::debug!("instance-handoff {app_id}: a launch left while connecting: {e}");
                    a.relisten()
                }
            };
            match listening {
                Ok(true) => connected(a, &mut conns, &core, now),
                Ok(false) => accept = Some(a),
                Err(e) => {
                    log::warn!("instance-handoff {app_id}: listening again: {e}");
                    // A fresh instance is made before this one closes.
                    accept = None;
                    if let Some(l) = listener.as_mut() {
                        if let Ok((fresh, now_connected)) =
                            l.instance(false).and_then(Accept::start)
                        {
                            if now_connected {
                                connected(fresh, &mut conns, &core, now);
                            } else {
                                accept = Some(fresh);
                            }
                        }
                    }
                    drop(a);
                }
            }
        }

        for c in &mut conns {
            let h = c.handle();
            if c.write.done() {
                match c.write.result(h) {
                    Ok(n) => c.session.wrote(n),
                    Err(_) => c.session.broken(),
                }
            }
            if c.read.done() {
                match c.read.result(h) {
                    Ok(0) => {}
                    Ok(n) => {
                        if !c.checked {
                            // Impersonation needs a read first. A launch
                            // that fails is told so at once, in place of
                            // READY, and what it sent is dropped.
                            c.checked = true;
                            if let Err(e) = check_client(h) {
                                log::warn!("instance-handoff {app_id}: refused a launch: {e}");
                                c.session.refuse(refusal::PEER, now);
                            }
                        }
                        let bytes = c.read.buf[..n].to_vec();
                        if let Some(request) = c.session.read(&bytes, &core, now) {
                            match core.deliver(request) {
                                Some(answer) => c.session.answer(answer, Instant::now()),
                                None => c.session.abandon(),
                            }
                        }
                    }
                    Err(e) if is(&e, ERROR_BROKEN_PIPE) => c.session.eof(&app_id),
                    Err(_) => c.session.broken(),
                }
            }
            if !c.session.is_done() && now >= c.session.deadline() {
                c.session.timed_out(now);
            }
            // A reply goes out at once, never on a later pass that a close
            // may cut short.
            pump(c, &app_id);
        }
        // A pipe has no half-close: after its last message, a connection
        // waits for the launch to close (it reads the REPLY first).
        conns.retain(|c| !c.session.is_done());

        if now >= next_check {
            let published = check_address(&core, listener.as_mut());
            next_check = now + if published { upkeep.check } else { soon };
        }
    }
    // Closing: every reply already decided gets a bounded chance to go out.
    let until = Some(Instant::now() + crate::server::DRAIN_WAIT);
    for c in &mut conns {
        let h = c.handle();
        loop {
            if c.write.pending {
                match wait_op(&mut c.write, h, until) {
                    Ok(n) => c.session.wrote(n),
                    Err(_) => break,
                }
            }
            if c.session.outgoing().is_empty() {
                break;
            }
            let out = c.session.outgoing().to_vec();
            if c.write.write(h, &out).is_err() {
                break;
            }
        }
    }
    drop(accept);
    drop(conns);
    drop(listener);
}

fn connected<T: Payload>(
    mut a: Accept,
    conns: &mut Vec<PipeConn<T>>,
    core: &Core<T>,
    now: Instant,
) {
    let app_id = &core.ctx.app_id;
    let (read, write) = match (Op::new(16 * 1024), Op::new(0)) {
        (Ok(r), Ok(w)) => (r, w),
        (Err(e), _) | (_, Err(e)) => {
            log::warn!("instance-handoff {app_id}: {e}");
            return;
        }
    };
    let mut pid = 0;
    // SAFETY: `pid` is valid for writes.
    let pid = (unsafe { GetNamedPipeClientProcessId(a.handle(), &mut pid) } != 0 && pid != 0)
        .then_some(pid);
    // Its connect has completed: nothing to cancel.
    let Some(pipe) = a.pipe.take() else {
        return;
    };
    let mut c = PipeConn {
        pipe,
        read,
        write,
        session: Session::new(core, Peer::new(pid), now),
        checked: false,
    };
    pump(&mut c, app_id);
    conns.push(c);
}

/// The address file must name this owner's pipe: written again when it
/// doesn't. Whether it does now.
fn check_address<T: Payload>(core: &Core<T>, listener: Option<&mut PipeListener>) -> bool {
    let Some(listener) = listener else {
        return true;
    };
    let held = core.shared.held();
    if core.shared.close.load(std::sync::atomic::Ordering::SeqCst) {
        return true;
    }
    let (Some(folder), Some(_)) = (&held.folder, &held.lock) else {
        return true;
    };
    let want = format!("{} {}\n", core.ctx.app_id, listener.secret);
    if folder.published().ok().flatten().as_deref() == Some(want.as_str()) {
        folder.hold_address();
        listener.published = true;
        return true;
    }
    if listener.published {
        log::warn!(
            "instance-handoff {}: {ADDRESS_FILE} was changed; writing it again",
            core.ctx.app_id
        );
    }
    listener.published = match folder.publish(&core.ctx.app_id, &listener.secret) {
        Ok(()) => true,
        Err(e) => {
            log::warn!(
                "instance-handoff {}: writing {ADDRESS_FILE}: {e}",
                core.ctx.app_id
            );
            false
        }
    };
    listener.published
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
    use windows_sys::Win32::Security::OBJECT_SECURITY_INFORMATION;

    const APP: &str = "test.windows";
    const KEY: &str = "i-0123456789abcdef";
    const DACL: OBJECT_SECURITY_INFORMATION = DACL_SECURITY_INFORMATION;
    const LABEL: OBJECT_SECURITY_INFORMATION = LABEL_SECURITY_INFORMATION;

    /// A place laid out as in Local AppData, in a private folder made in
    /// `tmp`: the app's folder, an instance folder, then this process's
    /// level folder.
    fn local(tmp: &Path) -> Place {
        let base = tmp.join("local");
        create_private_dir(&base, Role::Shared).unwrap();
        Place {
            base,
            kind: Base::Known,
            subs: vec![APP.into(), KEY.into()],
            level: Some(level_folder(me().unwrap().integrity).into()),
        }
    }

    /// An access list for this user and SYSTEM alone, its entries handed
    /// down as `inherit` says (`OICI`, or nothing).
    fn private(inherit: &str) -> String {
        let user = &me().unwrap().sid_string;
        format!("D:P(A;{inherit};FA;;;{user})(A;{inherit};FA;;;SY)")
    }

    /// The parts of `path`'s security that `info` names, as SDDL, and the
    /// level its label names, if `info` names the label and there is one.
    fn security(path: &Path, info: OBJECT_SECURITY_INFORMATION) -> (String, Option<u32>) {
        let file = OpenOptions::new()
            .access_mode(READ_CONTROL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .unwrap();
        let mut sacl: *mut ACL = null_mut();
        let mut sd: *mut c_void = null_mut();
        // SAFETY: a handle opened with READ_CONTROL; `sacl` points into
        // `sd`, freed by `Local`.
        let err = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                info,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut sacl,
                &mut sd,
            )
        };
        assert_eq!(err, 0, "GetSecurityInfo: {}", win32(err));
        let sd = Local(sd);
        // SAFETY: a valid (or null) SACL from the call above.
        (to_sddl(&sd, info), unsafe { label(sacl) })
    }

    /// The parts of the security descriptor `sd` holds that `info` names,
    /// as SDDL.
    fn to_sddl(sd: &Local, info: OBJECT_SECURITY_INFORMATION) -> String {
        let mut s: *mut u16 = null_mut();
        // SAFETY: both callers pass a security descriptor, from
        // GetSecurityInfo or from SDDL; `s` receives a LocalAlloc'd string,
        // freed by `Local`.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd.0,
                SDDL_REVISION_1,
                info,
                &mut s,
                null_mut(),
            )
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        let _free = Local(s.cast());
        // SAFETY: a NUL-terminated string from the call above.
        let len = (0..).take_while(|&i| unsafe { *s.add(i) } != 0).count();
        let units = unsafe { std::slice::from_raw_parts(s, len) };
        String::from_utf16_lossy(units)
    }

    /// The parts of `sddl` that `info` names, as Windows writes them back.
    /// It spells some SIDs by name, such as the built-in Administrator's
    /// (`LA`), which CI runs as.
    fn spelled(sddl: &str, info: OBJECT_SECURITY_INFORMATION) -> String {
        to_sddl(&SecurityDescriptor::from_sddl(sddl).unwrap().0, info)
    }

    /// Asserts that `open_folder` refuses `place` because of the folder
    /// `at`.
    fn refused(place: &Place, at: &Path) {
        match open_folder(place, true) {
            Err(Reason::RuntimeDir { path, .. }) => assert_eq!(path, at),
            other => panic!("{other:?}"),
        }
    }

    // The level folder comes last, below the instance folder that every
    // level shares. The runner's Local AppData is in the profiles folder,
    // so the profile check is live, and in the runner's own profile, so it
    // passes.
    #[test]
    fn the_default_folder_passes_the_check() {
        let mut place = default_place(&AppId::headless(APP)).unwrap();
        let base = open_dir(&place.base).unwrap();
        check_dir(&base, None).unwrap();
        let (profiles, mine) = profile_folders().unwrap();
        let local = final_path(&place.base).unwrap();
        let nowhere = Path::new(r"\\nowhere\x");
        assert!(in_another_profile(&local, &profiles, nowhere), "{local:?}");
        assert!(!in_another_profile(&local, &profiles, &mine), "{local:?}");
        check_profile(&base).unwrap();
        let level = level_folder(me().unwrap().integrity);
        place.push(KEY);
        assert_eq!(place.path(), place.base.join(APP).join(KEY).join(level));
    }

    // Each folder has an access list of its own and at most one label, its
    // own: the instance folder's isn't handed down to the level folder.
    // Windows reports a label given as a folder is made with AI
    // (auto-inherited) on the list that holds it, as the CI measurements in
    // docs/design show.
    #[test]
    fn folders_this_crate_makes_are_private_and_labelled() {
        let me = me().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let place = local(tmp.path());
        let folder = open_folder(&place, true).unwrap().unwrap();
        let app = place.base.join(APP);
        let key = app.join(KEY);
        assert_eq!(folder.path(), key.join(level_folder(me.integrity)));

        let both = DACL | LABEL;
        assert_eq!(security(&app, DACL).0, spelled(&private("OICI"), DACL));
        let (label, level) = security(&app, LABEL);
        assert_eq!(level, None, "{label}");
        let want = format!("{}S:AI(ML;;NWNR;;;ME)", private("OICI"));
        assert_eq!(security(&key, both).0, spelled(&want, both));
        let want = format!(
            "{}S:AI(ML;OICI;NWNR;;;S-1-16-{})",
            private("OICI"),
            me.integrity
        );
        assert_eq!(security(folder.path(), both).0, spelled(&want, both));

        // Under Builder::dir, the base and the instance folder belong to
        // this process's level.
        let mut place = Place::dir(tmp.path().join("dir"));
        place.push(KEY);
        let folder = open_folder(&place, true).unwrap().unwrap();
        for dir in [folder.path(), &tmp.path().join("dir")] {
            check_dir(&open_dir(dir).unwrap(), Some(Role::Level)).unwrap();
        }
    }

    // instance.lock has an access list of its own. Its one label is its
    // folder's, handed down.
    #[test]
    fn the_lock_file_has_its_own_access_list() {
        let tmp = tempfile::tempdir().unwrap();
        let folder = open_folder(&local(tmp.path()), true).unwrap().unwrap();
        let _lock = folder.lock().unwrap().unwrap();
        let path = folder.lock_path();
        assert_eq!(security(&path, DACL).0, spelled(&private(""), DACL));
        let (label, level) = security(&path, LABEL);
        assert_eq!(label.matches("(ML;").count(), 1, "{label}");
        assert_eq!(level, Some(me().unwrap().integrity), "{label}");
    }

    /// The level marker another handle holds in `file`, found as a launch
    /// will look for it: this process's own level's byte first, then the
    /// bytes in [1, 0x10000) by shared range locks, each given back at
    /// once, halving the range around a conflict. The highest held byte
    /// wins. Byte 0 is owning, never a marker, so at RID 0 only the search
    /// runs.
    fn marker(file: &File) -> io::Result<Option<u64>> {
        let own = level_marker(me()?.integrity);
        if own != OWNER_BYTE {
            if !try_lock(file, own, 1, false)? {
                return Ok(Some(highest_held(file, own + 1, 0x10000)?.unwrap_or(own)));
            }
            unlock(file, own, 1)?;
        }
        highest_held(file, 1, 0x10000)
    }

    /// The highest byte in `start..end` that another handle holds
    /// exclusively. An empty range holds none.
    fn highest_held(file: &File, start: u64, end: u64) -> io::Result<Option<u64>> {
        if start >= end {
            return Ok(None);
        }
        if try_lock(file, start, end - start, false)? {
            unlock(file, start, end - start)?;
            return Ok(None);
        }
        if end - start == 1 {
            return Ok(Some(start));
        }
        let mid = start + (end - start) / 2;
        match highest_held(file, mid, end)? {
            Some(byte) => Ok(Some(byte)),
            None => highest_held(file, start, mid),
        }
    }

    // On disk: byte 0 of instance.lock is owning, and the byte at the
    // owner's level's RID marks its level. Only a major release may change
    // them. Every other byte stays free for launches to probe.
    #[test]
    fn the_lock_holds_byte_0_and_a_marker_at_its_level() {
        let tmp = tempfile::tempdir().unwrap();
        let folder = open_folder(&Place::dir(tmp.path().join("run")), true)
            .unwrap()
            .unwrap();
        let lock = folder.lock().unwrap().unwrap();
        let rid = u64::from(me().unwrap().integrity);
        let other = folder.open_lock(false).unwrap();
        assert!(!try_lock(&other, 0, 1, false).unwrap());
        assert!(!try_lock(&other, rid, 1, false).unwrap());
        for (start, end) in [(1, rid), (rid + 1, 0x10000)] {
            assert!(try_lock(&other, start, end - start, true).unwrap());
            unlock(&other, start, end - start).unwrap();
        }
        assert_eq!(marker(&other).unwrap(), Some(rid));

        // Dropped, the lock frees both.
        drop(lock);
        assert_eq!(marker(&other).unwrap(), None);
        assert!(try_lock(&other, 0, 1, true).unwrap());
    }

    // A launch may hold the marker's byte for a moment while it probes.
    // Held longer, the owner gives byte 0 back rather than own without a
    // marker, and at once: its handle is still open when a third handle
    // finds byte 0 free.
    #[test]
    fn an_owner_without_its_marker_gives_byte_0_back() {
        let tmp = tempfile::tempdir().unwrap();
        let folder = open_folder(&Place::dir(tmp.path().join("run")), true)
            .unwrap()
            .unwrap();
        let rid = u64::from(me().unwrap().integrity);
        let other = folder.open_lock(true).unwrap();
        assert!(try_lock(&other, rid, 1, false).unwrap());
        let owner = folder.open_lock(false).unwrap();
        let began = Instant::now();
        assert!(!take(&owner, rid).unwrap());
        assert!(began.elapsed() >= MARKER_RETRY);
        assert!(!folder.lock_held().unwrap());

        unlock(&other, rid, 1).unwrap();
        assert!(take(&owner, rid).unwrap());
    }

    // Each label here is one this process may set: below its own level, or
    // at it.
    #[test]
    fn a_folder_made_for_another_integrity_level_is_refused() {
        let me = me().unwrap();
        let below = format!(
            "{}S:(ML;OICI;NWNR;;;S-1-16-{})",
            private("OICI"),
            me.integrity - 0x1000
        );

        // An instance folder labelled low.
        let tmp = tempfile::tempdir().unwrap();
        let place = local(tmp.path());
        let app = place.base.join(APP);
        create_private_dir(&app, Role::Shared).unwrap();
        let low = format!("{}S:(ML;;NWNR;;;LW)", private("OICI"));
        create_dir_with_sd(&app.join(KEY), &low).unwrap();
        refused(&place, &app.join(KEY));

        // One labelled above medium, where this process may label it so.
        if me.integrity > MEDIUM {
            let tmp = tempfile::tempdir().unwrap();
            let place = local(tmp.path());
            let app = place.base.join(APP);
            create_private_dir(&app, Role::Shared).unwrap();
            create_private_dir(&app.join(KEY), Role::Level).unwrap();
            refused(&place, &app.join(KEY));
        }

        // A level folder labelled one level below this process's.
        let tmp = tempfile::tempdir().unwrap();
        let place = local(tmp.path());
        let app = place.base.join(APP);
        create_private_dir(&app, Role::Shared).unwrap();
        create_private_dir(&app.join(KEY), Role::Key).unwrap();
        create_dir_with_sd(&place.path(), &below).unwrap();
        refused(&place, &place.path());

        // So is a Builder::dir base, which belongs to a level too.
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("dir");
        create_dir_with_sd(&base, &below).unwrap();
        refused(&Place::dir(base.clone()), &base);
    }

    // Instance folders used to be made without a label, and every level
    // may still use one.
    #[test]
    fn an_instance_folder_with_no_label_counts_as_medium() {
        let tmp = tempfile::tempdir().unwrap();
        let place = local(tmp.path());
        let app = place.base.join(APP);
        create_private_dir(&app, Role::Shared).unwrap();
        create_private_dir(&app.join(KEY), Role::Shared).unwrap();
        assert!(open_folder(&place, true).unwrap().is_some());
    }

    #[test]
    fn a_junction_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .status()
            .unwrap();
        assert!(made.success());
        assert!(open_folder(&Place::dir(link), false).is_err());
    }

    #[test]
    fn more_instances_can_be_made_and_the_address_parses() {
        let tmp = tempfile::tempdir().unwrap();
        let folder = open_folder(&Place::dir(tmp.path().join("run")), true)
            .unwrap()
            .unwrap();
        let id = AppId::headless("test.windows");
        let mut listener = folder.listen(&id).unwrap();
        assert!(listener.published);
        let _first = listener.instance(false).unwrap();
        let _second = listener.instance(false).unwrap();
        let address = folder.address().unwrap().unwrap();
        assert_eq!(address.pipe, listener.name);
        // Held while published: nothing else can rewrite it.
        let file = tmp.path().join("run").join(ADDRESS_FILE);
        assert!(std::fs::write(&file, "x \\\\evil\\pipe\n").is_err());
        folder.unpublish();
        std::fs::write(&file, "x \\\\evil\\pipe\n").unwrap();
        assert!(folder.address().is_err());
    }

    // A launch can show windows outside session 0, on a visible window
    // station.
    #[test]
    fn who_can_show_windows() {
        let (yes, no) = (Some(true), Some(false));
        // (launch, session, visible station, can show windows), where
        // `None` is a fact unread or an answer unknown.
        let rows = [
            ("a desktop", Some(1), yes, yes),
            ("a second RDP session", Some(3), yes, yes),
            ("a service or an OpenSSH login", Some(0), no, no),
            ("session 0, on a visible station", Some(0), yes, no),
            ("a station of its own", Some(1), no, no),
            ("session 0, station unread", Some(0), None, no),
            ("hidden, session unread", None, no, no),
            ("visible, session unread", None, yes, None),
            ("a desktop, station unread", Some(1), None, None),
            ("nothing read", None, None, None),
        ];
        for (launch, session, visible, shows) in rows {
            let station = Station { session, visible };
            assert_eq!(shows_windows_from(&station), shows, "{launch}: {station:?}");
        }
    }

    // Both facts can be read. CI's runner, at either level, runs the tests
    // in session 2 on WinSta0, which is visible
    // (docs/design/0015-windows-measurements.md), so they can show windows
    // there. Over OpenSSH or in a service, they run in session 0 and can't.
    #[test]
    fn the_tests_session_and_window_station_are_read() {
        let station = station();
        let (Some(session), Some(_)) = (station.session, station.visible) else {
            panic!("{station:?}");
        };
        assert_eq!(can_show_windows(), Some(session != 0), "{station:?}");
    }

    // Whose folders a launch may keep its state in, by owner SID.
    #[test]
    fn the_state_owner_rule() {
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
        let me = me().unwrap();
        let table = [
            (me.sid_string.as_str(), true),
            ("S-1-5-18", true),
            // Administrators: an elevated process's own files.
            ("S-1-5-32-544", true),
            (TRUSTED_INSTALLER, true),
            // Another user, such as the account that administrator
            // protection elevates to.
            ("S-1-5-21-1-2-3-1001", false),
            ("S-1-5-32-545", false),
            ("S-1-1-0", false),
        ];
        for (sid_string, want) in table {
            let mut sid: PSID = null_mut();
            let s = wide(OsStr::new(sid_string));
            // SAFETY: a NUL-terminated string; `sid` receives a LocalAlloc'd
            // SID, freed by `Local`.
            assert_ne!(unsafe { ConvertStringSidToSidW(s.as_ptr(), &mut sid) }, 0);
            let _sid = Local(sid);
            assert_eq!(trusted(sid, me), want, "{sid_string}");
        }
    }

    // Where Local AppData may lead, for alice, whose profile is
    // C:\Users\alice unless a row says otherwise. A redirect outside the
    // profiles folder is allowed.
    #[test]
    fn local_appdata_in_another_users_profile_is_refused() {
        let (users, alice) = (r"C:\Users", r"C:\Users\alice");
        // The same folders verbatim, and with trailing separators.
        let (users_v, alice_v) = (r"\\?\C:\Users", r"\\?\C:\Users\alice");
        let (users_t, alice_t) = (r"C:\Users\", r"C:\Users\alice\");
        // (case, Local AppData's final path, profiles folder, this user's
        // profile, refused)
        #[rustfmt::skip]
        let rows = [
            ("her own", r"C:\Users\alice\AppData\Local", users, alice, false),
            ("bob's", r"C:\Users\bob\AppData\Local", users, alice, true),
            ("Public", r"C:\Users\Public\AppData\Local", users, alice, true),
            ("the profiles folder", r"C:\Users", users, alice, true),
            ("her own, other case", r"c:\USERS\Alice\appdata\local", users, alice, false),
            ("bob's, other case", r"c:\users\BOB\AppData\Local", users, alice, true),
            ("JÜRGEN, for jürgen", r"C:\Users\JÜRGEN\AppData", users, r"C:\Users\jürgen", false),
            ("her own, verbatim", r"\\?\C:\Users\alice\AppData\Local", users, alice, false),
            ("bob's, verbatim", r"\\?\C:\Users\bob\AppData\Local", users, alice, true),
            ("verbatim folders", r"C:\Users\alice\AppData\Local", users_v, alice_v, false),
            ("bob's, verbatim folders", r"C:\Users\bob\AppData\Local", users_v, alice_v, true),
            ("her own, trailing", r"C:\Users\alice\AppData\Local\", users_t, alice_t, false),
            ("bob's, trailing", r"C:\Users\bob\", users_t, alice_t, true),
            ("alice's, for al", r"C:\Users\alice\AppData\Local", users, r"C:\Users\al", true),
            ("beside the profiles folder", r"C:\Users2\bob\AppData\Local", users, alice, false),
            ("on another drive", r"D:\Data\alice\Local", users, alice, false),
            ("on a share", r"\\server\share\alice\Local", users, alice, false),
            ("her own, elsewhere", r"D:\Profiles\alice\Local", users, r"D:\Profiles\alice", false),
            ("bob's, hers elsewhere", r"C:\Users\bob", users, r"D:\Profiles\alice", true),
        ];
        for (case, path, profiles, mine, refused) in rows {
            let got = in_another_profile(Path::new(path), Path::new(profiles), Path::new(mine));
            assert_eq!(got, refused, "{case}: {path}");
        }
    }

    // A Local AppData that is the profiles folder itself is refused when it
    // is opened. C:\Users is SYSTEM's and read-only to others, so it is safe
    // and only the profile check refuses it. Nothing is created, so the
    // runner's C:\Users is left as it is even if the check fails to refuse.
    #[test]
    fn local_appdata_in_the_profiles_folder_is_refused_when_opened() {
        let (profiles, _) = profile_folders().unwrap();
        let place = Place {
            base: profiles.clone(),
            kind: Base::Known,
            subs: vec![APP.into(), KEY.into()],
            level: Some(level_folder(me().unwrap().integrity).into()),
        };
        match open_folder(&place, false) {
            Err(Reason::RuntimeDir { path, source }) => {
                assert_eq!(path, profiles);
                assert!(source.to_string().contains("profiles folder"), "{source}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn this_users_folders_are_not_foreign() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!is_foreign(tmp.path()).unwrap());
        let local = default_place(&AppId::headless("test.windows"))
            .unwrap()
            .base;
        assert!(!is_foreign(&local).unwrap());
        let err = is_foreign(&tmp.path().join("missing").join("app")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn final_paths_drop_the_verbatim_prefix_of_drives_and_shares() {
        let table = [
            (r"\\?\C:\Users\me", r"C:\Users\me"),
            (r"\\?\C:\", r"C:\"),
            (r"\\?\UNC\server\share\me", r"\\server\share\me"),
            (r"\\?\Volume{0}\me", r"\\?\Volume{0}\me"),
            (r"\\?\GLOBALROOT\Device\X\me", r"\\?\GLOBALROOT\Device\X\me"),
        ];
        for (verbatim, plain) in table {
            let path = plain_path(OsStr::new(verbatim).encode_wide().collect());
            assert_eq!(path, Path::new(plain), "{verbatim}");
        }
    }

    // The runner's temporary folder is named with 8.3 names, which the final
    // path spells out.
    #[test]
    fn a_final_path_is_canonicalize_without_the_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let verbatim = std::fs::canonicalize(tmp.path()).unwrap();
        let want = verbatim.to_str().unwrap().strip_prefix(r"\\?\").unwrap();
        assert_eq!(final_path(tmp.path()).unwrap(), Path::new(want));
    }

    #[test]
    fn a_junction_is_resolved_to_its_target() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .status()
            .unwrap();
        assert!(made.success());
        assert_eq!(final_path(&link).unwrap(), final_path(&real).unwrap());
    }

    /// A `SUBST` letter, removed on drop.
    struct Subst(char);

    impl Drop for Subst {
        fn drop(&mut self) {
            let _ = std::process::Command::new("subst")
                .arg(format!("{}:", self.0))
                .arg("/D")
                .status();
        }
    }

    // SUBST needs no elevation. A mapping is per logon session; the final
    // path is what every session sees. CI's medium token shares the
    // elevated runner's logon session and couldn't map a letter there, so
    // the test skips where no letter maps; the high run covers it.
    #[test]
    fn a_subst_letter_becomes_the_real_drive() {
        let tmp = tempfile::tempdir().unwrap();
        let mut refused = String::new();
        let subst = ('Q'..='Z')
            .filter(|l| !Path::new(&format!(r"{l}:\")).exists())
            .find_map(|l| {
                let out = std::process::Command::new("subst")
                    .arg(format!("{l}:"))
                    .arg(tmp.path())
                    .output()
                    .unwrap();
                if !out.status.success() {
                    refused = String::from_utf8_lossy(&out.stdout).trim().to_owned()
                        + String::from_utf8_lossy(&out.stderr).trim();
                }
                out.status.success().then_some(Subst(l))
            });
        let Some(subst) = subst else {
            eprintln!("skipped: subst mapped no letter from Q to Z: {refused}");
            return;
        };
        let root = PathBuf::from(format!(r"{}:\", subst.0));
        let real = final_path(tmp.path()).unwrap();
        assert_eq!(final_path(&root).unwrap(), real);
        assert_eq!(
            crate::state::canonical(&root.join("missing")),
            real.join("missing")
        );
    }
}
