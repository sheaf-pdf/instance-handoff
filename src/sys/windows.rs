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
    TOKEN_QUERY, TOKEN_USER, TokenIntegrityLevel, TokenUser, WinBuiltinAdministratorsSid,
    WinCreatorOwnerRightsSid, WinCreatorOwnerSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
    FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_READ_EA, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES,
    FILE_WRITE_EA, GetFileInformationByHandle, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    LockFileEx, PIPE_ACCESS_DUPLEX, READ_CONTROL, ReadFile, SECURITY_IDENTIFICATION, SYNCHRONIZE,
    WRITE_DAC, WRITE_OWNER, WriteFile,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    WaitNamedPipeW,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, SECURITY_MANDATORY_MEDIUM_RID,
    SYSTEM_MANDATORY_LABEL_ACE_TYPE,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetCurrentThread, INFINITE, OpenProcessToken, OpenThreadToken,
    SetEvent, WaitForMultipleObjects, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{FOLDERID_LocalAppData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
use windows_sys::Win32::UI::WindowsAndMessaging::AllowSetForegroundWindow;

use crate::naming::level_folder;
use crate::server::{Core, Session};
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
    subs: Vec<OsString>,
    /// How many of `subs` every integrity level shares. The folders below
    /// them belong to this process's level, and so does a created base.
    shared: usize,
}

impl Place {
    pub(crate) fn dir(dir: PathBuf) -> Place {
        Place {
            base: dir,
            kind: Base::Create,
            subs: Vec::new(),
            shared: 0,
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
        subs: vec![id.as_str().into(), level_folder(level).into()],
        shared: 1,
    })
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

/// A real folder, owned by this user (or SYSTEM, Administrators,
/// TrustedInstaller), that nobody else may change. A folder this crate
/// makes (`private`) must also be one nobody else may read, and one that
/// belongs to an integrity level (`level`) must be labelled at this
/// process's level (no label counts as medium).
fn check_dir(dir: &File, private: bool, level: bool) -> io::Result<()> {
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
    if level && unsafe { label(sacl) }.unwrap_or(MEDIUM) != me.integrity {
        return Err(denied("made for another integrity level"));
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
        if private && ace.mask & READS != 0 {
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
/// its parent would hand down. A `level` folder is also labelled at this
/// process's integrity level, and so is everything made in it, so that
/// lower levels can't open any of it. An existing folder is left as it is.
fn create_private_dir(path: &Path, level: bool) -> io::Result<()> {
    let me = me()?;
    let mut sddl = format!("D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY)", me.sid_string);
    if level {
        sddl += &format!("S:(ML;OICI;NWNR;;;S-1-16-{})", me.integrity);
    }
    let sd = SecurityDescriptor::from_sddl(&sddl)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (sd.0).0,
        bInheritHandle: 0,
    };
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

pub(crate) fn open_folder(place: &Place, create: bool) -> Result<Option<Folder>, Reason> {
    let mut path = place.base.clone();
    let missing = |e: &io::Error| e.kind() == io::ErrorKind::NotFound && !create;
    let made = place.kind == Base::Create;
    if made && create {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Reason::runtime_dir(&path, e))?;
        }
        create_private_dir(&path, true).map_err(|e| Reason::runtime_dir(&path, e))?;
    }
    let mut dir = match open_dir(&path).and_then(|d| check_dir(&d, made, made).map(|()| d)) {
        Ok(dir) => dir,
        Err(e) if missing(&e) => return Ok(None),
        Err(e) => return Err(Reason::runtime_dir(&path, e)),
    };
    for (i, sub) in place.subs.iter().enumerate() {
        let level = i >= place.shared;
        path.push(sub);
        if create {
            create_private_dir(&path, level).map_err(|e| Reason::runtime_dir(&path, e))?;
        }
        dir = match open_dir(&path).and_then(|d| check_dir(&d, true, level).map(|()| d)) {
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

/// The held lock: `LockFileEx` on the first byte of the open file, released
/// when the handle closes. The file can't be deleted while it is open.
#[derive(Debug)]
pub(crate) struct Lock(#[allow(dead_code)] File);

fn try_lock(file: &File) -> io::Result<bool> {
    // SAFETY: plain data; LockFileEx reads the offset from it.
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    // SAFETY: a synchronous handle; with FAIL_IMMEDIATELY it never waits.
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
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

    fn open_lock(&self, create: bool) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(self.lock_path())
    }

    pub(crate) fn lock(&self) -> io::Result<Option<Lock>> {
        let file = self.open_lock(true)?;
        Ok(try_lock(&file)?.then_some(Lock(file)))
    }

    pub(crate) fn lock_held(&self) -> io::Result<bool> {
        match self.open_lock(false) {
            Ok(file) => try_lock(&file).map(|got| !got),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
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
        let id = AppId::parse(id).map_err(|_| bad())?;
        if secret.len() != 32
            || !secret
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(bad());
        }
        Ok(Some(Address {
            pipe: pipe_name(&id, secret),
        }))
    }

    /// Creates the pipe, then publishes its name. A failed publish (another
    /// program holding the file) is retried by the owner's upkeep.
    pub(crate) fn listen(&self, app_id: &AppId) -> io::Result<PipeListener> {
        let secret = random_hex()?;
        let name = pipe_name(app_id, &secret);
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

fn pipe_name(id: &AppId, secret: &str) -> OsString {
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

/// The pipe's security: owned by this user, open to this user alone, and
/// labelled at this process's integrity level.
struct SecurityDescriptor(Local);

// SAFETY: an immutable block, only read by CreateNamedPipeW.
unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl std::fmt::Debug for SecurityDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecurityDescriptor")
    }
}

impl SecurityDescriptor {
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
}

fn create_instance(name: &OsStr, sd: &SecurityDescriptor, first: bool) -> io::Result<OwnedHandle> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (sd.0).0,
        bInheritHandle: 0,
    };
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
        let name = pipe_name(app_id, &secret);
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

/// The folder and the lock, as the owner holds them.
#[derive(Debug)]
pub(crate) struct Held {
    pub(crate) folder: Option<Folder>,
    pub(crate) lock: Option<Lock>,
}

impl Held {
    #[cfg(test)]
    pub(crate) fn detached() -> Held {
        Held {
            folder: None,
            lock: None,
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
    pub(crate) fn new(folder: Folder, lock: Lock, app_id: &AppId) -> Claimed {
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

    pub(crate) fn abandon(self) {
        std::mem::forget(self.lock);
    }

    pub(crate) fn into_parts(self) -> (Held, Option<PipeListener>, Option<io::Error>) {
        let held = Held {
            folder: Some(self.folder),
            lock: Some(self.lock),
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
        session: Session::new(core, pid, now),
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

    #[test]
    fn the_default_folder_passes_the_check() {
        let place = default_place(&AppId::new("test.windows")).unwrap();
        let base = open_dir(&place.base).unwrap();
        check_dir(&base, false, false).unwrap();
        assert_eq!(place.subs[1], *level_folder(me().unwrap().integrity));
    }

    #[test]
    fn folders_this_crate_makes_are_private_and_labelled() {
        let tmp = tempfile::tempdir().unwrap();
        let mut place = Place::dir(tmp.path().join("run"));
        place.push("scope");
        let folder = open_folder(&place, true).unwrap().unwrap();
        check_dir(&open_dir(folder.path()).unwrap(), true, true).unwrap();
        check_dir(&open_dir(&tmp.path().join("run")).unwrap(), true, true).unwrap();
    }

    #[test]
    fn a_folder_made_for_another_integrity_level_is_refused() {
        // Labelled one level below this process's, which it may do.
        let me = me().unwrap();
        let sd = SecurityDescriptor::from_sddl(&format!(
            "D:P(A;OICI;FA;;;{})S:(ML;OICI;NW;;;S-1-16-{})",
            me.sid_string,
            me.integrity - 0x1000
        ))
        .unwrap();
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: (sd.0).0,
            bInheritHandle: 0,
        };
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("run");
        let wide_path = wide(path.as_os_str());
        // SAFETY: a NUL-terminated path and valid security attributes.
        assert_ne!(unsafe { CreateDirectoryW(wide_path.as_ptr(), &sa) }, 0);
        assert!(matches!(
            open_folder(&Place::dir(path), true),
            Err(Reason::RuntimeDir { .. })
        ));
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
        let id = AppId::new("test.windows");
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
}
