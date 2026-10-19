//! Launches and locks across Windows integrity levels.
//!
//! These need a process at high integrity, which can start children at
//! medium: GitHub's Windows runner is one (an administrator with UAC off).
//! The children get the Basic User token that `runas /trustlevel:0x20000`
//! uses: the same user, with Administrators deny-only, no admin privileges
//! and medium integrity, as an unelevated launch has. Real UAC (a split
//! token, consent, Windows `sudo`) needs a machine with UAC on. Below high
//! integrity, each test returns at once.
//!
//! A child is this binary run for one of the `child_*` tests, which do
//! nothing unless [`ROLE`] names them. It reports on stdout, one line each.

#![cfg(windows)]

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use instance_handoff::{AppId, Args, Builder, Claim, Reason, Started};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION, GENERIC_READ, GENERIC_WRITE, HANDLE,
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LocalFree, SetHandleInformation,
};
use windows_sys::Win32::Security::AppLocker::{
    SAFER_LEVEL_OPEN, SAFER_LEVELID_NORMALUSER, SAFER_SCOPEID_USER, SaferCloseLevel,
    SaferComputeTokenFromLevel, SaferCreateLevel,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, GetLengthSid, GetSidSubAuthority,
    GetSidSubAuthorityCount, GetTokenInformation, LABEL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE,
    SID_AND_ATTRIBUTES, SetTokenInformation, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL,
    TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER, TokenIntegrityLevel, TokenOwner, TokenUser,
    WinBuiltinAdministratorsSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_SHARE_READ, FILE_SHARE_WRITE, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    LockFileEx, READ_CONTROL,
};
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::SystemServices::SE_GROUP_INTEGRITY;
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, GetCurrentProcess,
    OpenProcessToken, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW,
    TerminateProcess, WaitForSingleObject,
};

const APP: AppId = AppId::new("test.levels");
/// Which `child_*` test a child runs as.
const ROLE: &str = "INSTANCE_HANDOFF_LEVELS_ROLE";
/// The app id a child launches as.
const ID: &str = "INSTANCE_HANDOFF_LEVELS_ID";
/// The folder a child is given: `Builder::dir`, or where the probe works.
const DIR: &str = "INSTANCE_HANDOFF_LEVELS_DIR";

const MEDIUM: u32 = 0x2000;
const HIGH: u32 = 0x3000;
/// The byte a proposed state lock would hold, after 0015.
const GUARD: u64 = 1 << 31;

/// Files high makes for medium to try, and the label each gets. The last is
/// owned by Administrators, as an elevated process's files are with UAC on;
/// CI's runner, the built-in Administrator, makes them owned by the user.
const FILES: [(&str, Option<&str>); 5] = [
    ("no-label", None),
    ("medium-label", Some("S:(ML;;NW;;;ME)")),
    ("high-label", Some("S:(ML;;NW;;;HI)")),
    ("high-label-nr", Some("S:(ML;;NWNR;;;HI)")),
    ("administrators-owned", Some("O:BAS:(ML;;NW;;;ME)")),
];
/// Folders high makes for medium to create a file in.
const FOLDERS: [(&str, Option<&str>); 2] = [
    ("folder-no-label", None),
    ("folder-high-label-nr", Some("S:(ML;;NWNR;;;HI)")),
];

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

#[test]
fn a_medium_launch_never_hands_off_to_a_high_owner() {
    if !elevated() {
        return;
    }
    let id = app("high-owner");
    let claim = claim(Builder::new(id.clone()).start(&Args::default()));
    assert!(
        claim.dir().ends_with("run-high"),
        "{}",
        claim.dir().display()
    );
    let base = claim.dir().parent().unwrap().to_path_buf();
    let (tx, rx) = mpsc::channel();
    let owner = claim.serve(move |r| tx.send(r).is_ok());

    let mut child = medium("child_launch", &[(ID, OsStr::new(id.as_str()))]);
    let outcome = child.expect("outcome ");
    assert!(
        outcome.starts_with("owner ") && outcome.ends_with(r"\run"),
        "{outcome}"
    );
    child.finish();
    assert!(
        rx.try_recv().is_err(),
        "the high owner took a medium launch"
    );
    owner.release();
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn a_high_launch_never_hands_off_to_a_medium_owner() {
    if !elevated() {
        return;
    }
    let id = app("medium-owner");
    let mut child = medium("child_owner", &[(ID, OsStr::new(id.as_str()))]);
    let dir = child.expect("owner ");
    assert!(dir.ends_with(r"\run"), "{dir}");

    match Builder::new(id.clone()).start(&Args::new(["from-high"])) {
        Started::Owner(claim) => {
            assert!(
                claim.dir().ends_with("run-high"),
                "{}",
                claim.dir().display()
            );
            claim.release();
        }
        other => panic!("{}", describe(&other)),
    }
    let reason = Builder::new(id)
        .hand_off(&Args::new(["from-high"]))
        .unwrap_err();
    assert!(matches!(reason, Reason::NoOwner { .. }), "{reason}");

    let rest = child.finish();
    assert!(!rest.iter().any(|l| l.starts_with("took ")), "{rest:?}");
    let _ = std::fs::remove_dir_all(Path::new(&dir).parent().unwrap());
}

#[test]
fn a_folder_made_at_one_level_is_refused_at_the_other() {
    if !elevated() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();

    let high = tmp.path().join("high");
    let claim = claim(Builder::new(APP).dir(&high).start(&Args::default()));
    let (tx, rx) = mpsc::channel();
    let owner = claim.serve(move |r| tx.send(r).is_ok());
    let mut child = medium(
        "child_launch",
        &[(ID, OsStr::new(APP.as_str())), (DIR, high.as_os_str())],
    );
    let outcome = child.expect("outcome ");
    assert!(outcome.starts_with("alone RuntimeDir"), "{outcome}");
    child.finish();
    assert!(
        rx.try_recv().is_err(),
        "the high owner took a medium launch"
    );
    owner.release();

    let made_at_medium = tmp.path().join("medium");
    let mut child = medium(
        "child_owner",
        &[
            (ID, OsStr::new(APP.as_str())),
            (DIR, made_at_medium.as_os_str()),
        ],
    );
    child.expect("owner ");
    match Builder::new(APP)
        .dir(&made_at_medium)
        .start(&Args::new(["from-high"]))
    {
        Started::Alone(Reason::RuntimeDir { .. }) => {}
        other => panic!("{}", describe(&other)),
    }
    let rest = child.finish();
    assert!(!rest.iter().any(|l| l.starts_with("took ")), "{rest:?}");
}

/// What a medium process may do with files, folders and locks a high one
/// made, and the reverse: the facts a lock shared across levels (0015)
/// would rest on.
#[test]
#[ignore = "a probe that reports rather than checks: `just levels` runs it"]
fn what_each_level_may_do_with_the_others_files() {
    if !elevated() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let mut facts = vec![("high: token".to_owned(), token_facts())];

    for (name, sddl) in FILES {
        let made = create(&dir.join(name), sddl, false).map(drop);
        facts.push((
            format!("{name}: made by high"),
            made_as(&dir.join(name), &made),
        ));
    }
    for (name, sddl) in FOLDERS {
        let made = create(&dir.join(name), sddl, true).map(drop);
        facts.push((
            format!("{name}: made by high"),
            made_as(&dir.join(name), &made),
        ));
    }
    // A lock file as 0015 proposes: labelled medium, with high holding the
    // state byte and its own level's byte.
    let guard = create(&dir.join("guard"), Some("S:(ML;;NW;;;ME)"), false)
        .unwrap()
        .unwrap();
    lock(&guard, GUARD, true).unwrap();
    lock(&guard, u64::from(HIGH), true).unwrap();
    facts.push(("guard: made by high".into(), security(&dir.join("guard"))));

    let mut child = medium("child_probe", &[(DIR, dir.as_os_str())]);
    let lines = child.finish();
    if !lines.iter().any(|l| l == "done") {
        panic!("the medium probe didn't finish:\n{}", lines.join("\n"));
    }
    facts.extend(lines.iter().filter_map(|l| {
        let (name, value) = l.strip_prefix("fact ")?.split_once(" = ")?;
        Some((name.to_owned(), value.to_owned()))
    }));

    // The reverse: medium holds a lock file it made, and high tries it.
    let mut holder = medium("child_holder", &[(DIR, dir.as_os_str())]);
    holder.expect("ready");
    let held = dir.join("made-by-medium");
    facts.push(("made-by-medium: made by medium".into(), security(&held)));
    let file = OpenOptions::new().read(true).write(true).open(&held);
    facts.push(("made-by-medium: high opens to write".into(), result(&file)));
    if let Ok(file) = &file {
        let probes = [
            ("exclusive lock on the state byte", GUARD, true),
            ("shared lock on medium's byte", u64::from(MEDIUM), false),
            ("shared lock on high's byte", u64::from(HIGH), false),
        ];
        for (what, offset, exclusive) in probes {
            let got = result(&lock(file, offset, exclusive));
            facts.push((format!("made-by-medium: high's {what}"), got));
        }
    }
    holder.finish();

    let width = facts.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    println!("\nWhat each integrity level may do with the other's files and locks:\n");
    for (name, value) in &facts {
        println!("  {name:<width$}  {value}");
    }
    println!();
}

// ---------------------------------------------------------------------------
// The children
// ---------------------------------------------------------------------------

/// Becomes the owner, reports each request it takes, and exits when its
/// stdin closes.
#[test]
fn child_owner() {
    if !is_role("child_owner") {
        return;
    }
    let claim = match child_builder().start(&Args::default()) {
        Started::Owner(claim) => claim,
        other => {
            println!("outcome {}", describe(&other));
            return;
        }
    };
    println!("owner {}", claim.dir().display());
    let _owner = claim.serve(|request| {
        println!("took {:?}", request.payload());
        true
    });
    let _ = io::stdin().read_line(&mut String::new());
}

/// Launches once and reports how.
#[test]
fn child_launch() {
    if !is_role("child_launch") {
        return;
    }
    let started = child_builder().start(&Args::new(["from-medium"]));
    println!("outcome {}", describe(&started));
    if let Started::Owner(claim) = started {
        claim.release();
    }
}

/// Tries what high made in the probe's folder.
#[test]
fn child_probe() {
    if !is_role("child_probe") {
        return;
    }
    let dir = PathBuf::from(std::env::var_os(DIR).unwrap());
    fact("medium: token", token_facts());
    for name in FILES.map(|(name, _)| name).into_iter().chain(["guard"]) {
        let path = dir.join(name);
        let read = OpenOptions::new().read(true).open(&path);
        let write = OpenOptions::new().read(true).write(true).open(&path);
        fact(&format!("{name}: medium opens to read"), result(&read));
        fact(&format!("{name}: medium opens to write"), result(&write));
        let Ok(file) = write.as_ref().or(read.as_ref()) else {
            continue;
        };
        if name == "guard" {
            let probes = [
                ("exclusive lock on the state byte", GUARD, true),
                ("shared lock on high's byte", u64::from(HIGH), false),
                ("shared lock on medium's byte", u64::from(MEDIUM), false),
            ];
            for (what, offset, exclusive) in probes {
                fact(
                    &format!("guard: medium's {what}"),
                    result(&lock(file, offset, exclusive)),
                );
            }
        } else {
            fact(
                &format!("{name}: medium's exclusive lock"),
                result(&lock(file, 0, true)),
            );
        }
    }
    for (name, _) in FOLDERS {
        let made = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(name).join("from-medium"));
        fact(
            &format!("{name}: medium creates a file in it"),
            result(&made),
        );
    }
    println!("done");
}

/// Makes a lock file, holds the state byte and medium's byte, and waits
/// for stdin to close.
#[test]
fn child_holder() {
    if !is_role("child_holder") {
        return;
    }
    let dir = PathBuf::from(std::env::var_os(DIR).unwrap());
    let file = create(&dir.join("made-by-medium"), None, false)
        .unwrap()
        .unwrap();
    lock(&file, GUARD, true).unwrap();
    lock(&file, u64::from(MEDIUM), true).unwrap();
    println!("ready");
    let _ = io::stdin().read_line(&mut String::new());
}

fn is_role(name: &str) -> bool {
    std::env::var_os(ROLE).is_some_and(|r| r == name)
}

fn child_builder() -> Builder {
    let id: AppId = std::env::var(ID).unwrap().parse().unwrap();
    match std::env::var_os(DIR) {
        Some(dir) => Builder::new(id).dir(PathBuf::from(dir)),
        None => Builder::new(id),
    }
}

fn fact(name: &str, value: impl std::fmt::Display) {
    println!("fact {name} = {value}");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A fresh app id, so tests in the real local AppData don't meet.
fn app(name: &str) -> AppId {
    format!("test.levels.{}.{name}", std::process::id())
        .parse()
        .unwrap()
}

fn claim(started: Started<Args>) -> Claim<Args> {
    match started {
        Started::Owner(claim) => claim,
        other => panic!("{}", describe(&other)),
    }
}

fn describe(started: &Started<Args>) -> String {
    match started {
        Started::Owner(claim) => format!("owner {}", claim.dir().display()),
        Started::HandedOff(info) => format!("handed off to {info:?}"),
        Started::Alone(reason) => format!("alone {reason:?}"),
    }
}

fn result<T>(r: &io::Result<T>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => "access denied".into(),
        Err(e) if e.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) => "lock violation".into(),
        Err(e) => e.to_string(),
    }
}

/// `path`'s owner and label, or why it couldn't be made.
fn made_as(path: &Path, made: &io::Result<()>) -> String {
    match made {
        Ok(()) => security(path),
        Err(_) => format!("not made: {}", result(made)),
    }
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

/// A NUL-terminated string from `LocalAlloc`, which this frees.
///
/// # Safety
///
/// `p` is such a string.
unsafe fn take_wide(p: *mut u16) -> String {
    // SAFETY: NUL-terminated, per the contract.
    let len = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
    let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) });
    unsafe { LocalFree(p.cast()) };
    s
}

/// Whether this process can start medium children: it must be above them.
fn elevated() -> bool {
    let level = token_level(own_token().as_raw_handle());
    if level < HIGH {
        eprintln!("skipped: starting medium children needs high integrity, not {level:#x}");
    }
    level >= HIGH
}

fn own_token() -> OwnedHandle {
    let mut token = null_mut();
    // SAFETY: the current-process pseudo handle; `token` receives a handle.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    assert_ne!(ok, 0, "OpenProcessToken: {}", io::Error::last_os_error());
    unsafe { OwnedHandle::from_raw_handle(token) }
}

/// A token's information of one class, in a buffer aligned for it.
fn token_info(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Vec<u64> {
    let mut len = 0;
    // SAFETY: a size query.
    unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut len) };
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` holds `len` bytes.
    let ok = unsafe { GetTokenInformation(token, class, buf.as_mut_ptr().cast(), len, &mut len) };
    assert_ne!(ok, 0, "GetTokenInformation: {}", io::Error::last_os_error());
    buf
}

fn token_level(token: HANDLE) -> u32 {
    let label = token_info(token, TokenIntegrityLevel);
    // SAFETY: a TOKEN_MANDATORY_LABEL whose SID points into the buffer; its
    // last sub-authority is the level.
    unsafe {
        let sid = (*(label.as_ptr() as *const TOKEN_MANDATORY_LABEL))
            .Label
            .Sid;
        let n = *GetSidSubAuthorityCount(sid);
        *GetSidSubAuthority(sid, u32::from(n - 1))
    }
}

fn sid_string(sid: PSID) -> String {
    let mut text = null_mut();
    // SAFETY: a valid SID; `text` receives a LocalAlloc'd string.
    assert_ne!(unsafe { ConvertSidToStringSidW(sid, &mut text) }, 0);
    unsafe { take_wide(text) }
}

/// This process's user, as a SID string.
fn user() -> String {
    let user = token_info(own_token().as_raw_handle(), TokenUser);
    // SAFETY: a TOKEN_USER whose SID points into the buffer.
    sid_string(unsafe { (*(user.as_ptr() as *const TOKEN_USER)).User.Sid })
}

/// Names the SIDs these reports show: this user and Administrators.
fn names(sddl: &str) -> String {
    sddl.replace(&user(), "<user>")
        .replace("S-1-5-32-544", "Administrators")
}

/// This process's level, who owns what it creates, and whether its
/// Administrators group is enabled.
fn token_facts() -> String {
    let token = own_token();
    let level = token_level(token.as_raw_handle());
    let owner = token_info(token.as_raw_handle(), TokenOwner);
    // SAFETY: a TOKEN_OWNER whose SID points into the buffer.
    let owner = sid_string(unsafe { (*(owner.as_ptr() as *const TOKEN_OWNER)).Owner });
    let mut admins = [0u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(4)];
    let mut len = std::mem::size_of_val(&admins) as u32;
    // SAFETY: `admins` holds `len` bytes, aligned for a SID.
    let ok = unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            null_mut(),
            admins.as_mut_ptr().cast(),
            &mut len,
        )
    };
    assert_ne!(ok, 0, "CreateWellKnownSid: {}", io::Error::last_os_error());
    let mut member = 0;
    // SAFETY: a null token checks this process's own.
    let ok = unsafe { CheckTokenMembership(null_mut(), admins.as_mut_ptr().cast(), &mut member) };
    assert_ne!(
        ok,
        0,
        "CheckTokenMembership: {}",
        io::Error::last_os_error()
    );
    format!(
        "level {level:#x}; what it makes is owned by {}; Administrators {}",
        names(&owner),
        if member != 0 {
            "enabled"
        } else {
            "not enabled"
        }
    )
}

/// `path`'s owner and label, as SDDL.
fn security(path: &Path) -> String {
    let file = match OpenOptions::new()
        .access_mode(READ_CONTROL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
    {
        Ok(file) => file,
        Err(e) => return format!("can't read its security: {}", result(&Err::<(), _>(e))),
    };
    let info = OWNER_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
    let mut sd = null_mut();
    // SAFETY: an open handle; `sd` receives a LocalAlloc'd descriptor.
    let err = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            info,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        )
    };
    if err != 0 {
        return format!(
            "GetSecurityInfo: {}",
            io::Error::from_raw_os_error(err as i32)
        );
    }
    let mut text = null_mut();
    // SAFETY: the descriptor from above; `text` receives a LocalAlloc'd string.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            info,
            &mut text,
            null_mut(),
        )
    };
    let err = io::Error::last_os_error();
    unsafe { LocalFree(sd) };
    if ok == 0 {
        return format!("ConvertSecurityDescriptorToStringSecurityDescriptorW: {err}");
    }
    let sddl = unsafe { take_wide(text) };
    let sddl = if sddl.contains("S:") {
        sddl
    } else {
        format!("{sddl} (no label: medium)")
    };
    names(&sddl)
}

/// Creates the file or folder `path` with the owner and label in `sddl`
/// (such as `S:(ML;;NW;;;ME)`), or the defaults, and the access list
/// inherited. A file comes back open to read and write, shared.
fn create(path: &Path, sddl: Option<&str>, folder: bool) -> io::Result<Option<File>> {
    let mut sd = null_mut();
    if let Some(sddl) = sddl {
        let sddl = wide(OsStr::new(sddl));
        // SAFETY: a NUL-terminated string; `sd` receives a LocalAlloc'd block.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let name = wide(path.as_os_str());
    let made = if folder {
        // SAFETY: a NUL-terminated path and valid attributes.
        if unsafe { CreateDirectoryW(name.as_ptr(), &sa) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(None)
        }
    } else {
        // SAFETY: as above.
        let h = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &sa,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(Some(unsafe { File::from_raw_handle(h) }))
        }
    };
    if !sd.is_null() {
        unsafe { LocalFree(sd) };
    }
    made
}

/// One byte at `offset`, without waiting.
fn lock(file: &File, offset: u64, exclusive: bool) -> io::Result<()> {
    // SAFETY: plain data.
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.Anonymous.Anonymous.Offset = offset as u32;
    ov.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
    let mut flags = LOCKFILE_FAIL_IMMEDIATELY;
    if exclusive {
        flags |= LOCKFILE_EXCLUSIVE_LOCK;
    }
    // SAFETY: an open, synchronous handle; the call completes before it
    // returns, so `ov` outlives it.
    if unsafe { LockFileEx(file.as_raw_handle(), flags, 0, 1, 0, &mut ov) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Starting a child at medium
// ---------------------------------------------------------------------------

/// Spawns one child at a time: a child's ends of its pipes are inheritable
/// until it has started, and a child started meanwhile would inherit them
/// too, holding the pipes open.
static SPAWN: Mutex<()> = Mutex::new(());

struct Child {
    process: OwnedHandle,
    stdin: Option<File>,
    lines: Receiver<String>,
}

impl Child {
    /// The rest of the first line that starts with `prefix`.
    fn expect(&self, prefix: &str) -> String {
        let mut seen = Vec::new();
        while let Ok(line) = self.lines.recv_timeout(Duration::from_secs(30)) {
            if let Some(rest) = line.strip_prefix(prefix) {
                return rest.to_owned();
            }
            seen.push(line);
        }
        panic!("no `{prefix}` line from the child:\n{}", seen.join("\n"));
    }

    /// Closes its stdin, waits for it to exit, and returns the lines it
    /// printed that nobody read yet.
    fn finish(&mut self) -> Vec<String> {
        drop(self.stdin.take());
        // SAFETY: a process handle this value owns.
        unsafe { WaitForSingleObject(self.process.as_raw_handle(), 30_000) };
        // The channel closes once the reader sees the pipe close.
        std::iter::from_fn(|| self.lines.recv_timeout(Duration::from_secs(5)).ok()).collect()
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        // SAFETY: a process handle this value owns. Fails harmlessly once
        // the child has exited.
        unsafe { TerminateProcess(self.process.as_raw_handle(), 1) };
    }
}

/// Runs this test binary as the child `role` at medium, with `env` added
/// to this process's environment. Panics unless the child's token really
/// is at medium before it starts.
fn medium(role: &str, env: &[(&str, &OsStr)]) -> Child {
    let token = medium_token();
    let mut cmd = OsString::from("\"");
    cmd.push(std::env::current_exe().unwrap());
    cmd.push(format!("\" --exact {role} --nocapture --test-threads=1 -q"));
    let mut cmd = wide(&cmd);
    let env = env_block(role, env);

    let spawning = SPAWN.lock().unwrap_or_else(|e| e.into_inner());
    let (out_read, out_write) = pipe();
    let (in_read, in_write) = pipe();
    no_inherit(&out_read);
    no_inherit(&in_write);
    // SAFETY: plain data.
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in_read.as_raw_handle();
    si.hStdOutput = out_write.as_raw_handle();
    si.hStdError = out_write.as_raw_handle();
    // SAFETY: plain data, filled in by the call.
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: a valid token, a writable NUL-terminated command line, a
    // double-NUL-terminated environment block, and valid structures.
    let ok = unsafe {
        CreateProcessAsUserW(
            token.as_raw_handle(),
            null(),
            cmd.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            env.as_ptr().cast(),
            null(),
            &si,
            &mut pi,
        )
    };
    let err = io::Error::last_os_error();
    drop((in_read, out_write));
    drop(spawning);
    assert_ne!(ok, 0, "CreateProcessAsUserW: {err}");

    // SAFETY: handles the call returned, now owned here.
    let process = unsafe { OwnedHandle::from_raw_handle(pi.hProcess) };
    let thread = unsafe { OwnedHandle::from_raw_handle(pi.hThread) };
    let child = Child {
        process,
        stdin: Some(File::from(in_write)),
        lines: reader(File::from(out_read)),
    };
    let mut child_token = null_mut();
    // SAFETY: the child's process handle; `child_token` receives a handle.
    let ok =
        unsafe { OpenProcessToken(child.process.as_raw_handle(), TOKEN_QUERY, &mut child_token) };
    assert_ne!(ok, 0, "OpenProcessToken: {}", io::Error::last_os_error());
    let child_token = unsafe { OwnedHandle::from_raw_handle(child_token) };
    let level = token_level(child_token.as_raw_handle());
    assert_eq!(
        level, MEDIUM,
        "the child would run at {level:#x}, not medium"
    );
    // SAFETY: the child's main thread, suspended.
    unsafe { ResumeThread(thread.as_raw_handle()) };
    child
}

/// This user's Basic User token, at medium integrity.
fn medium_token() -> OwnedHandle {
    let mut level = null_mut();
    // SAFETY: `level` receives a handle, closed below.
    let ok = unsafe {
        SaferCreateLevel(
            SAFER_SCOPEID_USER,
            SAFER_LEVELID_NORMALUSER,
            SAFER_LEVEL_OPEN,
            &mut level,
            null(),
        )
    };
    assert_ne!(ok, 0, "SaferCreateLevel: {}", io::Error::last_os_error());
    let mut token = null_mut();
    // SAFETY: an open level; a null token means this process's.
    let ok = unsafe { SaferComputeTokenFromLevel(level, null_mut(), &mut token, 0, null_mut()) };
    let err = io::Error::last_os_error();
    unsafe { SaferCloseLevel(level) };
    assert_ne!(ok, 0, "SaferComputeTokenFromLevel: {err}");
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    if token_level(token.as_raw_handle()) != MEDIUM {
        let text = wide(OsStr::new("S-1-16-8192"));
        let mut sid = null_mut();
        // SAFETY: a NUL-terminated string; `sid` receives a LocalAlloc'd SID.
        let ok = unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut sid) };
        assert_ne!(
            ok,
            0,
            "ConvertStringSidToSidW: {}",
            io::Error::last_os_error()
        );
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: SE_GROUP_INTEGRITY as u32,
            },
        };
        // SAFETY: a valid SID.
        let len =
            std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32 + unsafe { GetLengthSid(sid) };
        // SAFETY: a token from above and a label of `len` bytes.
        let ok = unsafe {
            SetTokenInformation(
                token.as_raw_handle(),
                TokenIntegrityLevel,
                (&label as *const TOKEN_MANDATORY_LABEL).cast(),
                len,
            )
        };
        let err = io::Error::last_os_error();
        unsafe { LocalFree(sid) };
        assert_ne!(ok, 0, "SetTokenInformation: {err}");
    }
    token
}

/// This process's environment with [`ROLE`] set to `role` and `extra`
/// added, as a sorted, double-NUL-terminated block.
fn env_block(role: &str, extra: &[(&str, &OsStr)]) -> Vec<u16> {
    let ours = |k: &OsStr| [ROLE, ID, DIR].iter().any(|n| k.eq_ignore_ascii_case(n));
    let mut vars: Vec<(OsString, OsString)> =
        std::env::vars_os().filter(|(k, _)| !ours(k)).collect();
    vars.push((ROLE.into(), role.into()));
    vars.extend(extra.iter().map(|&(k, v)| (k.into(), v.to_os_string())));
    vars.sort_by_key(|(k, _)| k.to_ascii_uppercase());
    let mut block = Vec::new();
    for (k, v) in vars {
        block.extend(k.encode_wide());
        block.push(u16::from(b'='));
        block.extend(v.encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

/// An anonymous pipe whose ends are both inheritable.
fn pipe() -> (OwnedHandle, OwnedHandle) {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let (mut read, mut write) = (null_mut(), null_mut());
    // SAFETY: valid out-pointers and attributes.
    let ok = unsafe { CreatePipe(&mut read, &mut write, &sa, 0) };
    assert_ne!(ok, 0, "CreatePipe: {}", io::Error::last_os_error());
    // SAFETY: handles the call returned.
    unsafe {
        (
            OwnedHandle::from_raw_handle(read),
            OwnedHandle::from_raw_handle(write),
        )
    }
}

fn no_inherit(handle: &OwnedHandle) {
    // SAFETY: an open handle.
    let ok = unsafe { SetHandleInformation(handle.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) };
    assert_ne!(
        ok,
        0,
        "SetHandleInformation: {}",
        io::Error::last_os_error()
    );
}

fn reader(out: File) -> Receiver<String> {
    let (tx, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    lines
}
