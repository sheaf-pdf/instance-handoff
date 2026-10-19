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
use std::time::{Duration, Instant};

use instance_handoff::{AppId, Args, Builder, Claim, Kind, Reason, Started, State};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION, ERROR_NO_SUCH_LOGON_SESSION, GENERIC_READ,
    GENERIC_WRITE, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LocalFree,
    SetHandleInformation, SetLastError,
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
    CheckTokenMembership, CreateWellKnownSid, DACL_SECURITY_INFORMATION, GetLengthSid,
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsTokenRestricted,
    LABEL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSID,
    SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES, SetTokenInformation,
    TOKEN_ELEVATION_TYPE, TOKEN_INFORMATION_CLASS, TOKEN_LINKED_TOKEN, TOKEN_MANDATORY_LABEL,
    TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER, TokenElevationType, TokenElevationTypeDefault,
    TokenElevationTypeFull, TokenElevationTypeLimited, TokenIntegrityLevel, TokenIsAppContainer,
    TokenLinkedToken, TokenOwner, TokenRestrictedSids, TokenSessionId, TokenUser,
    WinBuiltinAdministratorsSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_SHARE_READ, FILE_SHARE_WRITE, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    LockFileEx, READ_CONTROL, UnlockFileEx,
};
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::StationsAndDesktops::{
    GetProcessWindowStation, GetUserObjectInformationW, UOI_FLAGS, UOI_NAME, USEROBJECTFLAGS,
};
use windows_sys::Win32::System::SystemServices::SE_GROUP_INTEGRITY;
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, GetCurrentProcess,
    OpenProcessToken, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW,
    TerminateProcess, WaitForSingleObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::WSF_VISIBLE;

const APP: AppId = AppId::headless("test.levels");
/// Which `child_*` test a child runs as.
const ROLE: &str = "INSTANCE_HANDOFF_LEVELS_ROLE";
/// The app id a child launches as.
const ID: &str = "INSTANCE_HANDOFF_LEVELS_ID";
/// The folder a child is given: `Builder::dir`, or where the probe works.
const DIR: &str = "INSTANCE_HANDOFF_LEVELS_DIR";
/// The state folder a child launches with. Without it, `State::none()`.
const STATE: &str = "INSTANCE_HANDOFF_LEVELS_STATE";

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
/// The label of a key folder and of its instance.lock, as 0015 lays them
/// out. It doesn't inherit, so nothing made in the key folder gets a label
/// from it. Like every label in the layout, it isn't protected (`S:P`):
/// the `protected-label` row reports why.
const KEY_LABEL: &str = "S:(ML;;NWNR;;;ME)";
/// The labels of the level folders in a key folder. They inherit, so what
/// an owner makes in its folder is labelled at its level.
const RUN: &str = "S:(ML;OICI;NWNR;;;ME)";
const RUN_HIGH: &str = "S:(ML;OICI;NWNR;;;HI)";

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

#[test]
fn a_medium_launch_never_hands_off_to_a_high_owner() {
    if !elevated() {
        return;
    }
    let id = app("high-owner");
    let claim = claim(Builder::new(id.clone(), State::none()).start(&Args::default()));
    assert!(
        claim.dir().ends_with("run-high"),
        "{}",
        claim.dir().display()
    );
    let base = app_folder(claim.dir(), &id).to_path_buf();
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
    let base = app_folder(Path::new(&dir), &id).to_path_buf();

    match Builder::new(id.clone(), State::none()).start(&Args::new(["from-high"])) {
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
    let reason = Builder::new(id, State::none())
        .hand_off(&Args::new(["from-high"]))
        .unwrap_err();
    assert!(matches!(reason, Reason::NoOwner { .. }), "{reason}");

    let rest = child.finish();
    assert!(!rest.iter().any(|l| l.starts_with("took ")), "{rest:?}");
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn a_folder_made_at_one_level_is_refused_at_the_other() {
    if !elevated() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();

    let high = tmp.path().join("high");
    let claim = claim(
        Builder::new(APP, State::none())
            .dir(&high)
            .start(&Args::default()),
    );
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
    match Builder::new(APP, State::none())
        .dir(&made_at_medium)
        .start(&Args::new(["from-high"]))
    {
        Started::Alone(Reason::RuntimeDir { .. }) => {}
        other => panic!("{}", describe(&other)),
    }
    let rest = child.finish();
    assert!(!rest.iter().any(|l| l.starts_with("took ")), "{rest:?}");
}

// Every level locks one guard in the state folder, though each has a
// runtime folder of its own: while an owner at one level holds it, a
// launch at the other runs alone with StateInUse at once. Medium can lock
// the guard file that high made.
#[test]
fn the_guard_holds_across_levels() {
    if !elevated() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    let at_medium = tmp.path().join("medium");
    let id = APP;
    let env = [
        (ID, OsStr::new(id.as_str())),
        (DIR, at_medium.as_os_str()),
        (STATE, state.as_os_str()),
    ];
    let high = Builder::new(APP, state.as_path()).dir(tmp.path().join("high"));

    // High owns first, and makes the state folder and the guard file.
    let owner = claim(high.start(&Args::default()));
    assert!(owner.guarded());
    let mut child = medium("child_launch", &env);
    let outcome = child.expect("outcome ");
    assert!(outcome.starts_with("alone StateInUse"), "{outcome}");
    let ms: u64 = child.expect("elapsed ").parse().unwrap();
    assert!(ms < 1000, "{ms} ms");
    child.finish();
    owner.release();

    let mut child = medium("child_owner", &env);
    child.expect("owner ");
    let t = Instant::now();
    match high.start(&Args::new(["from-high"])) {
        Started::Alone(Reason::StateInUse { .. }) => {}
        other => panic!("{}", describe(&other)),
    }
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    let rest = child.finish();
    assert!(!rest.iter().any(|l| l.starts_with("took ")), "{rest:?}");
}

/// What a medium process may do with files, folders and locks a high one
/// made, and the reverse: the facts a lock shared across levels (0015)
/// would rest on. Each level also reports its token, session and window
/// station, and tries 0015's layout as the other level made it.
#[test]
#[ignore = "a probe that reports rather than checks: `just levels` runs it"]
fn what_each_level_may_do_with_the_others_files() {
    if !elevated() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let mut facts: Vec<(String, String)> = token_facts()
        .into_iter()
        .map(|(name, value)| (format!("high: {name}"), value))
        .collect();

    for (name, sddl) in FILES {
        let made = create(&dir.join(name), sddl, false).map(drop);
        facts.push((
            format!("{name}: made by high"),
            made_as(&dir.join(name), &made, security),
        ));
    }
    for (name, sddl) in FOLDERS {
        let made = create(&dir.join(name), sddl, true).map(drop);
        facts.push((
            format!("{name}: made by high"),
            made_as(&dir.join(name), &made, security),
        ));
    }
    // A lock file as 0015 proposes: labelled medium, with high holding the
    // state byte and its own level's byte.
    let guard = create(&dir.join("guard"), Some("S:(ML;;NW;;;ME)"), false)
        .unwrap()
        .unwrap();
    lock(&guard, GUARD, 1, true).unwrap();
    lock(&guard, u64::from(HIGH), 1, true).unwrap();
    facts.push(("guard: made by high".into(), security(&dir.join("guard"))));
    // A key folder with its label protected (S:P). Its row shows why no
    // label in the layout is protected.
    let protected = dir.join("protected-label");
    let sddl = layout_sddl("OICI", "S:P(ML;;NWNR;;;ME)");
    let made = create(&protected, Some(&sddl), true);
    facts.push((
        "protected-label: made by high".into(),
        made_as(&protected, &made, full_security),
    ));
    // 0015's layout, owned by high: the key folder and instance.lock, with
    // high's own folder in it.
    let key = dir.join("key-by-high");
    let _owned = make_key(&key, "high", HIGH, &mut facts);
    make_level_folder(&key, "run-high", RUN_HIGH, "high", &mut facts);

    let mut child = medium("child_probe", &[(DIR, dir.as_os_str())]);
    let lines = child.finish();
    if !lines.iter().any(|l| l == "done") {
        panic!("the medium probe didn't finish:\n{}", lines.join("\n"));
    }
    facts.extend(parse_facts(&lines));

    // The reverse: medium holds a lock file and a layout it made, and high
    // tries them.
    let mut holder = medium("child_holder", &[(DIR, dir.as_os_str())]);
    let reported = holder.until("ready");
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
            let got = result(&lock(file, offset, 1, exclusive));
            facts.push((format!("made-by-medium: high's {what}"), got));
        }
    }
    // The layout medium owns: high finds the owner's level, and makes its
    // own folder in the key folder.
    facts.extend(parse_facts(&reported));
    let key = dir.join("key-by-medium");
    try_key(&key, "high", &mut facts);
    make_level_folder(&key, "run-high", RUN_HIGH, "high", &mut facts);
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

/// Launches once and reports how, and how long `start` took, in
/// milliseconds.
#[test]
fn child_launch() {
    if !is_role("child_launch") {
        return;
    }
    let t = Instant::now();
    let started = child_builder().start(&Args::new(["from-medium"]));
    let ms = t.elapsed().as_millis();
    println!("outcome {}", describe(&started));
    println!("elapsed {ms}");
    if let Started::Owner(claim) = started {
        claim.release();
    }
}

/// Reports its token, and tries what high made in the probe's folder.
#[test]
fn child_probe() {
    if !is_role("child_probe") {
        return;
    }
    let dir = PathBuf::from(std::env::var_os(DIR).unwrap());
    for (name, value) in token_facts() {
        fact(&format!("medium: {name}"), value);
    }
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
                    result(&lock(file, offset, 1, exclusive)),
                );
            }
        } else {
            fact(
                &format!("{name}: medium's exclusive lock"),
                result(&lock(file, 0, 1, true)),
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

    // The layout high owns: medium opens the key folder, makes its own
    // folder in it, tries the lock as a launch would, and tries to list
    // high's folder.
    let key = dir.join("key-by-high");
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(&key);
    let mut facts = vec![("key-by-high: medium opens it".to_owned(), result(&opened))];
    make_level_folder(&key, "run", RUN, "medium", &mut facts);
    try_key(&key, "medium", &mut facts);
    let listed = std::fs::read_dir(key.join("run-high"));
    facts.push((
        r"key-by-high\run-high: medium lists it".into(),
        result(&listed),
    ));
    for (name, value) in facts {
        fact(&name, value);
    }
    println!("done");
}

/// Makes a lock file and holds the state byte and medium's byte. Then
/// makes a key folder with instance.lock in it, and holds bytes 0 and
/// medium's as an owner would. Waits for stdin to close.
#[test]
fn child_holder() {
    if !is_role("child_holder") {
        return;
    }
    let dir = PathBuf::from(std::env::var_os(DIR).unwrap());
    let file = create(&dir.join("made-by-medium"), None, false)
        .unwrap()
        .unwrap();
    lock(&file, GUARD, 1, true).unwrap();
    lock(&file, u64::from(MEDIUM), 1, true).unwrap();
    let mut facts = Vec::new();
    let _owned = make_key(&dir.join("key-by-medium"), "medium", MEDIUM, &mut facts);
    for (name, value) in facts {
        fact(&name, value);
    }
    println!("ready");
    let _ = io::stdin().read_line(&mut String::new());
}

fn is_role(name: &str) -> bool {
    std::env::var_os(ROLE).is_some_and(|r| r == name)
}

fn child_builder() -> Builder {
    let id = AppId::parse(std::env::var(ID).unwrap(), Kind::Headless).unwrap();
    let state = std::env::var_os(STATE).map_or_else(State::none, State::dir);
    match std::env::var_os(DIR) {
        Some(dir) => Builder::new(id, state).dir(PathBuf::from(dir)),
        None => Builder::new(id, state),
    }
}

fn fact(name: &str, value: impl std::fmt::Display) {
    println!("fact {name} = {value}");
}

/// The facts among a child's lines.
fn parse_facts(lines: &[String]) -> impl Iterator<Item = (String, String)> {
    lines.iter().filter_map(|l| {
        let (name, value) = l.strip_prefix("fact ")?.split_once(" = ")?;
        Some((name.to_owned(), value.to_owned()))
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A fresh app id, so tests in the real local AppData don't meet.
fn app(name: &str) -> AppId {
    AppId::parse(
        format!("test.levels.{}.{name}", std::process::id()),
        Kind::Headless,
    )
    .unwrap()
}

/// The folder named after `id` that `dir` is in: the one the crate made
/// in the real local AppData, which a test removes when it is done.
fn app_folder<'a>(dir: &'a Path, id: &AppId) -> &'a Path {
    dir.ancestors()
        .find(|p| p.file_name() == Some(OsStr::new(id.as_str())))
        .unwrap_or_else(|| panic!("{} isn't in a folder named {id}", dir.display()))
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
        Err(e) => error(e),
    }
}

fn error(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(code) if code == ERROR_ACCESS_DENIED as i32 => "access denied".into(),
        Some(code) if code == ERROR_LOCK_VIOLATION as i32 => "lock violation".into(),
        _ => e.to_string(),
    }
}

/// What `read` says of `path`, or why it couldn't be made.
fn made_as<T>(path: &Path, made: &io::Result<T>, read: fn(&Path) -> String) -> String {
    match made {
        Ok(_) => read(path),
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
    try_token_info(token, class).unwrap_or_else(|e| panic!("GetTokenInformation: {e}"))
}

/// A token's information of one class, in a buffer aligned for it, or why
/// it couldn't be read.
fn try_token_info(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
    let mut len = 0;
    // SAFETY: a size query.
    unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut len) };
    // At least one word, so that a class of up to 8 bytes, such as the
    // u32 ones read here, fits even when the size query gives no size.
    let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
    let size = (buf.len() * 8) as u32;
    // SAFETY: `buf` holds `size` bytes.
    let ok = unsafe { GetTokenInformation(token, class, buf.as_mut_ptr().cast(), size, &mut len) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buf)
}

/// A token's information of one class, read as the `T` it starts with.
///
/// # Safety
///
/// The class's information starts with a `T`, which is valid for any bytes
/// and needs no more than 8-byte alignment.
unsafe fn token_value<T: Copy>(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<T> {
    let info = try_token_info(token, class)?;
    // SAFETY: the call wrote the class's information, which starts with a
    // `T`, into a buffer aligned to 8 bytes; per the contract, that is
    // enough.
    Ok(unsafe { *(info.as_ptr() as *const T) })
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

/// This process's token, session and window station, and the machine's
/// UAC settings: the facts 0015's rules for who may own would rest on.
/// The first, `token`, is the level, who owns what it creates, and whether
/// its Administrators group is enabled.
fn token_facts() -> Vec<(&'static str, String)> {
    let owned = own_token();
    let token = owned.as_raw_handle();
    let level = token_level(token);
    let owner = token_info(token, TokenOwner);
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
    let summary = format!(
        "level {level:#x}; what it makes is owned by {}; Administrators {}",
        names(&owner),
        if member != 0 {
            "enabled"
        } else {
            "not enabled"
        }
    );

    // SAFETY, for each `token_value`: the class's information starts with
    // the type read, a plain number or a handle. TokenRestrictedSids gives
    // a TOKEN_GROUPS, which starts with its count.
    let elevation = match unsafe { token_value::<TOKEN_ELEVATION_TYPE>(token, TokenElevationType) }
    {
        Ok(t) if t == TokenElevationTypeDefault => "default".into(),
        Ok(t) if t == TokenElevationTypeFull => "full".into(),
        Ok(t) if t == TokenElevationTypeLimited => "limited".into(),
        Ok(t) => format!("unknown ({t})"),
        Err(e) => error(&e),
    };
    let linked = match unsafe { token_value::<TOKEN_LINKED_TOKEN>(token, TokenLinkedToken) } {
        Ok(linked) => {
            // SAFETY: a handle the call opened, for the caller to close.
            drop(unsafe { OwnedHandle::from_raw_handle(linked.LinkedToken) });
            "yes".into()
        }
        Err(e) if e.raw_os_error() == Some(ERROR_NO_SUCH_LOGON_SESSION as i32) => "no".into(),
        Err(e) => error(&e),
    };
    // IsTokenRestricted returns 0 both for "no" and for a failure, which
    // only the last error tells apart.
    // SAFETY: no preconditions.
    unsafe { SetLastError(0) };
    // SAFETY: a token open for query.
    let restricted = match unsafe { IsTokenRestricted(token) } {
        0 => match io::Error::last_os_error() {
            e if e.raw_os_error() == Some(0) => "no".to_owned(),
            e => error(&e),
        },
        _ => "yes".to_owned(),
    };
    let restricting = match unsafe { token_value::<u32>(token, TokenRestrictedSids) } {
        Ok(count) => count.to_string(),
        Err(e) => error(&e),
    };
    let app_container = match unsafe { token_value::<u32>(token, TokenIsAppContainer) } {
        Ok(0) => "no".into(),
        Ok(_) => "yes".into(),
        Err(e) => error(&e),
    };
    let session = match unsafe { token_value::<u32>(token, TokenSessionId) } {
        Ok(session) => session.to_string(),
        Err(e) => error(&e),
    };
    vec![
        ("token", summary),
        ("elevation type", elevation),
        ("linked token", linked),
        (
            "restricted",
            format!("{restricted}; restricting SIDs: {restricting}"),
        ),
        ("AppContainer", app_container),
        ("session", session),
        ("window station", window_station()),
        ("UAC", uac()),
    ]
}

/// This process's window station: its name, and whether it is visible,
/// as only the interactive one is.
fn window_station() -> String {
    // SAFETY: no arguments. The handle it returns is never to be closed,
    // and isn't.
    let station = unsafe { GetProcessWindowStation() };
    if station.is_null() {
        return format!(
            "GetProcessWindowStation: {}",
            error(&io::Error::last_os_error())
        );
    }
    let mut name = [0u16; 256];
    let mut len = 0;
    // SAFETY: an open window station, and a buffer of the size given.
    let ok = unsafe {
        GetUserObjectInformationW(
            station,
            UOI_NAME,
            name.as_mut_ptr().cast(),
            std::mem::size_of_val(&name) as u32,
            &mut len,
        )
    };
    let name = if ok == 0 {
        format!("UOI_NAME: {}", error(&io::Error::last_os_error()))
    } else {
        let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        String::from_utf16_lossy(&name[..end])
    };
    let mut flags = USEROBJECTFLAGS::default();
    // SAFETY: as above.
    let ok = unsafe {
        GetUserObjectInformationW(
            station,
            UOI_FLAGS,
            (&mut flags as *mut USEROBJECTFLAGS).cast(),
            std::mem::size_of::<USEROBJECTFLAGS>() as u32,
            &mut len,
        )
    };
    let visible = if ok == 0 {
        format!("UOI_FLAGS: {}", error(&io::Error::last_os_error()))
    } else if flags.dwFlags & WSF_VISIBLE as u32 != 0 {
        "visible".into()
    } else {
        "not visible".into()
    };
    format!("{name}, {visible}")
}

/// `EnableLUA` and `FilterAdministratorToken`, as `reg query` shows them.
fn uac() -> String {
    const KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    let out = {
        // Under SPAWN, as children at medium are, so that neither child can
        // inherit the other's pipes.
        let _spawning = SPAWN.lock().unwrap_or_else(|e| e.into_inner());
        std::process::Command::new("reg")
            .args(["query", KEY])
            .output()
    };
    let out = match out {
        Ok(out) if out.status.success() => out,
        Ok(out) => return format!("reg: {}", String::from_utf8_lossy(&out.stderr).trim()),
        Err(e) => return format!("reg: {}", error(&e)),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    ["EnableLUA", "FilterAdministratorToken"]
        .map(|name| {
            // A value's line: its name, its type, then its data.
            let data = text.lines().find_map(|line| {
                let mut words = line.split_whitespace();
                // Registry value names ignore case.
                let found = words.next().is_some_and(|w| w.eq_ignore_ascii_case(name));
                found.then(|| words.last()).flatten()
            });
            format!("{name} {}", data.unwrap_or("not set"))
        })
        .join("; ")
}

/// `path`'s owner and label, as SDDL.
fn security(path: &Path) -> String {
    let info = OWNER_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
    match sddl(path, info) {
        Ok(sddl) if sddl.contains("S:") => sddl,
        Ok(sddl) => format!("{sddl} (no label: medium)"),
        Err(e) => e,
    }
}

/// `path`'s owner, access list and label, as SDDL, then its label ACEs.
/// Each object in 0015's layout should have exactly one, its own; the
/// protected-label row shows what a protected one would be.
fn full_security(path: &Path) -> String {
    let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
    match sddl(path, info) {
        Ok(sddl) => format!("{sddl} ({})", labels(&sddl)),
        Err(e) => e,
    }
}

/// How many label ACEs `sddl` has, and for each its level and whether it
/// is explicit or inherited: "2 label ACEs: ME, explicit; HI, inherited".
fn labels(sddl: &str) -> String {
    let aces: Vec<String> = sddl
        .split('(')
        .filter_map(|ace| ace.strip_prefix("ML;"))
        .map(|ace| {
            // The rest of the ACE: flags, rights, two object GUIDs and the
            // SID. An inherited ACE has ID among its two-letter flags.
            let mut fields = ace.split([';', ')']);
            let flags = fields.next().unwrap_or_default();
            let level = fields.nth(3).unwrap_or("?");
            let inherited = flags.as_bytes().chunks(2).any(|f| f == b"ID");
            let how = if inherited { "inherited" } else { "explicit" };
            format!("{level}, {how}")
        })
        .collect();
    if aces.is_empty() {
        return "0 label ACEs".into();
    }
    let s = if aces.len() == 1 { "" } else { "s" };
    format!("{} label ACE{s}: {}", aces.len(), aces.join("; "))
}

/// The parts of `path`'s security that `info` names, as SDDL, or why they
/// couldn't be read.
fn sddl(path: &Path, info: OBJECT_SECURITY_INFORMATION) -> Result<String, String> {
    let file = match OpenOptions::new()
        .access_mode(READ_CONTROL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
    {
        Ok(file) => file,
        Err(e) => return Err(format!("can't read its security: {}", error(&e))),
    };
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
        return Err(format!(
            "GetSecurityInfo: {}",
            io::Error::from_raw_os_error(err as i32)
        ));
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
        return Err(format!(
            "ConvertSecurityDescriptorToStringSecurityDescriptorW: {err}"
        ));
    }
    Ok(names(&unsafe { take_wide(text) }))
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

/// `len` bytes from `offset`, without waiting.
fn lock(file: &File, offset: u64, len: u64, exclusive: bool) -> io::Result<()> {
    let mut ov = at(offset);
    let mut flags = LOCKFILE_FAIL_IMMEDIATELY;
    if exclusive {
        flags |= LOCKFILE_EXCLUSIVE_LOCK;
    }
    // SAFETY: an open, synchronous handle; the call completes before it
    // returns, so `ov` outlives it.
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
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Gives back the range that `lock` took.
fn unlock(file: &File, offset: u64, len: u64) -> io::Result<()> {
    let mut ov = at(offset);
    // SAFETY: as in `lock`.
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

/// An `OVERLAPPED` that names `offset`, for a synchronous call.
fn at(offset: u64) -> OVERLAPPED {
    // SAFETY: plain data.
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.Anonymous.Anonymous.Offset = offset as u32;
    ov.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
    ov
}

/// The marker a launch would find in a held instance.lock: the bytes in
/// [1, 0x10000) that another handle holds exclusively. Shared range locks,
/// each given back at once, halve the range around a conflict. Also says
/// how many it tried.
fn marker(file: &File) -> String {
    let mut tries = 0;
    match held(file, 1, 0x10000, &mut tries) {
        Ok(bytes) if bytes.is_empty() => format!("none, after {tries} range locks"),
        Ok(bytes) => {
            let bytes: Vec<String> = bytes.iter().map(|b| format!("{b:#x}")).collect();
            format!("{}, after {tries} range locks", bytes.join(" and "))
        }
        Err(e) => error(&e),
    }
}

/// The bytes in `start..end` that another handle holds exclusively.
fn held(file: &File, start: u64, end: u64, tries: &mut u32) -> io::Result<Vec<u64>> {
    *tries += 1;
    match lock(file, start, end - start, false) {
        Ok(()) => return unlock(file, start, end - start).map(|()| Vec::new()),
        Err(e) if e.raw_os_error() != Some(ERROR_LOCK_VIOLATION as i32) => return Err(e),
        Err(_) => {}
    }
    if end - start == 1 {
        return Ok(vec![start]);
    }
    let mid = start + (end - start) / 2;
    let mut bytes = held(file, start, mid, tries)?;
    bytes.extend(held(file, mid, end, tries)?);
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// 0015's layout, made by hand
// ---------------------------------------------------------------------------

/// The security 0015 gives the key folder (`inherit` "OICI") and
/// instance.lock (""): an explicit, protected access list for this user
/// and SYSTEM, then `label`. The protected-label row passes a protected
/// label to show why the layout's aren't.
fn layout_sddl(inherit: &str, label: &str) -> String {
    let user = user();
    format!("D:P(A;{inherit};FA;;;{user})(A;{inherit};FA;;;SY){label}")
}

/// Makes the key folder `key` with instance.lock in it, and holds the
/// lock's byte 0 and then the byte at `level`, as an owner would. Reports
/// as `who`, and returns the lock, held until it is dropped.
fn make_key(key: &Path, who: &str, level: u32, facts: &mut Vec<(String, String)>) -> Option<File> {
    let name = key.file_name().unwrap().to_string_lossy();
    let made = create(key, Some(&layout_sddl("OICI", KEY_LABEL)), true);
    facts.push((
        format!("{name}: made by {who}"),
        made_as(key, &made, full_security),
    ));
    let path = key.join("instance.lock");
    let made = create(&path, Some(&layout_sddl("", KEY_LABEL)), false);
    facts.push((
        format!(r"{name}\instance.lock: made by {who}"),
        made_as(&path, &made, full_security),
    ));
    let file = made.ok().flatten()?;
    for (what, offset) in [("byte 0", 0), ("its level's byte", level)] {
        let got = result(&lock(&file, offset.into(), 1, true));
        facts.push((
            format!(r"{name}\instance.lock: {who}'s exclusive lock on {what}"),
            got,
        ));
    }
    Some(file)
}

/// Makes the level folder `folder` in the key folder `key`, labelled
/// `label`, and reports as `who`.
fn make_level_folder(
    key: &Path,
    folder: &str,
    label: &str,
    who: &str,
    facts: &mut Vec<(String, String)>,
) {
    let name = key.file_name().unwrap().to_string_lossy();
    let path = key.join(folder);
    let made = create(&path, Some(label), true);
    facts.push((
        format!(r"{name}\{folder}: made by {who}"),
        made_as(&path, &made, full_security),
    ));
}

/// Tries the instance.lock that another level holds in `key`, as a launch
/// would: opens it to write, tries byte 0, and looks for the marker.
/// Reports as `who`.
fn try_key(key: &Path, who: &str, facts: &mut Vec<(String, String)>) {
    let name = key.file_name().unwrap().to_string_lossy();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(key.join("instance.lock"));
    facts.push((
        format!(r"{name}\instance.lock: {who} opens to write"),
        result(&file),
    ));
    if let Ok(file) = &file {
        facts.push((
            format!(r"{name}\instance.lock: {who}'s exclusive lock on byte 0"),
            result(&lock(file, 0, 1, true)),
        ));
        facts.push((
            format!(r"{name}\instance.lock: the marker {who} finds"),
            marker(file),
        ));
    }
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

    /// The lines before the first that is `end`.
    fn until(&self, end: &str) -> Vec<String> {
        let mut seen = Vec::new();
        while let Ok(line) = self.lines.recv_timeout(Duration::from_secs(30)) {
            if line == end {
                return seen;
            }
            seen.push(line);
        }
        panic!("no `{end}` line from the child:\n{}", seen.join("\n"));
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
    let ours = |k: &OsStr| {
        [ROLE, ID, DIR, STATE]
            .iter()
            .any(|n| k.eq_ignore_ascii_case(n))
    };
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
