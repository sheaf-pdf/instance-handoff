# 0015: implementation calls

The planning run behind [0015-plan.md](0015-plan.md) left questions that the records don't answer. These are the answers. Where these and [0015-requirements.md](0015-requirements.md) differ, these win.

- **Recommended:** the planning run's recommendation. The maintainer accepted all of them on 2026-10-19.
- **Our call:** the run asked without recommending, so one was chosen when the plan was written. It can change before its slice lands; record the change here.

## 1. Wire (slices 5, 9, 13, 16, 17, 18)

1. **Tags.** HELLO: 7 LEVEL, 9 STATE (the state and scope), 11 FEATURES (u32 LE). Today's HELLO tag 6, also called STATE (the serving state), is renamed SERVING. Gaps are left for 0.2. *Recommended.*
2. **REQUEST.** 0x8A HAND_DOWN: a variant byte, then two RIDs as u32 LE. It is critical, so an older owner refuses it. *Recommended.*
3. **Refusal codes.** 8 PRIVILEGE, 10 PEER; 9, 11 and 12 reserved. *Recommended.*
4. **APP.** One kind byte, then the id. *Recommended.*
5. **STATE** carries the exact framed bytes the instance folder's hash is computed from. *Recommended.* Slice 13 settled two cases this leaves open. *Our call (slice 13).*
   - Every HELLO must carry STATE, even an empty one (`State::none()` with no scope). A HELLO without it is malformed, and a launch reads it as not this protocol.
   - A launch reads a HELLO body of up to 4096 bytes more than its own STATE, so an owner of the same state always fits, however long the path or scope. A longer one isn't from its owner, and reads as not this protocol too.
6. **The owner's level in REPLY** travels in the next free REPLY tag, chosen in slice 17 and pinned by its frozen test. Unix owners don't send LEVEL. *Our call; Unix part recommended.*
7. **Refusing before HELLO.** On Unix, a REPLY REFUSED PEER is the first and only frame, and launches handle both shapes. A Windows owner can refuse only after HELLO, because impersonation needs a read, so it never refuses a probe. *Recommended.*
8. **FEATURES** ships in 0.1, though no 0.1 launch reads bit 0 yet. *Recommended.*
9. **A STATE mismatch in HELLO** (two states with the same hash) is `Reason::OtherApp`, whose docs widen to say so. Refusal code 11 stays reserved. *Recommended.*

## 2. App ids and kinds (slices 8, 9, 12, 36)

1. `AppId` loses `FromStr`. *Recommended.*
2. `Kind` is exhaustive and derives `Ord`, so `AppId` keeps `Ord`. A third kind would change the contract between builds anyway, and apps can match both kinds. *Our call.*
3. The kind isn't hashed into the instance folder. Launches compare it from HELLO. *Recommended.*
4. `Ineligible::Headless`, a windowed launch that can't show windows, is renamed `NoWindows`, because `Headless` now names a kind. *Our call.*

## 3. The state (slices 10, 12, 24, 25)

1. **Canonical form.**
   - Unix: the `realpath` of the nearest existing ancestor, plus the rest.
   - Windows: `GetFinalPathNameByHandleW`, without the verbatim prefix for drive paths and in the plain UNC form, as WTF-8.
   - A missing tail is kept as given.
   - In the hash, a tag byte and a u32 length frame each part, so `State::none()`, an empty scope and no scope all differ.

   *Recommended.*

   Slice 10 settled the cases this leaves open, and slice 12 freezes them into the hash. *Our call (slice 10).*
   - A `..` in the missing tail drops the part before it, as `mkdir -p` will, so a folder has one form before and after it exists: `<real>/a/../b` is `<real>/b`. A `..` with no missing part before it drops the last part of the resolved folder. If folding brings a folder that exists onto the path, as `<real>/new/../link` does, that folder is resolved too. On Windows, making the path absolute already folds every `..`. This refines "kept as given".
   - A path whose links can't be resolved (any error but not-found, such as a folder this user can't search, or a volume that reports no final path) is kept as given, made absolute. One that can't be made absolute (an empty path, or a relative one once the working directory is gone) is kept as given, so `state_dir()` is then relative. The launch goes on, with a warning in the log, since no `Reason` fits. Either case could instead get a `Reason` naming the state path, before slice 12.
   - On Windows, a final path with no drive or share, `\\?\Volume{…}\…` or `\\?\GLOBALROOT\…`, keeps its verbatim prefix.
   - A file where a folder should be, `<file>/state`, can't be resolved on Unix (`ENOTDIR`), so the whole path is kept as given. On Windows the open reports the path not found, so `state` counts as missing and the file's own path is resolved. Neither folder can be created.

   Slice 12 fixed the hash's framing: the state with tag 1, then the scope with tag 2, each as `tag u8 | length u32 LE | bytes`, and a missing part left out rather than written empty. Paths are their bytes on Unix and WTF-8 on Windows. The lib.rs contract and `naming`'s frozen tests pin it, and HELLO's STATE record (slice 13) carries the same bytes. *Our call (slice 12).*
2. **ForeignState.** A non-root Unix launch trusts folders owned by itself or by root, and root trusts only root's. Windows keeps `trusted()`. Test the rule with a table, and end to end under bwrap. *Recommended.* Slice 24 settled four cases the call left open. *Our call (slice 24).*
   - An owner that can't be read passes, with a warning in the log, as a path whose links can't be resolved already does.
   - A Windows volume that keeps no owners (FAT, exFAT, no `FILE_PERSISTENT_ACLS`) always passes.
   - `ForeignState { path }` names the folder found to be another user's: the state folder, or, while it is missing, the nearest folder above it.
   - The overflow uid (65534) counts as another user's. In a user namespace that doesn't map root (Flatpak, bwrap), host root's folders show with that uid, so a missing state folder whose nearest existing folder is one of them gives `ForeignState`. Slice 38 tests this under bwrap, and treats the overflow uid as unknown instead if the refusal turns out wrong there.
3. **A missing state folder.** `start` and `exclusive` create a missing state folder after the ForeignState check and the runtime lock. They use `create_dir_all`; on Unix the last folder gets mode 0700, and on Windows an access list for the user and SYSTEM. ForeignState applies only to `start` and `exclusive`. *Recommended.*
4. `Level` and `Rights` live in `src/level.rs`, re-exported. *Recommended.*

## 4. The guard (slices 25 to 30)

1. No holder text in 0.1: `StateInUse` names no holder, and the lock file stays unwritten (0010). The guard sits at offset 2^31, which leaves room for text later. *Recommended.*
2. A read-only state folder, `EACCES`, or a guard file that belongs to another user gives `Reason::Lock`. `ENOLCK` and `EOPNOTSUPP` leave the owner unguarded. *Recommended.*
3. The Windows guard's handle doesn't share delete, so the app can't rename or delete its own state folder while it runs. *Recommended.*
4. A state folder labelled above medium gives `Reason::Lock`, since the guard can't be made or locked there. *Our call.*
5. `start` retries the guard for about 50 ms, and that counts as "at once". *Recommended.*
6. **LostState.**
   - After `LostState` the owner gives up its runtime lock and socket. It watches for `LostState` only while it holds the guard. *Recommended.*
   - A guard file deleted from an unchanged state folder is re-created if nobody holds the new one; otherwise the owner ends with `LostState`. This matches how the runtime lock already works (0008). *Our call.*
7. **exclusive().** With `State::none()`, `Guard::Off` or a skipped guard, `exclusive()` takes the runtime lock without listening, as `Mode::Separate` did. `ElevatedOwner` applies to it, so a raised `exclusive()` under `NotRaised` gets `MayNotOwn { Raised }`. *Recommended.* Until slice 30, a `Mode::Separate` launch that may not own does the same: `MayNotOwn` at once, whether or not an owner runs. *Our call (slice 34).*

## 5. Folders and bases (slices 7, 19, 22, 31)

1. The Linux order is Flatpak, snap, root, systemd, then `/tmp`. The sandboxes come first because they set the runtime folder. *Our call.*
2. Root on illumos uses `/var/run/instance-handoff`, as on the BSDs. Root on Android stays on `TMPDIR`. *Our call.*
3. Root's long-path socket goes to `<root base>/<hash>.sock`. *Recommended.*
4. On Windows, `Claim::dir`, `Owner::dir` and `runtime_dir` return the shared key folder. *Recommended.*
5. An existing key folder with no label counts as medium. *Recommended.*
6. A `Builder::dir` base stays unlabelled, like `<LocalAppData>\<id>`. Only `i-<hash>` gets the explicit medium label. *Recommended; the label is no longer protected, as 5.8 now says.* A base labelled above medium is refused with `RuntimeDir`. *Our call.*
7. A Local AppData that resolves into another user's profile gives `RuntimeDir`, naming the path. A redirect outside the profiles folder stays allowed. *Recommended.*
8. Every label the crate sets is explicit, and none is protected. A protected label (`S:P`) needs a privilege the crate's processes don't have enabled. On Windows CI, both levels failed to make a folder with one (error 1314, run 39221106656), and the crate never enables privileges. The key folder's label doesn't inherit, so each object in it carries only its own explicit label. The SDDL tests check that each object has exactly one label. *Changed after slice 3's run.*

## 6. Across Windows levels (slices 20 to 23)

1. **The marker.**
   - The owner locks byte 0, then the byte at its level's RID, retrying for about 100 ms. If the marker still fails, it gives byte 0 back.
   - A launch probes its own RID first, then searches [1, 0x10000) with shared range locks.
   - When several markers are held, the highest wins.
   - Byte 0 held with no marker means the owner is starting: retry until the deadline.

   *Recommended.*
2. A probe at another level is answered from the marker alone, unconfirmed. *Recommended.*
3. `MoreRights` and `OwnerHasMoreRights` don't name the owner's pid, since `instance.lock` stays unwritten. *Recommended.*
4. A committed launch whose owner died and that then finds the guard, or a lock at another level, held reports an unconfirmed handoff, never `Alone`. Running alone there would break 0004. *The critic's fix.*

## 7. Who may own (slices 32 to 37)

1. `Excluded` applies to `start`, `hand_off`, `probe` and `exclusive`. *Recommended.*
2. Set-id is a plain comparison of the raw ids. *Recommended.* Slice 4 must show that the SAFER token used by the medium tests isn't restricted, or the medium job would break.
3. **Raised on Unix.** `SUDO_UID`, `PKEXEC_UID`, `DOAS_USER` and `loginuid` are enough for 0.1. `su` on the BSDs and macOS goes undetected, since they have no `loginuid`. `run0` sets `SUDO_UID`: its man page lists it, with `SUDO_USER` and `SUDO_GID`, since systemd 256 (checked in slice 34 against systemd 259). *Our call.* A variable that isn't a number, or a `DOAS_USER` that names no user, counts as unset. *Our call (slice 34).*
4. On Unix, `NotAboveNormal` means no root owner. *Recommended.*
5. UIAccess (0x2010) may own under `NotAboveNormal`, as the sketch says. MEDIUM_PLUS (0x2100) counts as above normal. *Our call.*
6. **Can show windows.** Unknown counts as able everywhere.
   - Linux and the BSDs: `DISPLAY` or `WAYLAND_DISPLAY` is set.
   - macOS: `SessionGetInfo`'s graphic-access bit.
   - Windows: not session 0, on a visible window station (`WSF_VISIBLE`).
   - Android: unknown.

   *Our call.*

   Slice 36 settled what this leaves open. *Our call (slice 36).*
   - A variable that is set but empty counts as unset. illumos follows the BSDs. `WAYLAND_SOCKET`, which the plan also named, isn't read.
   - On macOS, a `SessionGetInfo` that fails is unknown.
   - A windowed app's launch that can't show windows gets `NoWindows` before any reason its rights give, since no `ElevatedOwner` lets it own.

   Slice 37 settled how the two Windows facts combine when one can't be read. *Our call (slice 37).* Either alone can say no: session 0, or a window station that isn't visible. A visible station says yes only with a session that was read and isn't 0, since nobody sees session 0's windows. Otherwise the answer is unknown.
7. **No test hook in 0.1.** The docs tell a windowed app to run its tests under a display (Xvfb), or to build its test `AppId` as headless with its own test state. The crate's own tests use headless ids. *Our call.*

## 8. Tests and CI (slices 6, 38)

1. CI installs fakeroot and bubblewrap and requires them through `INSTANCE_HANDOFF_REQUIRE_*` variables. For the bwrap tests, it relaxes AppArmor's limit on unprivileged user namespaces. Locally, these tests skip with a message when a tool is missing. *Recommended.*

## 9. Scope (slices 39 to 46)

1. `hand_off` and `probe` never return `NoSession`. Without a runtime folder they report `NoOwner`, or `StateInUse` from the guard. Slice 39 goes ahead. *Recommended.*
2. `Builder::dir` refusing network volumes and other users' trees waits. Slice 40 is dropped. *Recommended.*
3. macOS keeps its long-path socket fallback for 0.1. Slice 41 is dropped. *Recommended.*
4. `Request::launcher_pid` stays in 0.1, and gives way to `Request::origin` in 0.2. Slice 42 is dropped. *Recommended.* This departs from 0015's consequence "`Mode` and `launcher_pid` go". When 0015 is marked built, that line will say so.
5. The examples use a folder under `HOME` or `LOCALAPPDATA`, with a comment to pass the storage layer's own folder instead. *Recommended.*
6. This release no longer meets `sheaf-instance` builds on the same lock. 0009 and the CHANGELOG say so. *Recommended.*
7. 0001's in-scope bullet gets a pointer to 0015, not a rewrite, following the design README's rule. *Our call.*
8. **Freezing the Windows layout.** The manual run on a machine with UAC on (slice 46) is the gate for 0.1. A second administrator on CI isn't required. Slice 46 needs the maintainer's Windows machine. *Our call.*
