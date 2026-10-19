# 0015: implementation calls

The planning run behind [0015-plan.md](0015-plan.md) left questions that the records don't answer. These are the answers. Where these and [0015-requirements.md](0015-requirements.md) differ, these win.

- **Recommended:** the planning run's recommendation. The maintainer accepted all of them on 2026-10-19.
- **Our call:** the run asked without recommending, so one was chosen when the plan was written. It can change before its slice lands; record the change here.

## 1. Wire (slices 5, 9, 13, 16, 17, 18)

1. **Tags.** HELLO: 7 LEVEL, 9 STATE (the state and scope), 11 FEATURES (u32 LE). Today's HELLO tag 6, also called STATE (the serving state), is renamed SERVING. Gaps are left for 0.2. *Recommended.* Slice 16 settled two cases this leaves open for HELLO's LEVEL. *Our call (slice 16).*
   - Only Windows owners send it. Unix owners send none, as with REPLY in 1.6.
   - A LEVEL that isn't 4 bytes makes HELLO malformed, as a wrong-sized SERVING or FEATURES does, and a launch reads it as not this protocol.
2. **REQUEST.** 0x8A HAND_DOWN: a variant byte, then two RIDs as u32 LE. It is critical, so an older owner refuses it. *Recommended.* Slice 18 settled what this leaves open. *Our call (slice 18).*
   - The variant byte is 0 for `Rights::Level`, then the launch's RID and the owner's, so the record is 9 bytes. It goes last, after PAYLOAD. REQUEST tags 7, 8 and 9, and 0x8B, are kept for later.
   - Another length for variant 0, or an empty record, makes REQUEST malformed. A variant the owner doesn't know gets UNSUPPORTED, as an unknown critical record does: the owner couldn't say what was given up.
   - The record is only the launch's consent. An owner admits a launch whose token is above its own level only with it, and reports `Rights::Level { launch, owner }` from the two attested levels, whatever RIDs the record names. At the owner's own level, and where neither has a level (Unix), the record is ignored. Below it, or with the launch's level unread where the owner has one, the launch gets PRIVILEGE, record or not.
   - A launch sends it only to an owner whose HELLO names a level below its own, with `hand_down` set, and never from a probe. It encodes its request before HELLO, as before, and adds the record once HELLO shows it is needed, so `after_commit` decides again for each owner. `OwnerInfo::handed_down` is the same `Rights`, from the launch's level and HELLO's LEVEL, on a confirmed or unconfirmed handoff. A committed launch whose owner died and that reports no owner names none, as it names no level. A launch that handed down and is still refused with PRIVILEGE, as when the owner reads its token at another level than the launch reads it, reads the refusal as any launch does: `MoreRights` when the owner's level is below its own.
   - Slice 23 lets a launch hand down to an owner it finds by the marker. With `hand_down` set, `meet` sends a launch above that owner to the address folder of the marker's level, never from a probe and never to a level above its own. `connect` checks that folder and the pipe's label against that level, as it does at the launch's own, so `check_pipe_owner` is unchanged. A missing folder there, or one with no `instance.pipe` yet, is an owner not listening yet (5.9), so the launch looks again until its deadline; one that fails its check gives `Reason::Peer`. A committed launch whose owner died meets the next owner the same way, so it hands down to one below it rather than report an unconfirmed handoff (6.4). *Our call (slice 23).*
   - After it connects below its own level, the launch knows the owner's level from the pipe's label, so HELLO must name the same. A HELLO with no LEVEL, or another, isn't from that owner: the launch reads it as not this protocol (`Reason::WireVersion`) and sends nothing, rather than send the request without HAND_DOWN or report the wrong `Rights`. At its own level the launch reads HELLO's LEVEL as 1.6 says. *Our call (slice 23).*
3. **Refusal codes.** 8 PRIVILEGE, 10 PEER; 9, 11 and 12 reserved. *Recommended.*
4. **APP.** One kind byte, then the id. *Recommended.*
5. **STATE** carries the exact framed bytes the instance folder's hash is computed from. *Recommended.* Slice 13 settled two cases this leaves open. *Our call (slice 13).*
   - Every HELLO must carry STATE, even an empty one (`State::none()` with no scope). A HELLO without it is malformed, and a launch reads it as not this protocol.
   - A launch reads a HELLO body of up to 4096 bytes more than its own STATE, so an owner of the same state always fits, however long the path or scope. A longer one isn't from its owner, and reads as not this protocol too.
6. **The owner's level in REPLY** travels in the next free REPLY tag, chosen in slice 17 and pinned by its frozen test. Unix owners don't send LEVEL. *Our call; Unix part recommended.* Slice 17 chose tag 5 and settled what this leaves open. *Our call (slice 17).*
   - REPLY's LEVEL is the owner's RID as a u32 LE, as in HELLO, and goes only with PRIVILEGE. One that isn't 4 bytes makes REPLY malformed.
   - The owner compares the launch's level, from its token, with its own, both as options. So on Windows, where the owner has a level, a launch whose level wasn't read is refused too, and on Unix, where neither has one, nobody is. Rights come after the wire and payload versions, and before the payload is decoded or the owner says whether it serves.
   - A launch decides from HELLO's LEVEL before it looks at whether the owner serves. At another level, `start` and `hand_off` fail at once with `MoreRights` or `OwnerHasMoreRights`, and `probe` returns `Ok`, unconfirmed, whether or not the owner serves.
   - A launch reads PRIVILEGE by comparing REPLY's LEVEL with its own, whether it came after HELLO or in its place. Without a LEVEL, or with the launch's own, it can't name the rights, so it reads the cause as one it doesn't know: `Declined`.
   - The Windows owner refuses with PEER only a launch of another user, or one it can't check.
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

   Slice 38's bwrap test kept the overflow uid as another user's. *Our call (slice 38).* In a user namespace that binds the host's `/`, as the test's bwrap does, root and the user alike see `/` and the host's `/tmp` with that uid, so a missing state folder right under either gives `ForeignState`, and nothing is made (the test checks `/`). Read as unknown in a trial run, the uid let root in the namespace take the lock and make its runtime folder, then fail to make the state folder with `Reason::Lock`. The uid stands for host root and for every other user the namespace doesn't map, and a launch can't tell which. Refusals the host wouldn't make come only from folders of host root's that the user may write in, such as a `/tmp` shared with the host with the state folder missing right under it. A state folder the app makes first is the user's, and passes.
3. **A missing state folder.** `start` and `exclusive` create a missing state folder after the ForeignState check and the runtime lock. They use `create_dir_all`; on Unix the last folder gets mode 0700, and on Windows an access list for the user and SYSTEM. ForeignState applies only to `start` and `exclusive`. *Recommended.* Slice 25 settled the cases this leaves open. *Our call (slice 25).*
   - On Unix every `start` that takes the runtime lock with a `State::dir` creates it, under `Guard::Off` and with a scope too, before it takes the guard. Whatever is at the path already, a file say, is left as it is: the guard, where one is taken, refuses it.
   - A state folder that can't be created gives `Reason::Lock`, naming the folder. A committed launch whose owner died reports an unconfirmed handoff instead, as beside a held guard (6.4).
   - The Windows half, with its access list, lands with the Windows guard in slice 27, once slice 19 has the access lists. Until then nothing creates the folder on Windows.

   Slice 27 made the Windows half like the Unix one: the last folder gets `D:P(A;OICI;FA;;;<user>)(A;OICI;FA;;;SY)`, which what the app makes in it inherits, and no label of its own. A label the folder above it hands down still reaches it, as a `Builder::dir` base's does (4.4). Whatever is at the path already is left as it is. The raw calls that make folders and files with an access list are given the path's verbatim form (`\\?\C:\…`, `\\?\UNC\…`), as std gives its own, so a path longer than `MAX_PATH` doesn't stop them. A test makes and guards a state folder whose path is over 300 characters. *Our call (slice 27).*
4. `Level` and `Rights` live in `src/level.rs`, re-exported. *Recommended.*

## 4. The guard (slices 25 to 30)

1. No holder text in 0.1: `StateInUse` names no holder, and the lock file stays unwritten (0010). The guard sits at offset 2^31, which leaves room for text later. *Recommended.* `StateInUse { path }` names the guard file. *Our call (slice 25).*
2. A read-only state folder, `EACCES`, or a guard file that belongs to another user gives `Reason::Lock`. `ENOLCK` and `EOPNOTSUPP` leave the owner unguarded. *Recommended.* Slice 25 settled two cases, and slice 26 one more. *Our call (slice 25).*
   - `ENOTSUP` counts with `EOPNOTSUPP`: they are one number on Linux and FreeBSD, and two on macOS, NetBSD, OpenBSD and illumos.
   - The guard file is opened read-only and without blocking, so one that exists is locked in a read-only folder, and a FIFO in its place can't hold the launch up. Anything but a regular file gives `Reason::Lock`. `EBADF` from `flock` on it also leaves the owner unguarded: the NFS client emulates `flock` with POSIX locks, and an exclusive one needs a descriptor open for writing (flock(2)). So a state folder on NFS leaves each host its own owner, as R05's network rule wants, before slice 28 and on any file system its list misses.
   - On NFS, which emulates `flock` with POSIX locks, a shared one needs only a descriptor open for reading. So a keyed owner there holds the guard, even where an unkeyed one goes unguarded on `EBADF`. Neither keeps the other out, so a keyed and an unkeyed owner of one state folder on NFS own side by side, in either order. Slice 28 skips the guard on NFS for both. *Our call (slice 26).*
   - On Windows, as on Unix, the guard file is opened to read only, and a link or a folder in its place gives `Reason::Lock`. So does a guard file whose owner `trusted()` refuses, as for `ForeignState` (3.2); on a volume that keeps no owners it isn't checked. `ERROR_NOT_SUPPORTED` and `ERROR_INVALID_FUNCTION` from `LockFileEx` leave the owner unguarded, as `ENOLCK` and `EOPNOTSUPP` do. *Our call (slice 27).*
   - On Windows, as `O_NOFOLLOW | O_DIRECTORY` does on Unix, the state folder is opened as itself before the guard is made, and a link, a junction or anything but a folder there gives `Reason::Lock`, naming the guard file. A link is a reparse point that stands for another file or folder (a name surrogate: a symbolic link, a junction or a mount point). Other reparse points, such as a OneDrive placeholder or a deduplicated file, count as the file or folder they are, as std's `is_symlink` counts them, so a state folder that OneDrive syncs isn't refused as a link. The guard file is then made by its path, so a folder swapped in between by this user isn't caught, as it is on Unix by `openat`. *Our call (slice 27).*
3. The Windows guard's handle doesn't share delete, so the app can't rename or delete its own state folder while it runs. *Recommended.*
4. A state folder labelled above medium gives `Reason::Lock`, since the guard can't be made or locked there. *Our call.* Slice 27 reads the state folder's label before it makes the guard file, and `Reason::Lock` names the guard file. A launch that can't open the folder to read its label, as at medium under a high label with no-read-up, gets `Reason::Lock` too. A folder labelled low or medium takes the guard, and so does one on a volume that keeps no labels. The label read is the folder's effective one, inherited or its own, so a state folder inside a `Builder::dir` base made above medium, which hands its label down, is refused at every start there; the docs of `Builder::dir` and `Guard::Local` say to keep the state folder outside. *Our call (slice 27).* From slice 22 the crate makes a `Builder::dir` base with no label at every level (5.6), so a state folder made in it takes none from it, and those docs no longer say to keep it outside. One made under a folder that hands down a label above medium is still refused. *Our call (slice 22).*
5. `start` retries the guard for about 50 ms, and that counts as "at once". *Recommended.*
6. **LostState.**
   - After `LostState` the owner gives up its runtime lock and socket. It watches for `LostState` only while it holds the guard. *Recommended.*
   - A guard file deleted from an unchanged state folder is re-created if nobody holds the new one; otherwise the owner ends with `LostState`. This matches how the runtime lock already works (0008). *Our call.*

   Slice 29 settled what this leaves open. *Our call (slice 29).*
   - On Unix the guard holds the state folder open beside the guard file, so neither inode is reused while the owner runs. Each check compares `lstat` of the state path, then of the guard file in the folder held, with them. A state path that names nothing, or anything but the folder held (another folder, or a link to the one held), gives `LostState`. One that can't be looked at for another reason (`EACCES`, say) is looked at again at the next check, with a warning in the log. On glibc every `stat` in the Unix code is the `*64` call, as `fstatfs64` is in 4.8, since a 32-bit target's `fstat` and `fstatat` fail with `EOVERFLOW` on an inode number above 2^32, as on XFS with `inode64`.
   - A guard file removed or replaced is opened in the folder held, made if missing, and locked in the owner's mode. Locked, it takes the old one's place, with a warning in the log; keyed owners lock it side by side. Held by another process in a mode that conflicts, it gives `LostState`; from slice 39, only once it is still held after 50 ms (9.1). One that can't be made, opened or locked leaves the old one held, with a warning, and the next check tries again.
   - Removed means that the guard file's path names nothing (`ENOENT`), and replaced that it names another file. Any other error, from the path or from the file held, leaves the old one held as above, since a second lock on the file held, were it still in place, would conflict with the owner's own and end it. So does a file that, opened, turns out to be the one held, put back since the look.
   - At `LostState` the owner removes its socket, if it is still its own, gives up the guard and then the lock, and closes its listener. The Windows owner withdraws its address the same way. Nothing else in the runtime folder is touched, then or when the `Owner` closes.
   - While the guard is held alone, a lock in the re-made runtime folder that another process holds is a launch that will get `StateInUse`. The owner logs it at debug and looks again in a second (or at the check interval, if that is shorter), as the Windows owner looks again at an address it couldn't publish. An owner under `Guard::Off` that took the lock there is waited out the same way, so an owner that holds the guard alone never ends with `LostLock`. A keyed owner, or one without a guard, still does. No launch holds the lock for long, so after 10 seconds of this the owner says so once at warn: launches reach the other process, or nobody, until it lets go.
   - The Windows owner compares the guard path's volume serial number and file index (`GetFileInformationByHandle`) with its handle's at each check. The file can't be removed while held, so nothing is made again: another file at the path, or none, gives `LostState`. One that can't be opened is looked at again at the next check.
7. **exclusive().** With `State::none()`, `Guard::Off` or a skipped guard, `exclusive()` takes the runtime lock without listening, as `Mode::Separate` did. `ElevatedOwner` applies to it, so a raised `exclusive()` under `NotRaised` gets `MayNotOwn { Raised }`. *Recommended.* Until slice 30, a `Mode::Separate` launch that may not own does the same: `MayNotOwn` at once, whether or not an owner runs. *Our call (slice 34).* Until then, too, a `Mode::Separate` launch that takes the runtime lock takes the guard as any `start` does, so beside an owner in another runtime folder it gets `StateInUse`, not `OwnerRunning`. *Our call (slice 25).* A keyed `Mode::Separate` launch takes the guard shared, as any keyed `start` does; `exclusive()` will take it alone (R26). *Our call (slice 26).* Slice 30 replaced `Mode` and settled what this leaves open. *Our call (slice 30).*
   - Only the rights part of `ElevatedOwner` applies. A windowed app's `exclusive()` that can't show windows still holds the state: it serves no launches, and a migration from cron or CI must run. `MayNotOwn` comes first, as in `start`, then `ForeignState`. `Excluded` (slice 32) goes before both.
   - With a guard to take, `exclusive()` makes a missing state folder, then takes the guard alone with `start`'s 50 ms retry (4.5), whatever the scope. It needs no runtime folder, so `NoSession` and `RuntimeDir` never reach it there. No new `sys` entry point was needed: `sys::take_guard(state, false)` already takes it alone.
   - Without one, it takes the runtime lock, looking again for 50 ms as `Mode::Separate` did, since `hand_off` and `probe` take and drop that lock to test it. A runtime folder deleted under it meanwhile (a cleaner, `rm`) is opened afresh, as `start` does. Still held, it gives `StateInUse` naming `instance.lock`, in place of `OwnerRunning`. It then makes a missing state folder, as `start` does once it holds the lock. Where `Guard::Local` skipped the guard, the folder was made before.
   - While an exclusive run holds the runtime lock, launches there find nobody serving and get `Unresponsive` at their timeout. Telling them sooner would need a new wire or on-disk mark.
   - `Exclusive` holds the guard, or the runtime folder and its lock, and `release()` only drops it. On Unix a child forked without `exec` keeps it, as it keeps an owner's.
   - `process.rs`'s `next_owner_process` waited its turn with `Mode::Separate`. It now probes until nobody holds the lock, then starts.
8. **Network volumes on Unix.** Slice 28 settled what the plan leaves open. *Our call (slice 28).*
   - A state folder on a network file system gets no guard file. The folder itself is still made, as 3.3 says.
   - A file system whose type can't be read counts as local, and the lock's own errors decide.
   - Linux's magic numbers are written out in the crate as `u32`, and `f_type` is cut to `u32` before it is compared, since libc's types for both differ by architecture. On glibc it comes from `fstatfs64`, since a 32-bit target's `fstatfs` fails with `EOVERFLOW` on a volume with more than 2^32 blocks or files.
   - On illumos, `nfs`, `nfs3`, `nfs4` and `smbfs` are the network file systems: each NFS version is a file system type of its own.
   - The skip goes to the log at debug, since it is the rule, not a fault.
9. **Network volumes on Windows.** A share, as `\\server\share` or `\\?\UNC\…`, is remote. So is a drive, as `C:\` or `\\?\C:\`, that `GetDriveTypeW` reports as `DRIVE_REMOTE`: a mapped drive whose final path couldn't be read. A volume without a drive letter (`\\?\Volume{…}`), `GLOBALROOT`, a device or a relative path counts as local, and the lock decides. As on Unix, the state folder is still made, no guard file is, and the skip goes to the log at debug. *Our call (slice 27).*

## 5. Folders and bases (slices 7, 19, 22, 31)

1. The Linux order is Flatpak, snap, root, systemd, then `/tmp`. The sandboxes come first because they set the runtime folder. *Our call.*
2. Root on illumos uses `/var/run/instance-handoff`, as on the BSDs. Root on Android stays on `TMPDIR`. *Our call.*
3. Root's long-path socket goes to `<root base>/<hash>.sock`. *Recommended.*
4. On Windows, `Claim::dir`, `Owner::dir` and `runtime_dir` return the shared key folder. *Recommended.*
5. An existing key folder with no label counts as medium. *Recommended.*
6. A `Builder::dir` base stays unlabelled, like `<LocalAppData>\<id>`. Only `i-<hash>` gets the explicit medium label. *Recommended; the label is no longer protected, as 5.8 now says.* A base labelled above medium is refused with `RuntimeDir`. *Our call.* Slice 22 refuses the app's folder in Local AppData the same way, since every level shares it too and a launch at medium couldn't make `i-<hash>` in it. *Our call (slice 22).*
7. A Local AppData that resolves into another user's profile gives `RuntimeDir`, naming the path. A redirect outside the profiles folder stays allowed. *Recommended.* Slice 31 settled what this leaves open. *Our call (slice 31).*
   - Anywhere in the profiles folder (`GetProfilesDirectoryW`) outside this user's profile (`GetUserProfileDirectoryW`) counts as another user's. So Public and the profiles folder itself are refused too.
   - Only final paths are compared, name by name and without case. A verbatim prefix or a trailing separator makes no difference.
   - If the final path of Local AppData, the profiles folder or the user's profile can't be read, the launch goes on with a warning in the log, as for an owner that can't be read (3.2). A path with its links resolved is never compared with one without.
   - `RuntimeDir` names Local AppData as the shell gives it. Its source names the final path.
   - The check runs as the folder is opened, on the handle already checked to be safe. So `Builder::runtime_dir` still returns a path in it, as it does for any unsafe folder.
8. Every label the crate sets is explicit, and none is protected. A protected label (`S:P`) needs a privilege the crate's processes don't have enabled. On Windows CI, both levels failed to make a folder with one (error 1314, run 39221106656), and the crate never enables privileges. The key folder's label doesn't inherit, so each object in it carries only its own explicit label. The SDDL tests check that each object has exactly one label. *Changed after slice 3's run.*
9. **Address folders.** Slice 22 settled what the plan leaves open. *Our call (slice 22).*
   - The owner makes its level's address folder as it listens, once it holds the lock, and holds it open, sharing no delete. One it can't make, or one that fails its check (another user's, or labelled at another level), is a listen error, as a socket that can't be bound is on Unix: the owner keeps the lock, and `Claim::listen_error` says why.
   - A launch opens the address folder of the marker's level only to read `instance.pipe`, and checks it first, as it checks the folders above. A missing folder, or one with no `instance.pipe` yet, is an owner not listening yet: the launch looks again until its deadline. One that fails the check gives `Reason::Peer`.
   - The address folders of other levels stay in the instance folder, and the next owner at a level uses its folder again.

## 6. Across Windows levels (slices 20 to 23)

1. **The marker.**
   - The owner locks byte 0, then the byte at its level's RID, retrying for about 100 ms. If the marker still fails, it gives byte 0 back.
   - A launch probes its own RID first, then searches [1, 0x10000) with shared range locks.
   - When several markers are held, the highest wins.
   - Byte 0 held with no marker means the owner is starting: retry until the deadline.

   *Recommended.*

   Slice 20 settled the cases this leaves open. *Our call (slice 20).*
   - Any failure to take the marker gives byte 0 back, an error as well as a timeout. The error then fails the lock, as other lock errors do.
   - Byte 0 is given back with `UnlockFileEx` at once, not left to the handle's close. A launch that takes byte 0 only to see whether it is held gives it back the same way.
   - An untrusted process (RID 0) would mark byte 0, the owning byte, so it never owns: its lock fails at once with an error (`Reason::Lock` from `start`). Slice 33 excludes it before it gets there.
   - When a launch's marker probe finds its own level's byte held, it still searches above it, and a higher marker wins over its own.

   Slice 21 settled what this leaves open for launches. *Our call (slice 21).*
   - A launch reads the marker once it finds byte 0 held, and before it sends anything. `start` reads it before it encodes its request, so nothing is encoded for an owner at another level. `hand_off` encodes its payload first, as before, so a payload that can't be encoded gives `Reason::Encode` before any answer the marker gives. A `Mode::Separate` launch doesn't read it: it never hands off, so until slice 30 it gets `OwnerRunning` at any level. Since slice 30, `exclusive()` doesn't read it either: where it takes the runtime lock, it gets `StateInUse` from it at any level.
   - Byte 0 held with no marker is retried as an owner that isn't listening yet is: past the deadline it gives `Unresponsive`, and after a commit an unconfirmed handoff (6.4). An `instance.lock` gone since byte 0 was found held counts the same, and the next look at the lock decides.
   - A marker that can't be read gives `Reason::Lock`, naming `instance.lock`, as a lock that can't be taken does. After a commit it gives an unconfirmed handoff.
   - A launch that can't read its own level, facing a marker at another, fails closed: it connects as to an owner at its own level, which no pipe's label matches, so it gets `Reason::Peer` and sends nothing. It can't happen yet, since reading the marker needs the launch's own level. From slice 22 such a launch has no address folder to look in either, and `connect` gives `Reason::Peer` before it opens anything. *Our call (slice 22).*
2. A probe at another level is answered from the marker alone, unconfirmed. *Recommended.*
3. `MoreRights` and `OwnerHasMoreRights` don't name the owner's pid, since `instance.lock` stays unwritten. *Recommended.* Slice 17 holds to it when the level comes from HELLO or PRIVILEGE, though the connection gives the pid there, so the reasons, and `probe`'s answer at another level, read the same whichever way the launch learns the level. *Our call (slice 17).*
4. A committed launch whose owner died and that then finds the guard, or a lock at another level, held reports an unconfirmed handoff, never `Alone`. Running alone there would break 0004. *The critic's fix.* From slice 23, one that hands down talks to an owner below it instead, as 1.2 says. *Our call (slice 23).*

## 7. Who may own (slices 32 to 37)

1. `Excluded` applies to `start`, `hand_off`, `probe` and `exclusive`. *Recommended.* It comes first in each, after only `Unsupported`: in `start` before `NoWindows` and the rights reasons, as in `exclusive` (4.7), and in `hand_off` and `probe` before the runtime folder is looked for and before the payload is encoded, so before `Encode`. *Our call (slice 32).*
2. Set-id is a plain comparison of the raw ids. *Recommended.* Slice 4 must show that the SAFER token used by the medium tests isn't restricted, or the medium job would break. Slice 32 settled what this leaves open. *Our call (slice 32).*
   - Only the real and effective ids are compared, not the saved set-ids. A set-id program that has set its effective ids back to its real ones, as with `seteuid(getuid())`, takes part, though it can take its rights back. Comparing the saved ids would need `getresuid` and `getresgid`, which macOS, NetBSD and illumos lack, and would be a change of call.
   - Linux's `AT_SECURE`, which R38 also names, isn't read, so a program given file capabilities takes part.
   - The docs say "a setuid or setgid program that runs with its rights", not "a setuid or setgid program", for the cases above.
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

## 8. Tests and CI (slices 6, 32, 38)

1. CI installs fakeroot and bubblewrap and requires them through `INSTANCE_HANDOFF_REQUIRE_*` variables. For the bwrap tests, it relaxes AppArmor's limit on unprivileged user namespaces. Locally, these tests skip with a message when a tool is missing. *Recommended.* Slice 32 added a launch from a copy of the test binary made setgid to another of the user's groups, which needs no root, so `Excluded { SetId }` is tested end to end after all. The copy goes in the build folder, since `/tmp` may be mounted nosuid. CI requires it on Linux and macOS with `INSTANCE_HANDOFF_REQUIRE_SETGID`. Locally it skips with a message where the user has no other group or the file system ignores set-id bits, as under a build folder in a nosuid `/tmp`. *Our call (slice 32).*

## 9. Scope (slices 39 to 46)

1. `hand_off` and `probe` never return `NoSession`. Without a runtime folder they report `NoOwner`, or `StateInUse` from the guard. Slice 39 goes ahead. *Recommended.* Slice 39 settled what this leaves open. *Our call (slice 39).*
   - Without a runtime folder means `NoSession` or `NoRuntimeDir` from the folder rule, or an instance folder (or `Builder::dir` base) that doesn't exist. So they never return `NoRuntimeDir` either. A folder that exists with nobody holding its lock still gives `NoOwner`, as the plan says, without a look at the guard: an owner that exits lets go of its lock a moment before its guard.
   - They look only where `start` would take the guard: with a state folder, under `Guard::Local`, and not on a network file system or where the file system can't lock files. A missing state folder or guard file, or a path through a file, is free.
   - The look takes the guard for a moment in the mode `start` would take it: shared for a keyed launch, as the plan said, and alone for an unkeyed one (`LOCK_SH` or `LOCK_EX` with `LOCK_NB`, or a shared or exclusive `LockFileEx` on the guard's byte). It gives it back at once (`LOCK_UN`, `UnlockFileEx`), not at close, so a child forked meanwhile keeps nothing. Held in a mode that conflicts, the guard gives `StateInUse`, naming the guard file, so `StateInUse` means what `start` would meet there. A keyed launch gets `StateInUse` beside an unkeyed owner or an exclusive run, and `NoOwner` beside keyed owners, of its own scope in another runtime folder or of another, since `start` would own beside them. An exclusive look for every launch would turn a keyed launch away beside keyed owners of other scopes while its own instance folder is missing, and let it through once that folder exists.
   - The 50 ms guard retry of `start` and `exclusive` (4.5) keeps a look from turning either away. An owner that locks a removed or replaced guard file again (4.6) looks again for 50 ms too before it ends with `LostState`, so a look at the new file doesn't end it. A look held up for longer than that between taking the guard and giving it back, as on a machine too busy to run it, still turns them away; keyed looks never collide with keyed starts.
   - The look only reads. It opens the guard file without making it, and checks neither whose it is nor, on Windows, the state folder's label. One it can't open or lock (a FIFO, a link, `EACCES`) gives `Reason::Lock`, naming it.
   - With the guard held and the instance folder missing, a launch looks for the folder once more: an owner that started there meanwhile made the folder before it took the guard, so the launch goes on to reach it rather than report `StateInUse`.
   - A `start` that may not own looks as `hand_off` does, so with no runtime folder it runs alone with `StateInUse` while the guard is held so that it couldn't own, and with `MayNotOwn` otherwise, never with `NoSession`.
2. `Builder::dir` refusing network volumes and other users' trees waits. Slice 40 is dropped. *Recommended.*
3. macOS keeps its long-path socket fallback for 0.1. Slice 41 is dropped. *Recommended.*
4. `Request::launcher_pid` stays in 0.1, and gives way to `Request::origin` in 0.2. Slice 42 is dropped. *Recommended.* This departs from 0015's consequence "`Mode` and `launcher_pid` go". When 0015 is marked built, that line will say so.
5. The examples use a folder under `HOME` or `LOCALAPPDATA`, with a comment to pass the storage layer's own folder instead. *Recommended.*
6. This release no longer meets `sheaf-instance` builds on the same lock. 0009 and the CHANGELOG say so. *Recommended.*
7. 0001's in-scope bullet gets a pointer to 0015, not a rewrite, following the design README's rule. *Our call.*
8. **Freezing the Windows layout.** The manual run on a machine with UAC on (slice 46) is the gate for 0.1. A second administrator on CI isn't required. Slice 46 needs the maintainer's Windows machine. *Our call.*
