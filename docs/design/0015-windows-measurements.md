# What Windows allowed across integrity levels

Measurements behind [0015](0015-state-keyed-identity.md) and [0012](0012-privilege-levels.md): taken on 2026-10-18 at commit e6863df, on CI on 2026-10-19, and under real UAC with the crate as built on 2026-10-20. The user's SID is shown as `<user>`.

## The two machines

| | GitHub's runner | A machine with UAC on |
|---|---|---|
| Windows | Server 2025 (image windows-2025-vs2026, 20261007.264.1) | 11 Pro 26H2, build 26300.9711 |
| UAC | not applied to this account | `EnableLUA` 1, `ConsentPromptBehaviorAdmin` 5, `PromptOnSecureDesktop` 1 |
| Account | the built-in Administrator (RID 500) | an ordinary administrator (RID 1001) |
| High process | the runner's own token | Run as administrator; Windows `sudo` in its new-window and inline modes |
| Medium process | a SAFER Basic User token | the probe's children: a SAFER token; `lockprobe` and the CLI: the real limited token |

The real full and limited tokens on the UAC machine:

- **Elevated:** `High Mandatory Level` (S-1-16-12288); Administrators `Enabled group, Group owner`.
- **Unelevated:** `Medium Mandatory Level` (S-1-16-8192); Administrators `Group used for deny only`.
- **Windows `sudo`:** gave the elevated token in both modes.

## The probe

`just levels` runs the probe in `tests/levels.rs`. High makes each file and folder; a medium child tries them. For the reverse, the medium child makes `made-by-medium` and holds the state byte and medium's byte, and high tries it. `guard` is a lock file as 0015 proposes: labelled medium, with high holding the state byte (2^31) and high's byte (0x3000).

What high made differed only in its owner:

| Made by high | Runner | UAC on |
|---|---|---|
| Owner of what it makes (token) | `<user>` | Administrators |
| `no-label` | `O:LA` (no label: medium) | `O:BA` (no label: medium) |
| `medium-label` | `O:LAS:AI(ML;;NW;;;ME)` | `O:BAS:AI(ML;;NW;;;ME)` |
| `high-label` | `O:LAS:AI(ML;;NW;;;HI)` | `O:BAS:AI(ML;;NW;;;HI)` |
| `high-label-nr` | `O:LAS:AI(ML;;NWNR;;;HI)` | `O:BAS:AI(ML;;NWNR;;;HI)` |
| `folder-no-label` | `O:LA` (no label: medium) | `O:BA` (no label: medium) |
| `folder-high-label-nr` | `O:LAS:AI(ML;;NWNR;;;HI)` | `O:BAS:AI(ML;;NWNR;;;HI)` |
| `guard` | `O:LAS:AI(ML;;NW;;;ME)` | `O:BAS:AI(ML;;NW;;;ME)` |

What the other level could do was the same on both machines, row for row:

| Try | Result |
|---|---|
| `no-label`: medium opens to read, to write; its exclusive lock | ok, ok, ok |
| `medium-label`: medium opens to read, to write; its exclusive lock | ok, ok, ok |
| `high-label`: medium opens to read, to write; its exclusive lock | ok, access denied, ok |
| `high-label-nr`: medium opens to read, to write | access denied, access denied |
| `guard`: medium opens to read, to write | ok, ok |
| `guard`: medium's exclusive lock on the state byte | lock violation |
| `guard`: medium's shared lock on high's byte | lock violation |
| `guard`: medium's shared lock on medium's byte | ok |
| `folder-no-label`: medium creates a file in it | ok |
| `folder-high-label-nr`: medium creates a file in it | access denied |
| `made-by-medium`: high opens to write | ok |
| `made-by-medium`: high's exclusive lock on the state byte | lock violation |
| `made-by-medium`: high's shared lock on medium's byte | lock violation |
| `made-by-medium`: high's shared lock on high's byte | ok |

## The real limited token

The probe's medium children use a SAFER token, so a throwaway program, `lockprobe`, repeated the lock rows with the real one. Elevated, it made two files in a new folder under `%APPDATA%`, opened each to read and write, and held exclusive one-byte locks on 2^31 and 0x3000:

- `unlabelled.lock`: `O:BA`, no label, and the access list the folder handed down (SYSTEM, Administrators and `<user>`, full control);
- `medium.lock`: `O:BAS:AI(ML;;NW;;;ME)`.

Unelevated, it opened each file once to read and once to read and write, and tried locks with `LockFileEx` and `LOCKFILE_FAIL_IMMEDIATELY`. Both files, through both handles, gave the same results:

| Try | Result |
|---|---|
| open | ok |
| exclusive lock on 2^31 | lock violation (33) |
| shared lock on 0x3000 | lock violation (33) |
| shared lock on 0x2000 | ok |

## The CLI example across real tokens

`examples/cli.rs` (`com.example.notes`) was run with each level's launches from its own shell. Each `add` printed only its own path, so no request crossed a level.

| Owner already running | Then | Result |
|---|---|---|
| medium | `add` from Run as administrator | its own owner, in `run-high` |
| high (Run as administrator), in a fresh app folder | `add` from medium | its own owner, in `run` |
| medium | `add` from `sudo`, new-window mode | its own owner |
| medium | `add` from `sudo`, inline mode, three times | its own owner each time |

In every case, `status` and `stop` from a level reached only that level's owner, and the other owner kept running.

Owners and labels of the folders, from `icacls`:

| Folder | Made at | Owner | Label |
|---|---|---|---|
| `com.example.notes` | medium | `<user>` | none |
| `com.example.notes` | high | Administrators | none |
| `run` | medium | `<user>` | Medium, `(OI)(CI)(NW,NR)` |
| `run-high` | high | Administrators | High, `(OI)(CI)(NW,NR)` |

Each `com.example.notes` had the same explicit access list: `<user>` and SYSTEM, full control. Unelevated, `run-high` couldn't be read at all ("Access is denied").

Inline `sudo` runs the elevated program attached to the terminal that started it:

| Window | Owner ended by | Then |
|---|---|---|
| A | `stop` from high | the window and `sudo` exited, `sudo` with code 0 |
| B | Ctrl+C sent to its console | owner gone within 5 s; the window's `cmd.exe` stayed up |
| C | closing its window | owner gone within 4 s |

After each, `status` from high said "not running", and the medium owner answered throughout.

## The layout, built by hand on CI

On 2026-10-19 the probe in `tests/levels.rs` built 0015's Windows layout by hand on GitHub's runner (image windows-2025-vs2026, 20261007.264.1; runs 39221106656 and 39224197678). It ran at high, and at medium through the SAFER token.

The two tokens:

| | High (the runner) | Medium (SAFER) |
|---|---|---|
| Level | 0x3000 | 0x2000 |
| Elevation type | default, no linked token | default, no linked token |
| Restricted | no; 0 restricting SIDs | no; 0 restricting SIDs |
| AppContainer | no | no |
| Session | 2 | 2 |
| Window station | `WinSta0`, visible | `WinSta0`, visible |

UAC is on (`EnableLUA` 1, `FilterAdministratorToken` not set), but the runner's user is the built-in Administrator, whose token UAC doesn't split. So CI can't make a full, split token.

What each level made, with its label ACEs counted:

| Object | Security as made | Labels |
|---|---|---|
| Key folder, by either level | `D:P(A;OICI;FA;;;<user>)(A;OICI;FA;;;SY)S:(ML;;NWNR;;;ME)` | one: medium, explicit |
| `instance.lock` in it | `D:P(A;;FA;;;<user>)(A;;FA;;;SY)S:(ML;;NWNR;;;ME)` | one: medium, explicit |
| `run` in it, by medium | `S:(ML;OICI;NWNR;;;ME)` | one: medium, explicit |
| `run-high` in it, by high | `S:(ML;OICI;NWNR;;;HI)` | one: high, explicit |
| The key folder with its label protected, `S:P(...)` | not made at either level: error 1314, "A required privilege is not held by the client" | |

Across levels, with the owner holding byte 0 and the byte at its level's RID:

| Try | Medium, in high's key folder | High, in medium's key folder |
|---|---|---|
| Open `instance.lock` to write | ok | ok |
| Exclusive lock on byte 0 | lock violation | lock violation |
| Find the marker with shared range locks | 0x3000, after 33 locks | 0x2000, after 33 locks |
| Make its own level folder | `run`: made | `run-high`: made |
| List the other level's folder | `run-high`: access denied | not tried |

Medium could also open high's key folder. So labels that aren't protected stay single, a folder's label that doesn't inherit reaches none of its children, and each level finds the other's marker. A protected label can't be set by either level, so the layout uses labels that aren't protected (call 5.8 in [docs/impl/0015-calls.md at 042c264](https://github.com/sheaf-pdf/instance-handoff/blob/042c264a21f7b8969bf24d3eacd169532cdc5b6b/docs/impl/0015-calls.md)).

## The built layout under real UAC

On 2026-10-20 the UAC machine above ran the crate as built: main at 046ded6, then branch `finish-0015` at df295f0. Elevated steps ran the built binaries from Run as administrator, and again under `sudo` in inline mode. Each step's output was recorded verbatim.

### The tokens

| | Elevated (Run as administrator, `sudo`) | Unelevated | The probe's medium child | `runas /trustlevel:0x20000` from the elevated shell |
|---|---|---|---|---|
| Level | high (0x3000) | medium | medium (0x2000) | high |
| Administrators | enabled, group owner | deny-only | not enabled | deny-only |
| Elevation type | full, with a linked token | not printed; the crate didn't count it as raised | full, with a linked token | full, as the crate's `Raised` shows |

The probe's medium child is a SAFER Basic User token made from the elevated one and lowered to medium. It keeps the elevation type full. Slice 35 counted every full token as raised, so these children couldn't own, and the maintainer narrowed the rule: a full token is raised only above medium (call 7.5 in [docs/impl/0015-calls.md at 042c264](https://github.com/sheaf-pdf/instance-handoff/blob/042c264a21f7b8969bf24d3eacd169532cdc5b6b/docs/impl/0015-calls.md)). `runas /trustlevel:0x20000` gives no such token from an elevated shell: SAFER keeps the level of the token it starts from, so its launches stay raised.

### The CLI example

`examples/cli.rs` (`com.example.notes`, a headless app) ran with a medium daemon in its own window.

| Launch | Command | Result |
|---|---|---|
| unelevated | `add first` | becomes the daemon, at medium |
| elevated | `status` | `running (pid unknown, medium)`: a reply across levels names no pid (call 6.3) |
| elevated | `add from-admin` | `the daemon (pid unknown, medium) lacks this launch's high integrity`, exit 2. The daemon never got it |
| unelevated | `add second` | delivered |
| unelevated | `migrate` | refused while the daemon holds the notes, exit 2 |
| elevated | `stop` | hands down: `stopped the daemon (pid …, medium) without this launch's high integrity`. The daemon exits with 0 |
| elevated, nothing running | `add raised`, `migrate` | `this launch may not hold the notes, since its rights were raised from a login`, exit 2. Nothing made |
| `runas /trustlevel:0x20000`, nothing running | `add de-elevated` | the same `MayNotOwn` message, exit 2 (at df295f0) |

Under inline `sudo` every step gave the same output and exit code.

What the crate made while the daemon ran, the same seen from either level (`icacls /save`, which keeps labels):

| Object | Owner | Security |
|---|---|---|
| `com.example.notes` (the app's folder) | `<user>` | `D:P(A;OICI;FA;;;<user>)(A;OICI;FA;;;SY)`, no label |
| `i-<hash>` in it | `<user>` | `D:P(A;OICI;FA;;;<user>)(A;OICI;FA;;;SY)S:AI(ML;;NWNR;;;ME)` |
| `i-<hash>\instance.lock` | `<user>` | `D:P(A;;FA;;;<user>)(A;;FA;;;SY)S:AI(ML;;NWNR;;;ME)` |
| `i-<hash>\run` | `<user>` | `D:P(A;OICI;FA;;;<user>)(A;OICI;FA;;;SY)S:AI(ML;OICI;NWNR;;;ME)` |
| `i-<hash>\run\instance.pipe` | `<user>` | `D:(A;;FA;;;<user>)(A;;FA;;;SY)S:AI(ML;ID;NWNR;;;ME)`, its label inherited from `run` |
| `example-notes` (the state folder) | `<user>` | `D:P(A;OICI;FA;;;<user>)(A;OICI;FA;;;SY)`, no label |
| `example-notes\.instance-handoff.lock` | `<user>` | `D:P(A;;FA;;;<user>)(A;;FA;;;SY)S:AI(ML;;NWNR;;;ME)` |

Each object carries at most one label, its own. No raised launch made `run-high` or anything owned by Administrators. After `stop`, only `run\instance.pipe` and the pipe were gone. (`Get-Acl` shows `instance.pipe`'s access entries as inherited, where `icacls /save` doesn't.) A layout from before slice 22, left by the run of 2026-10-18, sat beside it in the app's folder: `run` and `run-high` with their own `instance.lock`. The crate ignores it and never removes it.

### The tests, elevated

At 046ded6, 50 tests failed when run as administrator, each with `MayNotOwn { why: Raised }`: 31 in `tests/handoff.rs`, 11 in `tests/process.rs` and 8 in `tests/levels.rs`. The handoff and process tests assumed they never run raised, which holds on CI, whose built-in Administrator isn't. The levels tests failed through the SAFER children above. At df295f0, with call 7.5 and with the handoff and process tests' owners allowed any rights, every binary passed elevated: 118 unit tests, handoff 32, levels 15 (one ignored) and process 15. `raised_and_not_above_normal_at_high` reached and passed its `MoreRights` and `hand_down` checks. The doctests passed under an elevated `cargo test` at 046ded6.

The probe printed the same rows as on 2026-10-18 and on CI, both times. As before, what high makes is owned by Administrators, and medium can still open high's key folder, make `run` in it, open and write `instance.lock`, find the marker 0x3000 after 33 range locks, and not list `run-high`.

## Not measured

- The probe's rows across levels with the real limited token: only with SAFER. The layout the crate builds was measured with it, through the CLI's daemon.
- `sudo`'s input-closed mode.
- An elevated OpenSSH logon (the UAC machine has no OpenSSH server), and other users.
- A medium token that a real launcher makes from a full one. Only the tests' SAFER children have one.
- AppContainer: only the rule's table in `src/sys/windows.rs`. `tests/levels.rs` runs a launch at low, which gets `Excluded { Sandboxed }`.
- A full, split token on CI.
