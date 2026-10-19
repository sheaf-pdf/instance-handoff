# What Windows allowed across integrity levels

Measurements behind [0015](0015-state-keyed-identity.md) and [0012](0012-privilege-levels.md), taken on 2026-10-18 at commit e6863df. The user's SID is shown as `<user>`.

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

## Not measured

- The probe's folder rows, and the reverse direction, with the real limited token (only with SAFER).
- `sudo`'s input-closed mode.
- Elevated SSH, other users, low integrity and AppContainer.
- 0015's layout itself, which isn't built. These are the facts it would rest on.
