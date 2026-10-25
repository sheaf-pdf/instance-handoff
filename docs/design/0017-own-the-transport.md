# 0017. Sockets and pipes directly, not through interprocess

**Status:** Accepted, 2026-10-24, by the maintainer. Nothing to build: the crate already works this way.

## Context

Launches reach the owner over an AF_UNIX socket on Unix and a named pipe on Windows ([0011](0011-windows-named-pipes.md)), written directly on `libc` and `windows-sys`. [interprocess](https://crates.io/crates/interprocess) is a mature crate that wraps both behind one local-socket API, which raised the question of depending on it instead of owning that code.

On 2026-10-24 we read the source of interprocess 2.4.6 against what `src/sys` needs.

## Decision

Keep the transport in `src/sys`, on `libc` and `windows-sys`. Don't depend on interprocess.

## Why

- The transport is a small part of `src/sys`. Outside their tests, `unix.rs` and `windows.rs` are about 5,400 lines. Most of that is the folder rules, the lock and its level markers, the guard, access lists and labels, and the checks on tokens, levels and sandboxes. interprocess has none of it. What it could replace is a few hundred lines.
- It can't express control 6 of [0011](0011-windows-named-pipes.md). Its one client open on Windows (`connect_without_waiting`) passes `FILE_FLAG_OVERLAPPED`, without `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`. The default impersonation level then lets whoever serves the pipe act as the launching user on this machine. The Windows client would have to go around it.
  - On the server side it covers ours: a security descriptor, `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`, the client's pid and impersonation.
- It doesn't fit how the crate runs. The owner serves on one thread, with overlapped I/O on every pipe instance at once, a waker and its upkeep checks, and a launch waits on a read or write only until its deadline. There is no async runtime ([0001](0001-scope.md), [0002](0002-decide-then-serve.md)). interprocess's synchronous pipes either block or use `PIPE_NOWAIT`, which Windows keeps only for LAN Manager compatibility. Its Windows local-socket streams refuse read and write timeouts, and its asynchronous API is tokio's. The crate would keep its own wait loop and overlapped operations, the part most worth handing off.
- On Unix, its listener removes its socket by path when dropped, unless told not to. Removing by path is how a second `sheaf-instance` owner deleted the live owner's socket ([0008](0008-one-folder.md)). The owner here removes the socket only while it holds the lock and the file there is the one it bound, by device and inode. The fallback folder for paths too long for `sun_path`, and the connect with a deadline, would stay ours too. What it would replace is building the socket address and reading the peer's credentials.
- The address is part of the contract between builds ([0009](0009-contract-between-builds.md)), and [0010](0010-lock-primitive.md) already declined to let std choose the lock call. How the pipe and the socket are made and opened shouldn't change with a dependency's minor release.
- Weight isn't the reason. interprocess 2.4.6 uses the same `windows-sys` 0.61, and adds `widestring`, `recvmsg` and `doctest-file`.

## Consequences

- The crate keeps about 210 lines of `unsafe` overlapped I/O on Windows. Each operation is boxed so it never moves, and a cancel waits for the operation to end (`CancelIoEx`, then a waiting `GetOverlappedResult`) before anything is dropped. It passes Windows CI at high and medium integrity.
- Reconsider if the owner moves onto an async runtime, or if the crate gains a second transport.
- The README's "Other crates" keeps interprocess among the building blocks.
