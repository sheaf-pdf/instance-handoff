# Development tasks. CI runs these same recipes, so a local `just ci` checks
# what CI checks.

# The oldest Rust the crate supports, from Cargo.toml.
msrv := `grep -m1 '^rust-version' Cargo.toml | cut -d'"' -f2`

# List the recipes.
default:
    @just --list --unsorted

# Everything CI runs on Linux.
ci: fmt clippy test doc windows msrv

# Check formatting; `cargo fmt --all` fixes it.
fmt:
    cargo fmt --all -- --check

# Lint the library and tests.
clippy:
    cargo clippy --locked --all-targets -- -D warnings

# The tests use Unix sockets, so on Windows they compile but don't run.
# Unit tests and doctests.
test:
    cargo test --locked

# Build the API docs, failing on warnings.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps

# CI builds and tests on Windows itself; this checks from here that the
# Windows code compiles. Needs `rustup target add x86_64-pc-windows-gnu`.
# Lint the Windows code.
windows:
    cargo clippy --locked --all-targets --target x86_64-pc-windows-gnu -- -D warnings

# Test on the oldest supported Rust, which must be installed.
msrv:
    cargo +{{ msrv }} test --locked
