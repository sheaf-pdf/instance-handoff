# Development tasks. CI runs these same recipes, so a local `just ci` checks
# what CI checks.

# The oldest Rust the crate supports, from Cargo.toml.
msrv := `grep -m1 '^rust-version' Cargo.toml | cut -d'"' -f2`

# Platforms checked from here, beyond Linux and Windows: the other Unixes
# the crate supports, and targets where it compiles but can't own.
targets := "x86_64-apple-darwin x86_64-unknown-freebsd x86_64-unknown-netbsd x86_64-unknown-illumos aarch64-linux-android wasm32-unknown-unknown wasm32-wasip1"

# List the recipes.
default:
    @just --list --unsorted

# Everything CI runs on Linux.
ci: fmt clippy test doc windows targets msrv

# Check formatting; `cargo fmt --all` fixes it.
fmt:
    cargo fmt --all -- --check

# Lint the library, tests and examples.
clippy:
    cargo clippy --locked --all-targets --all-features -- -D warnings

# Unit, integration and doc tests.
test:
    cargo test --locked --all-features

# CI's Windows runner is an administrator with UAC off, so `test` runs
# elevated there; this covers an ordinary, unelevated launch.
# Windows only: run the unit and integration tests at medium integrity.
test-medium:
    pwsh -NoProfile -File .github/scripts/test-at-medium.ps1

# The probe in tests/levels.rs reports what a medium process may do with a
# high one's files, folders and locks, and the reverse. Needs an elevated
# process.
# Windows only: probe what each integrity level may do with the other's files.
levels:
    cargo test --locked --all-features --test levels -- --ignored --nocapture

# Build the API docs, failing on warnings.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features

# CI builds and tests on Windows itself; this checks from here that the
# Windows code compiles. Needs `rustup target add x86_64-pc-windows-gnu`.
# Lint the Windows code.
windows:
    cargo clippy --locked --all-targets --all-features --target x86_64-pc-windows-gnu -- -D warnings

# Lint every other platform's code. Needs each target added with rustup.
targets:
    for t in {{ targets }}; do cargo clippy --locked --all-targets --all-features --target $t -- -D warnings || exit 1; done

# Test on the oldest supported Rust, which must be installed.
msrv:
    cargo +{{ msrv }} test --locked --all-features
