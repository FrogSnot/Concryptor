# Contributing to Concryptor

Thank you for your interest in contributing! This document covers how to build,
test, and submit changes.

## Getting Started

```bash
# Clone the repository
git clone https://github.com/FrogSnot/Concryptor
cd Concryptor

# Build (debug)
cargo build

# Build (optimised release)
cargo build --release
```

## Running Tests

```bash
# Full test suite (67 tests)
cargo test --all

# A specific test
cargo test header::tests::test_name
```

## Running Benchmarks

```bash
# All benchmarks (HTML reports written to target/criterion/)
cargo bench

# Filter by name
cargo bench -- "encrypt/AES"
cargo bench -- "chunk_sweep"
```

## Code Style

Before submitting, please make sure your code:

1. **Formats cleanly** `cargo fmt --all`
2. **Passes Clippy** `cargo clippy --all -- -D warnings`
3. **All tests pass** `cargo test --all`

## Submitting Changes

1. Fork the repository and create a branch from `main`.
2. Make your changes with clear, atomic commits.
3. Ensure all of the above checks pass.
4. Open a pull request against `main` with a description of the change and why.

## Security Vulnerabilities

Do **not** open a public issue for security vulnerabilities. Please follow the
process described in [SECURITY.md](SECURITY.md).
