# Copilot Instructions for warp-openssl

## Overview

warp-openssl is a Rust crate that adds OpenSSL-based TLS support to [warp](https://docs.rs/warp) (which dropped built-in TLS in v0.4). It provides a drop-in `serve()` function that replaces warp's, with a builder API for configuring certificates, client authentication, and TLS levels.

## Build & Test

```bash
# Generate test certificates (required before first build/test)
cd certs && ./gencerts.sh

# Build
cargo build

# Build with vendored OpenSSL (no system OpenSSL required)
cargo build --features openssl-vendored

# Run all tests
cargo test

# Run a specific test case
cargo test client_auth_required_client_valid_success
```

Tests require the certificates in `certs/` to be generated first. CI does this automatically.

## Architecture

The crate is structured as a layered TLS server pipeline:

- **`server.rs`** — Public API. `serve()` creates an `OpensslServer<F>` builder. The builder configures TLS via `TlsConfigBuilder` and binds to an address, spawning a tokio task that accepts connections through `AddrIncoming` → `TlsStream` → hyper `auto::Builder`.
- **`config.rs`** — `TlsConfigBuilder` assembles the OpenSSL `SslAcceptor` from cert/key/client-auth settings. Supports Mozilla TLS security levels (default: `MozillaIntermediateV5`), CRL lookups, and `SSLKEYLOGFILE` for Wireshark debugging.
- **`stream.rs`** — `TlsStream` wraps `tokio_openssl::SslStream` and implements `hyper::rt::Read/Write`. Handles a two-phase state machine: `Handshaking` → `Streaming`, running the `CertificateVerifier` callback after handshake completion.
- **`certificate.rs`** — `Certificate` type extracts CN/OU/L from the peer X509. The `CertificateVerifier` trait is the extension point for custom client cert validation.
- **`acceptor.rs`** — Thin `SslConfig` struct holding the built `SslAcceptor` and optional verifier.

## Key Conventions

- **Builder pattern** — `OpensslServer` uses a consuming builder (`self` not `&mut self`), chaining through `with_tls()` which destructures and reconstructs the struct.
- **Client certificates via warp extensions** — Peer certificates are injected into hyper request extensions, accessible in warp filters via `warp::filters::ext::optional::<Certificate>()`.
- **Graceful shutdown** — Uses `tokio_util::CancellationToken` propagated to both the accept loop and individual connections.
- **Test certificates** — Integration tests use `include_bytes!` to embed certs from `certs/`. The test cert hierarchy is: CA → intermediate → localhost/client.
- **rstest parametrized tests** — Tests use `rstest` with `#[case]` attributes to cover the matrix of auth modes (off/optional/required) × verifier results (valid/invalid) × client cert presence.
- **Lint attributes** — The crate enforces `#![deny(missing_docs)]` and `#![deny(missing_debug_implementations)]` — all public items must have doc comments and `Debug` impls.
- **Error type** — Uses a boxed error alias: `type Error = Box<dyn std::error::Error + Send + Sync + 'static>`.
- **Deprecated API migration** — `common_name()` and `organizational_unit()` are deprecated in favor of their plural forms (`common_names()`, `organizational_units()`).

## Rust Coding Standards

Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) and these practices:

### Formatting & Linting

- Run `cargo fmt` before committing — all code must conform to the default `rustfmt` style.
- Run `cargo clippy -- -D warnings` and fix all warnings. Treat clippy lints as errors.
- Prefer `#[allow(clippy::...)]` with a justification comment over blanket suppression if a lint must be silenced.

### Error Handling

- Use `Result<T, E>` for fallible operations; never `panic!` or `unwrap()` in library code.
- `unwrap()` and `expect()` are acceptable only in tests and examples.
- Prefer `?` operator for error propagation over explicit `match` on `Result`.
- Error types should implement `std::error::Error`, `Display`, and `Debug`.
- Use `thiserror` for library error enums or manual `impl` as done in this crate's `TlsConfigError`.

### Safety & Unsafe

- Avoid `unsafe` unless absolutely necessary (e.g., FFI boundaries with OpenSSL).
- Every `unsafe` block must have a `// SAFETY:` comment explaining why the invariants are upheld.
- Minimize the scope of `unsafe` blocks — extract safe wrappers.

### API Design

- Use the **builder pattern** with consuming `self` methods for configuration structs (as this crate does with `OpensslServer`).
- Accept generic inputs: prefer `impl AsRef<[u8]>` or `impl Into<T>` over concrete types in public APIs.
- Implement common traits eagerly on public types: `Debug`, `Clone`, `Send`, `Sync` where applicable.
- Use `#[must_use]` on types/functions where ignoring the return value is likely a bug.
- Mark types `#[non_exhaustive]` if they may gain variants/fields in future versions.

### Async & Concurrency

- Use `tokio` as the async runtime (this crate's standard).
- Prefer `tokio::select!` for multiplexing futures; use `CancellationToken` for shutdown signaling.
- Avoid holding `Mutex` guards across `.await` points — use `tokio::sync::Mutex` if a lock must span awaits.
- Ensure types are `Send + Sync` when used across task boundaries.

### Documentation

- All public items must have doc comments (`///`) — enforced by `#![deny(missing_docs)]`.
- Include usage examples in doc comments for public functions and types.
- Use `# Errors`, `# Panics`, and `# Safety` sections in doc comments where applicable.
- Link to relevant external docs (e.g., OpenSSL, warp) with `[text](url)` in doc comments.

### Dependencies

- Keep the dependency tree minimal. Justify each new dependency.
- Pin major versions in `Cargo.toml` (e.g., `"0.10"` not `"*"`).
- Use feature flags to keep optional functionality behind gates (e.g., `openssl-vendored`).
