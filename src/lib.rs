#![doc(html_root_url = "https://docs.rs/warp-openssl")]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![cfg_attr(test, deny(warnings))]

//! # warp-openssl
//!
//! warp-openssl adds OpenSSL-backed TLS support to [warp](https://docs.rs/warp).
//!
//! `warp` 0.4 no longer ships a built-in TLS server, so this crate provides a drop-in
//! [`serve`](crate::serve) function with a builder API for configuring certificates,
//! TLS levels, and optional or required client authentication.
//!
//! So the following example:
//! ```ignore
//!  use warp::serve;
//!
//!  let server = serve(warp::Filter::map(warp::any(), || "Hello, World!"));
//! ```
//!
//! would convert to:
//!
//! ```
//!  use warp_openssl::serve;
//!
//!  let cert = vec![]; // certificate to use
//!  let key = vec![]; // private key for the certificate
//!  let server = serve(warp::Filter::map(warp::any(), || "Hello, World!"))
//!     .key(key)
//!     .cert(cert);
//! ```
//!
//! There is additional support for SSL key logging file to enable viewing network traffic in wireshark.
//! Just set the SSLKEYLOGFILE environment variable to the path of the file you want to use
//! and the key log gets generated to that file.
//!
//! If client authentication is enabled, the peer certificate is injected into the request
//! extensions and can be accessed in a filter with
//! `warp::filters::ext::optional::<warp_openssl::Certificate>()`:
//!
//!  ```
//!  use std::sync::Arc;
//!
//!  use warp_openssl::{Certificate, CertificateVerifier, serve};
//!
//!  let cert = vec![]; // certificate to use
//!  let key = vec![]; // private key for the certificate
//!  let trust_anchor = vec![]; // certificate authority for client certs
//!
//!  #[derive(Debug)]
//!  struct AllowAllVerifier;
//!
//!  impl CertificateVerifier for AllowAllVerifier {
//!      fn verify_certificate(&self, _: &Certificate) -> warp_openssl::Result<()> {
//!          Ok(())
//!      }
//!  }
//!
//!  let server = serve(warp::Filter::map(
//!     warp::Filter::and(warp::any(), warp::filters::ext::optional()),
//!     |_cert: Option<warp_openssl::Certificate>| "Hello, World!"
//!  ))
//!  .key(key)
//!  .cert(cert)
//!  .client_auth_optional(trust_anchor, Arc::new(AllowAllVerifier));
//! ```

#[doc(hidden)]
pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
#[doc(hidden)]
pub type Result<T> = std::result::Result<T, Error>;

mod certificate;
mod config;
mod server;
mod stream;

pub use certificate::{Certificate, CertificateVerifier};
pub use server::{serve, OpensslServer, TlsLevel};
