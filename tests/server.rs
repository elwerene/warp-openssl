//! Integration tests for TLS server with client certificate authentication.
//!
//! This test suite validates various combinations of client authentication modes
//! and certificate verification behavior using a local TLS server and client.

use reqwest::tls::Version;
use reqwest::{Certificate, ClientBuilder, Identity};
use rstest::*;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::oneshot;
use warp_openssl::Result;
use warp_openssl::{serve, CertificateVerifier};

/// A certificate verifier that always accepts certificates.
///
/// Used in tests to validate successful authentication flows.
struct ValidCertVerifier {}

impl CertificateVerifier for ValidCertVerifier {
    fn verify_certificate(
        &self,
        certificate: &warp_openssl::Certificate,
    ) -> warp_openssl::Result<()> {
        tracing::info!("Valid certificate {:?}", certificate);
        Result::Ok(())
    }
}

/// A certificate verifier that always rejects certificates.
///
/// Used in tests to validate error handling and rejection flows.
struct InValidCertVerifier {}

impl CertificateVerifier for InValidCertVerifier {
    fn verify_certificate(
        &self,
        certificate: &warp_openssl::Certificate,
    ) -> warp_openssl::Result<()> {
        tracing::info!("Invalid certificate {:?}", certificate);
        Result::Err("Invalid certificate".into())
    }
}

/// Specifies the client authentication mode for the TLS server.
enum AuthType {
    /// No client authentication required.
    Off,
    /// Client authentication is mandatory; connections without valid client certificates are rejected.
    Required,
    /// Client authentication is optional; certificates are verified if provided.
    Optional,
}

/// Specifies the certificate verification behavior.
enum VeriferType {
    /// Certificates are always accepted as valid.
    Valid,
    /// Certificates are always rejected as invalid.
    Invalid,
}

/// Comprehensive integration test for TLS client authentication scenarios.
///
/// This test validates the interaction between:
/// - Server authentication mode (off, optional, required)
/// - Certificate verifier behavior (accept, reject)
/// - Client certificate presentation (with/without certificate)
/// - Expected outcomes (success, failure)
///
/// # Test Cases
///
/// - `client_auth_off_*`: Server doesn't require authentication, should always succeed
/// - `client_auth_optional_noclient_*`: Optional auth without client cert should succeed
/// - `client_auth_optional_client_invalid_failure`: Optional auth with invalid cert should fail
/// - `client_auth_optional_client_valid_success`: Optional auth with valid cert should succeed
/// - `client_auth_required_noclient_*`: Required auth without client cert should fail
/// - `client_auth_required_client_valid_success`: Required auth with valid cert should succeed
/// - `client_auth_required_client_invalid_*`: Required auth with invalid cert should fail
///
/// # Parameters
///
/// * `auth_type` - The authentication mode for the server
/// * `verifier_type` - The certificate verification behavior
/// * `use_client_auth` - Whether the client should present a certificate
/// * `expect_error` - Whether the connection should fail
///
/// # Testing Strategy
///
/// Each test case:
/// 1. Starts a local TLS server with specified authentication settings
/// 2. Configures a client with optional certificate
/// 3. Tests both TLS 1.2 and TLS 1.3 protocols
/// 4. Validates the expected success/failure outcome
#[rstest]
#[case::client_auth_off_invalid_success(AuthType::Off, VeriferType::Invalid, false, false)]
#[case::client_auth_off_valid_success(AuthType::Off, VeriferType::Valid, false, false)]
#[case::client_auth_optional_noclient_invalid_success(
    AuthType::Optional,
    VeriferType::Invalid,
    false,
    false
)]
#[case::client_auth_optional_client_invalid_failure(
    AuthType::Optional,
    VeriferType::Invalid,
    true,
    true
)]
#[case::client_auth_optional_client_valid_success(
    AuthType::Optional,
    VeriferType::Valid,
    true,
    false
)]
#[case::client_auth_required_noclient_valid_failure(
    AuthType::Required,
    VeriferType::Valid,
    false,
    true
)]
#[case::client_auth_required_client_valid_success(
    AuthType::Required,
    VeriferType::Valid,
    true,
    false
)]
#[case::client_auth_required_client_invalid_success(
    AuthType::Required,
    VeriferType::Invalid,
    true,
    true
)]
#[tokio::test]
async fn client_tests(
    #[case] auth_type: AuthType,
    #[case] verifier_type: VeriferType,
    #[case] use_client_auth: bool,
    #[case] expect_error: bool,
) -> Result<()> {
    let _ = env_logger::try_init();
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ca_cert = include_bytes!("../certs/ca.crt").to_vec();

    let mut host_cert = include_bytes!("../certs/localhost.crt").to_vec();
    host_cert.extend(ca_cert.clone());

    let intermediate_cert = include_bytes!("../certs/intermediate.crt").to_vec();

    let (tx, rx) = oneshot::channel::<()>();

    let server = serve(warp::Filter::map(
        warp::Filter::and(warp::any(), warp::filters::ext::optional()),
        move |cert: Option<warp_openssl::Certificate>| {
            assert!(!use_client_auth || cert.is_some());
            tracing::info!("Returning hello world");
            "Hello, World!"
        },
    ))
    .key(include_bytes!("../certs/localhost.key"))
    .cert(host_cert);

    let server = match auth_type {
        AuthType::Off => server,
        AuthType::Required => match verifier_type {
            VeriferType::Valid => server
                .client_auth_required(intermediate_cert.clone(), Arc::new(ValidCertVerifier {})),
            VeriferType::Invalid => server
                .client_auth_required(intermediate_cert.clone(), Arc::new(InValidCertVerifier {})),
        },
        AuthType::Optional => match verifier_type {
            VeriferType::Valid => server
                .client_auth_optional(intermediate_cert.clone(), Arc::new(ValidCertVerifier {})),
            VeriferType::Invalid => server
                .client_auth_optional(intermediate_cert.clone(), Arc::new(InValidCertVerifier {})),
        },
    };

    let (addr, server) = server.bind_with_graceful_shutdown(addr, async move {
        rx.await.ok();
    })?;

    let server = tokio::spawn(async move {
        server.await;
    });

    let crt = include_bytes!("../certs/client.crt").to_vec();
    let key = include_bytes!("../certs/client.key").to_vec();
    let identity = Identity::from_pem(&[key, crt].concat())?;

    let trust_root = Certificate::from_pem(&ca_cert).unwrap();

    for version in [Version::TLS_1_2, Version::TLS_1_3] {
        println!("Testing with version: {:?}", version);

        let builder = ClientBuilder::new()
            .tls_backend_rustls()
            .min_tls_version(version)
            .add_root_certificate(trust_root.clone())
            .danger_accept_invalid_certs(true);

        let builder = if use_client_auth {
            builder.identity(identity.clone())
        } else {
            builder
        };

        let client = builder.build()?;
        let res = client
            .get(format!("https://localhost:{}", addr.port()))
            .send()
            .await;

        println!("Response: {:?}", res);

        if let Ok(ref res) = res {
            assert!(!expect_error);
            assert_eq!(res.status(), 200);
        } else {
            assert!(expect_error);
        }
    }

    tx.send(()).unwrap();
    server.await.unwrap();

    Ok(())
}
