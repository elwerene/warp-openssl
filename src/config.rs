use std::{
    env, fmt,
    fs::File,
    io::{self, Cursor, Read, Write},
    sync::{Arc, Mutex},
};

use openssl::{
    pkey::PKey,
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVerifyMode},
    x509::{
        store::{HashDir, X509Lookup, X509LookupRef, X509Store, X509StoreBuilder},
        verify::X509VerifyFlags,
        X509,
    },
};

use crate::{certificate::CertificateVerifier, server::TlsLevel};

pub(crate) struct SslConfig {
    pub(crate) acceptor: SslAcceptor,
    pub(crate) certificate_verifier: Option<Arc<dyn CertificateVerifier>>,
}

/// Represents errors that can occur building the TlsConfig
#[derive(Debug)]
pub(crate) enum TlsConfigError {
    Io(io::Error),
    /// An error from an empty key
    EmptyKey,
    /// No public certificate was found
    EmptyCert,
    /// An error from openssl
    OpensslError(::openssl::error::ErrorStack),
}

impl fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsConfigError::Io(err) => err.fmt(f),
            TlsConfigError::EmptyKey => write!(f, "key contains no private key"),
            TlsConfigError::EmptyCert => write!(f, "no public certificate found"),
            TlsConfigError::OpensslError(err) => write!(f, "Openssl failed, {}", err),
        }
    }
}

impl std::error::Error for TlsConfigError {}

/// Tls client authentication configuration.
#[derive(Debug)]
pub(crate) enum TlsClientAuth {
    /// No client auth.
    Off,
    /// Allow any anonymous or verification passing authenticated client with the given trust anchors.
    Optional((Vec<u8>, Arc<dyn CertificateVerifier>)),
    /// Allow any verification passing authenticated client with the given trust anchors.
    Required((Vec<u8>, Arc<dyn CertificateVerifier>)),
}

pub type LookupFileFn = Box<dyn FnOnce(&mut X509LookupRef<openssl::x509::store::File>)>;
pub type LookupHashDirFn = Box<dyn FnOnce(&mut X509LookupRef<HashDir>)>;

pub enum Lookup {
    File(LookupFileFn),
    HashDir(LookupHashDirFn),
}

pub type AddLookups = Vec<Lookup>;

/// Builder to set the configuration for the Tls server.
pub(crate) struct TlsConfigBuilder {
    cert: Box<dyn Read + Send + Sync>,
    key: Box<dyn Read + Send + Sync>,
    client_auth: TlsClientAuth,
    partial_chain_verification: bool,
    tls_level: TlsLevel,
    add_lookups: AddLookups,
}

impl fmt::Debug for TlsConfigBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfigBuilder")
            .field("client_auth", &self.client_auth)
            .finish()
    }
}

impl TlsConfigBuilder {
    pub(crate) fn new() -> TlsConfigBuilder {
        TlsConfigBuilder {
            key: Box::new(io::empty()),
            cert: Box::new(io::empty()),
            client_auth: TlsClientAuth::Off,
            partial_chain_verification: true,
            tls_level: TlsLevel::MozillaIntermediateV5,
            add_lookups: vec![],
        }
    }

    pub(crate) fn key(mut self, key: &[u8]) -> Self {
        self.key = Box::new(Cursor::new(Vec::from(key)));
        self
    }

    pub(crate) fn cert(mut self, cert: &[u8]) -> Self {
        self.cert = Box::new(Cursor::new(Vec::from(cert)));
        self
    }

    pub(crate) fn tls_level(mut self, tls_level: TlsLevel) -> Self {
        self.tls_level = tls_level;
        self
    }

    pub(crate) fn client_auth_optional(
        mut self,
        trust_anchor: &[u8],
        certificate_verifier: Arc<dyn CertificateVerifier>,
    ) -> Self {
        self.client_auth = TlsClientAuth::Optional((Vec::from(trust_anchor), certificate_verifier));
        self
    }

    pub(crate) fn client_auth_required(
        mut self,
        trust_anchor: &[u8],
        certificate_verifier: Arc<dyn CertificateVerifier>,
    ) -> Self {
        self.client_auth = TlsClientAuth::Required((Vec::from(trust_anchor), certificate_verifier));
        self
    }

    pub(crate) fn disable_partial_chain_verification(mut self) -> Self {
        self.partial_chain_verification = false;
        self
    }

    pub(crate) fn add_file_lookup(mut self, lookup: LookupFileFn) -> Self {
        self.add_lookups.push(Lookup::File(lookup));
        self
    }

    pub(crate) fn add_hash_dir_lookup(mut self, lookup: LookupHashDirFn) -> Self {
        self.add_lookups.push(Lookup::HashDir(lookup));
        self
    }
}

impl TlsConfigBuilder {
    fn configure_certs(
        mut key: Box<dyn Read + Send + Sync>,
        mut cert: Box<dyn Read + Send + Sync>,
        tls_level: TlsLevel,
    ) -> std::result::Result<SslAcceptorBuilder, TlsConfigError> {
        let mut key_vec = Vec::new();
        key.read_to_end(&mut key_vec).map_err(TlsConfigError::Io)?;

        if key_vec.is_empty() {
            return Err(TlsConfigError::EmptyKey);
        }

        let private_key =
            PKey::private_key_from_pem(&key_vec).map_err(TlsConfigError::OpensslError)?;

        let mut cert_vec = Vec::new();
        cert.read_to_end(&mut cert_vec)
            .map_err(TlsConfigError::Io)?;

        let mut cert_chain = X509::stack_from_pem(&cert_vec)
            .map_err(TlsConfigError::OpensslError)?
            .into_iter();
        let cert = cert_chain.next().ok_or(TlsConfigError::EmptyCert)?;
        let chain: Vec<_> = cert_chain.collect();
        let acceptor = match tls_level {
            TlsLevel::MozillaModern => SslAcceptor::mozilla_modern(SslMethod::tls_server()),
            TlsLevel::MozillaModernV5 => SslAcceptor::mozilla_modern_v5(SslMethod::tls_server()),
            TlsLevel::MozillaIntermediate => {
                SslAcceptor::mozilla_intermediate(SslMethod::tls_server())
            }
            TlsLevel::MozillaIntermediateV5 => {
                SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
            }
        };

        let mut acceptor = acceptor.map_err(TlsConfigError::OpensslError)?;
        acceptor
            .set_private_key(&private_key)
            .map_err(TlsConfigError::OpensslError)?;
        acceptor
            .set_certificate(&cert)
            .map_err(TlsConfigError::OpensslError)?;

        for cert in chain.iter() {
            acceptor
                .add_extra_chain_cert(cert.to_owned())
                .map_err(TlsConfigError::OpensslError)?;
        }

        Ok(acceptor)
    }

    pub(crate) fn build(self) -> std::result::Result<SslConfig, TlsConfigError> {
        let mut acceptor = TlsConfigBuilder::configure_certs(self.key, self.cert, self.tls_level)?;

        acceptor
            .set_alpn_protos(b"\x02h2\x08http/1.1")
            .map_err(TlsConfigError::OpensslError)?;

        fn read_trust_anchor(
            mut trust_anchor: &[u8],
            partial_chain_verification: bool,
            add_lookups: AddLookups,
        ) -> std::result::Result<X509Store, TlsConfigError> {
            let mut cert_vec = Vec::new();
            trust_anchor
                .read_to_end(&mut cert_vec)
                .map_err(TlsConfigError::Io)?;

            let certs = X509::stack_from_pem(&cert_vec).map_err(TlsConfigError::OpensslError)?;
            let mut store = X509StoreBuilder::new().map_err(TlsConfigError::OpensslError)?;

            for cert in certs.into_iter() {
                store.add_cert(cert).map_err(TlsConfigError::OpensslError)?;
            }

            let set_csr_check_flag = !add_lookups.is_empty();
            for lookup in add_lookups.into_iter() {
                match lookup {
                    Lookup::File(lookup_file_fn) => {
                        let lookup = store
                            .add_lookup(X509Lookup::file())
                            .map_err(TlsConfigError::OpensslError)?;
                        lookup_file_fn(lookup);
                    }
                    Lookup::HashDir(lookup_hash_dir_fn) => {
                        let lookup = store
                            .add_lookup(X509Lookup::hash_dir())
                            .map_err(TlsConfigError::OpensslError)?;
                        lookup_hash_dir_fn(lookup);
                    }
                };
            }

            let mut flags = X509VerifyFlags::empty();

            if partial_chain_verification {
                flags.insert(X509VerifyFlags::PARTIAL_CHAIN);
            }

            if set_csr_check_flag {
                flags.insert(X509VerifyFlags::CRL_CHECK);
                flags.insert(X509VerifyFlags::CRL_CHECK_ALL);
            }

            if flags != X509VerifyFlags::empty() {
                store
                    .set_flags(flags)
                    .map_err(TlsConfigError::OpensslError)?;
            }

            Ok(store.build())
        }

        let certificate_validator = match self.client_auth {
            TlsClientAuth::Off => {
                acceptor.set_verify(SslVerifyMode::NONE);
                None
            }
            TlsClientAuth::Optional((trust_anchor, certificate_valiator)) => {
                let store = read_trust_anchor(
                    &trust_anchor,
                    self.partial_chain_verification,
                    self.add_lookups,
                )?;
                acceptor.set_verify(SslVerifyMode::PEER);
                acceptor
                    .set_verify_cert_store(store)
                    .map_err(TlsConfigError::OpensslError)?;
                Some(certificate_valiator)
            }
            TlsClientAuth::Required((trust_anchor, certificate_validator)) => {
                let store = read_trust_anchor(
                    &trust_anchor,
                    self.partial_chain_verification,
                    self.add_lookups,
                )?;
                acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
                acceptor
                    .set_verify_cert_store(store)
                    .map_err(TlsConfigError::OpensslError)?;
                Some(certificate_validator)
            }
        };

        // Required to avoid "session id context uninitialized" errors when
        // clients attempt TLS session resumption.
        acceptor
            .set_session_id_context(b"warp-openssl")
            .map_err(TlsConfigError::OpensslError)?;

        if let Ok(filename) = env::var("SSLKEYLOGFILE") {
            let file = Mutex::new(File::create(filename).map_err(TlsConfigError::Io)?);

            acceptor.set_keylog_callback(move |_ssl, line| {
                let mut file = file.lock().unwrap();
                let _ = writeln!(&mut file, "{}", line);
            });
        };

        Ok(SslConfig {
            acceptor: acceptor.build(),
            certificate_verifier: certificate_validator,
        })
    }
}
