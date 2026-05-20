use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::certificate::{Certificate, CertificateVerifier};
use crate::config::{LookupFileFn, LookupHashDirFn, SslConfig, TlsConfigBuilder};
use crate::stream::{CloneableStream, TlsStream};
use crate::Result;

use futures_util::{Future, TryFuture};

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;

use tokio::net::TcpListener;
use warp::{Filter, Reply};

/// Create an `OpensslServer` with the provided `Filter`.
pub fn serve<F>(filter: F) -> OpensslServer<F> {
    OpensslServer {
        filter,
        tls: TlsConfigBuilder::new(),
    }
}

/// Settings corresponding to TLS level based on Mozilla's server side TLS recommendations.
/// See its [documentation][docs] for more details on specifics.
///
/// [docs]: https://wiki.mozilla.org/Security/Server_Side_TLS
#[derive(Debug, Clone)]
pub enum TlsLevel {
    /// Settings corresponding to modern configuration of version 4 of Mozilla's server side TLS
    /// recommendations
    MozillaModern,
    /// Settings corresponding to modern configuration of version 5 of Mozilla's server side TLS
    /// recommendations
    MozillaModernV5,
    /// Settings corresponding to the intermediate configuration of version 4 of Mozilla's server side TLS
    /// recommendations
    MozillaIntermediate,
    /// Settings corresponding to the intermediate configuration of version 5 of Mozilla's server side TLS
    /// recommendations
    MozillaIntermediateV5,
}

/// Create an openssl based TLS warp server with the provided filter.
///
#[derive(Debug)]
pub struct OpensslServer<F> {
    filter: F,
    tls: TlsConfigBuilder,
}

impl<F> OpensslServer<F>
where
    F: Filter + Clone + Send + Sync + 'static,
    <F::Future as TryFuture>::Ok: Reply,
{
    /// Specify the in-memory contents of the private key.
    ///
    pub fn key(self, key: impl AsRef<[u8]>) -> Self {
        self.with_tls(|tls| tls.key(key.as_ref()))
    }

    /// Specify the tls level based on Mozilla's server side TLS recommendations.
    /// See its [documentation][docs] for more details on specifics.
    ///
    /// Defaults to `TlsLevel::MozillaIntermediateV5`.
    ///
    /// [docs]: https://wiki.mozilla.org/Security/Server_Side_TLS
    pub fn tls_level(self, tls_level: TlsLevel) -> Self {
        self.with_tls(|tls| tls.tls_level(tls_level))
    }

    /// Specify the in-memory contents of the certificate.
    ///
    pub fn cert(self, cert: impl AsRef<[u8]>) -> Self {
        self.with_tls(|tls| tls.cert(cert.as_ref()))
    }

    /// Add file loop callback that loads all the certificates or CRLs present in a file into memory at the time the file is added as a lookup source.
    /// See [`openssl::x509::X509Lookup::file`] for more details.
    ///
    pub fn add_file_lookup(self, lookup: LookupFileFn) -> Self {
        self.with_tls(|tls| tls.add_file_lookup(lookup))
    }

    /// Add hash dir lookup callback that loads certificates and CRLs on demand and caches them in memory once they are loaded.
    /// See [`openssl::x509::X509Lookup::hash_dir`] for more details.
    ///
    pub fn add_hash_dir_lookup(self, lookup: LookupHashDirFn) -> Self {
        self.with_tls(|tls| tls.add_hash_dir_lookup(lookup))
    }

    /// Specify the in-memory contents of the trust anchor for optional client authentication.
    ///
    /// Anonymous clients will be accepted by default
    /// Non anonymous clients passing CertificateVerifier and having a valid certificate chain will be accepted.
    ///
    pub fn client_auth_optional(
        self,
        trust_anchor: impl AsRef<[u8]>,
        certificate_verifier: Arc<dyn CertificateVerifier>,
    ) -> Self {
        self.with_tls(|tls| tls.client_auth_optional(trust_anchor.as_ref(), certificate_verifier))
    }

    /// Specify the in-memory contents of the trust anchor for required client authentication.
    /// Only clients passing CertificateVerifier and having a valid certificate chain will be accepted.
    ///
    pub fn client_auth_required(
        self,
        trust_anchor: impl AsRef<[u8]>,
        certificate_verifier: Arc<dyn CertificateVerifier>,
    ) -> Self {
        self.with_tls(|tls| tls.client_auth_required(trust_anchor.as_ref(), certificate_verifier))
    }

    /// **Not recommended** Disables partial certificate chain verification.
    ///
    /// For certificate pinning to work properly its enough to validate that
    /// the certificate chains to an anchor in the trust store. This is the default behavior.
    ///
    pub fn disable_partial_chain_verification(self) -> Self {
        self.with_tls(|tls| tls.disable_partial_chain_verification())
    }

    fn with_tls<Func>(self, func: Func) -> Self
    where
        Func: FnOnce(TlsConfigBuilder) -> TlsConfigBuilder,
    {
        let OpensslServer { filter, tls } = self;
        let tls = func(tls);
        OpensslServer { filter, tls }
    }

    fn build_server(
        self,
        addr: impl Into<SocketAddr>,
    ) -> Result<(SocketAddr, TcpListener, SslConfig, F)> {
        let ssl_config = self.tls.build()?;
        let addr = addr.into();
        let std_listener = std::net::TcpListener::bind(addr)?;
        std_listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(std_listener)?;
        let local_addr = listener.local_addr()?;
        Ok((local_addr, listener, ssl_config, self.filter))
    }

    /// Create a tls server bound to a specific port.
    ///
    pub fn bind(
        self,
        addr: impl Into<SocketAddr>,
    ) -> Result<(SocketAddr, impl Future<Output = ()> + 'static)> {
        let (addr, listener, ssl_config, filter) = self.build_server(addr)?;
        let ssl_config = Arc::new(ssl_config);

        let srv = async move {
            let builder = auto::Builder::new(TokioExecutor::new());
            loop {
                let (tcp_stream, remote_addr) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::error!("accept error: {}", e);
                        continue;
                    }
                };

                if let Err(e) = tcp_stream.set_nodelay(true) {
                    tracing::warn!("set_nodelay failed for {}: {}", remote_addr, e);
                }

                let ssl_config = ssl_config.clone();
                let filter = filter.clone();
                let builder = builder.clone();

                tokio::spawn(async move {
                    if let Err(e) =
                        serve_connection(tcp_stream, &ssl_config, filter, &builder).await
                    {
                        tracing::error!("connection error: {}", e);
                    }
                });
            }
        };

        Ok((addr, srv))
    }

    /// Create a tls server bound to a specific port with graceful shutdown signal.
    ///
    /// When the signal completes, the server will start the graceful shutdown
    /// process.
    ///
    pub fn bind_with_graceful_shutdown(
        self,
        addr: impl Into<SocketAddr>,
        signal: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(SocketAddr, impl Future<Output = ()> + 'static)> {
        let (addr, listener, ssl_config, filter) = self.build_server(addr)?;
        let ssl_config = Arc::new(ssl_config);

        let srv = async move {
            let builder = auto::Builder::new(TokioExecutor::new());
            let graceful = GracefulShutdown::new();
            let mut signal = std::pin::pin!(signal);

            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let (tcp_stream, remote_addr) = match result {
                            Ok(conn) => conn,
                            Err(e) => {
                                tracing::error!("accept error: {}", e);
                                continue;
                            }
                        };

                        if let Err(e) = tcp_stream.set_nodelay(true) {
                            tracing::warn!("set_nodelay failed for {}: {}", remote_addr, e);
                        }

                        let ssl_config = ssl_config.clone();
                        let filter = filter.clone();
                        let builder = builder.clone();
                        let watcher = graceful.watcher();

                        tokio::spawn(async move {
                            let tls_stream = match TlsStream::new(tcp_stream, &ssl_config) {
                                Ok(s) => s,
                                Err(e) => {
                                    tracing::error!("TLS stream creation error: {}", e);
                                    return;
                                }
                            };

                            let stream_ref = tls_stream.stream();
                            let svc = CertInjectorService {
                                inner: warp::service(filter),
                                stream: stream_ref,
                            };

                            let conn = builder.serve_connection(
                                TokioIo::new(tls_stream),
                                TowerToHyperService::new(svc),
                            );
                            let conn = watcher.watch(conn.into_owned());

                            if let Err(e) = conn.await {
                                tracing::error!("connection error: {}", e);
                            }
                        });
                    }
                    _ = &mut signal => {
                        break;
                    }
                }
            }

            graceful.shutdown().await;
        };

        Ok((addr, srv))
    }
}

async fn serve_connection<F>(
    tcp_stream: tokio::net::TcpStream,
    ssl_config: &SslConfig,
    filter: F,
    builder: &auto::Builder<TokioExecutor>,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    F: Filter + Clone + Send + Sync + 'static,
    <F::Future as TryFuture>::Ok: Reply,
{
    let tls_stream = TlsStream::new(tcp_stream, ssl_config)?;
    let stream_ref = tls_stream.stream();

    let svc = CertInjectorService {
        inner: warp::service(filter),
        stream: stream_ref,
    };

    builder
        .serve_connection(TokioIo::new(tls_stream), TowerToHyperService::new(svc))
        .await?;

    Ok(())
}

/// A service wrapper that injects the peer certificate into request extensions.
#[derive(Clone)]
struct CertInjectorService<S> {
    inner: S,
    stream: CloneableStream,
}

impl<S, B> tower_service::Service<http::Request<B>> for CertInjectorService<S>
where
    S: tower_service::Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        let certificate: Option<Certificate> = self
            .stream
            .lock()
            .ok()
            .and_then(|stream| stream.ssl().peer_certificate())
            .and_then(|peer_certificate| peer_certificate.try_into().ok());

        if let Some(certificate) = certificate {
            req.extensions_mut().insert(certificate);
        }

        self.inner.call(req)
    }
}

impl<S> std::fmt::Debug for CertInjectorService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertInjectorService").finish()
    }
}
