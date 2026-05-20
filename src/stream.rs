use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use openssl::ssl::Ssl;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use crate::{certificate::CertificateVerifier, config::SslConfig};

pub(crate) type CloneableStream = Arc<Mutex<SslStream<TcpStream>>>;

enum AcceptState {
    Pending,
    Ready,
}

enum ConnectionState {
    Handshaking,
    Streaming,
}

/// Convenience wrapper around `tokio_openssl::SslStream` that handles the TLS handshake and
/// certificate validation.
pub(crate) struct TlsStream {
    state: ConnectionState,
    stream: CloneableStream,
    certificate_verifier: Option<Arc<dyn CertificateVerifier>>,
}

impl TlsStream {
    pub(crate) fn new(
        stream: TcpStream,
        ssl_config: &SslConfig,
    ) -> std::result::Result<TlsStream, io::Error> {
        let ssl = Ssl::new(ssl_config.acceptor.context()).map_err(io::Error::from)?;
        let stream = Arc::new(Mutex::new(
            SslStream::new(ssl, stream).map_err(io::Error::from)?,
        ));

        Ok(TlsStream {
            state: ConnectionState::Handshaking,
            stream,
            certificate_verifier: ssl_config.certificate_verifier.clone(),
        })
    }

    pub(crate) fn stream(&self) -> CloneableStream {
        self.stream.clone()
    }

    /// Performs the TLS handshake and sets the state to `Streaming` if successful.
    /// Returns `Ok(AcceptState::Ready)` if the handshake is complete, or `Ok(AcceptState::Pending)`
    /// if the handshake is still in progress.
    ///
    /// If the handshake fails, returns an `io::Error`.
    /// If the handshake succeeds but the certificate verification fails, returns an `io::Error`.
    ///
    fn do_poll_accept(self: &mut Pin<&mut Self>, cx: &mut Context<'_>) -> io::Result<AcceptState> {
        debug_assert!(matches!(self.state, ConnectionState::Handshaking));

        let stream = self.stream();
        let mut stream = stream.lock().expect("Could not lock stream");

        match Pin::new(&mut *stream).poll_accept(cx) {
            Poll::Ready(Ok(_)) => {
                self.state = ConnectionState::Streaming;
                if let Some(certificate_verifier) = self.certificate_verifier.as_ref() {
                    if let Some(cert) = stream.ssl().peer_certificate() {
                        let cert = cert.try_into()?;
                        certificate_verifier
                            .verify_certificate(&cert)
                            .map_err(|err| {
                                tracing::error!(
                                    "Certificate validation failed for certificate: {:?}",
                                    cert
                                );
                                io::Error::other(err)
                            })?
                    }
                }
                Ok(AcceptState::Ready)
            }
            Poll::Ready(Err(e)) => {
                // Log the error in case of cert verification falilure otherwise warp silently ignores this
                tracing::error!("Error in poll_accept: {:?}", e);
                Err(e.into_io_error().unwrap_or_else(io::Error::other))
            }
            Poll::Pending => Ok(AcceptState::Pending),
        }
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.state {
            ConnectionState::Handshaking => match self.do_poll_accept(cx)? {
                AcceptState::Pending => Poll::Pending,
                AcceptState::Ready => self.poll_read(cx, buf),
            },
            ConnectionState::Streaming => {
                let mut stream = self.stream.lock().expect("Could not lock stream");
                Pin::new(&mut *stream).poll_read(cx, buf)
            }
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, io::Error>> {
        match self.state {
            ConnectionState::Handshaking => match self.do_poll_accept(cx)? {
                AcceptState::Pending => Poll::Pending,
                AcceptState::Ready => self.poll_write(cx, buf),
            },
            ConnectionState::Streaming => {
                let mut stream = self.stream.lock().expect("Could not lock stream");
                Pin::new(&mut *stream).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), io::Error>> {
        match self.state {
            ConnectionState::Handshaking => Poll::Ready(Ok(())),
            ConnectionState::Streaming => {
                let mut stream = self.stream.lock().expect("Could not lock stream");
                Pin::new(&mut *stream).poll_flush(cx)
            }
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), io::Error>> {
        match self.state {
            ConnectionState::Handshaking => Poll::Ready(Ok(())),
            ConnectionState::Streaming => {
                let mut stream = self.stream.lock().expect("Could not lock stream");
                Pin::new(&mut *stream).poll_shutdown(cx)
            }
        }
    }
}
