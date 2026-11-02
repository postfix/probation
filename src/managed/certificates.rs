//! The TLS handshake's client-key proof, retained per connection for package admission.

use std::fmt;
use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::http::Request;
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error, ServerConfig, SignatureScheme};
use tokio::net::TcpStream;
use tower::Service;

/// Complete TLS-presented chain after the handshake proved possession of the leaf key.
/// Only [`PeerAcceptor`] can place this value in an HTTP request.
#[derive(Clone, Debug)]
pub struct VerifiedPeer {
    pub chain: Arc<[Vec<u8>]>,
}

/// At the handshake, accept an optional syntactically valid chain and verify the leaf's
/// TLS signature. The selected organisation's current root and status are checked by
/// `admit_certificate` for every HTTP request, including reused TLS connections.
#[derive(Debug)]
pub struct DeferredClientVerifier;

pub fn tls_config(cert_path: &Path, key_path: &Path) -> io::Result<RustlsConfig> {
    let certs = CertificateDer::pem_file_iter(cert_path)
        .map_err(io::Error::other)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    let key = PrivateKeyDer::from_pem_file(key_path).map_err(io::Error::other)?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(io::Error::other)?
    .with_client_cert_verifier(Arc::new(DeferredClientVerifier))
    .with_single_cert(certs, key)
    .map_err(io::Error::other)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(config)))
}

impl ClientCertVerifier for DeferredClientVerifier {
    fn client_auth_mandatory(&self) -> bool {
        false
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        leaf: &CertificateDer<'_>,
        _chain: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if leaf.is_empty() {
            return Err(Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Clone)]
pub struct PeerAcceptor(pub RustlsAcceptor);

impl<S> Accept<TcpStream, S> for PeerAcceptor
where
    S: Send + 'static,
{
    type Stream = <RustlsAcceptor as Accept<TcpStream, S>>::Stream;
    type Service = PeerService<S>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let inner = self.0.clone();
        Box::pin(async move {
            let (stream, service) = inner.accept(stream, service).await?;
            let peer = stream
                .get_ref()
                .1
                .peer_certificates()
                .map(|certs| VerifiedPeer {
                    chain: certs
                        .iter()
                        .map(|cert| cert.as_ref().to_vec())
                        .collect::<Vec<_>>()
                        .into(),
                });
            Ok((
                stream,
                PeerService {
                    inner: service,
                    peer,
                },
            ))
        })
    }
}

pub struct PeerService<S> {
    inner: S,
    peer: Option<VerifiedPeer>,
}

impl<S: Clone> Clone for PeerService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            peer: self.peer.clone(),
        }
    }
}

impl<S: fmt::Debug> fmt::Debug for PeerService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerService").finish()
    }
}

impl<S, B> Service<Request<B>> for PeerService<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        if let Some(peer) = &self.peer {
            request.extensions_mut().insert(peer.clone());
        }
        self.inner.call(request)
    }
}
