//! Live organization-issuer status. No cached good answer can authorize a request.
//!
//! OpenSSL's OCSP verifier supplies issuer-authorized signature validation, exact
//! CertID matching, nonce comparison and response-time checks. The small FFI below
//! binds those operations directly because the pinned Rust TLS stack has no OCSP
//! verifier and the Rust OpenSSL wrapper does not expose nonce comparison.

use std::ffi::{c_int, c_long, c_ulong, c_void};
use std::ptr;
use std::time::Duration;

use probation_policy::api::EnterpriseStatus;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use url::Url;

use super::certificates::VerifiedPeer;
use crate::upstream::resolver::{GuardedResolver, is_public};

const MAX_OCSP_BYTES: usize = 64 * 1024;
const STATUS_AGE_SECONDS: c_long = 60;

#[derive(Debug)]
pub enum EnterpriseRefusal {
    Invalid,
    Unavailable,
}

pub struct EnterprisePeer<'a> {
    pub chain: &'a VerifiedPeer,
    pub status: &'a EnterpriseStatus,
}

/// A signed, nonce-bound answer for a sample leaf used by the issuer activation
/// workflow. The portal must check `Good` and then `Revoked` for the same leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifiedIssuerStatus { Good, Revoked }

pub async fn check_sample_issuer_status(
    chain: Vec<Vec<u8>>, status: EnterpriseStatus,
) -> Result<VerifiedIssuerStatus, EnterpriseRefusal> {
    let peer = VerifiedPeer { chain: chain.into() };
    read_live_issuer_status(&EnterprisePeer { chain: &peer, status: &status }).await
}

/// The order named by `live-status-before-grant`: a current signed good answer is
/// required before this function can grant the enterprise certificate.
pub async fn resolve_enterprise_certificate(peer: &EnterprisePeer<'_>) -> Result<(), EnterpriseRefusal> {
    let status = check_live_issuer_status(peer).await?;
    grant_enterprise_certificate(status)
}

struct GoodStatus;

fn grant_enterprise_certificate(_status: GoodStatus) -> Result<(), EnterpriseRefusal> {
    Ok(())
}

async fn check_live_issuer_status(peer: &EnterprisePeer<'_>) -> Result<GoodStatus, EnterpriseRefusal> {
    match read_live_issuer_status(peer).await? {
        VerifiedIssuerStatus::Good => Ok(GoodStatus),
        VerifiedIssuerStatus::Revoked => Err(EnterpriseRefusal::Invalid),
    }
}

async fn read_live_issuer_status(peer: &EnterprisePeer<'_>) -> Result<VerifiedIssuerStatus, EnterpriseRefusal> {
    let leaf = peer.chain.chain.first().ok_or(EnterpriseRefusal::Invalid)?;
    let url = Url::parse(&peer.status.status_url).map_err(|_| EnterpriseRefusal::Invalid)?;
    if url.scheme() != "https" || url.host_str().is_none() || !url.username().is_empty()
        || url.password().is_some() || url.fragment().is_some() {
        return Err(EnterpriseRefusal::Invalid);
    }
    let private_cidrs: Vec<ipnet::IpNet> = peer.status.private_cidrs.iter()
        .map(|cidr| cidr.parse().map_err(|_| EnterpriseRefusal::Invalid))
        .collect::<Result<_, _>>()?;
    if let Some(ip) = url.host_str().and_then(|host| host.parse::<std::net::IpAddr>().ok())
        && !is_public(ip) && !private_cidrs.iter().any(|cidr| cidr.contains(&ip)) {
        return Err(EnterpriseRefusal::Invalid);
    }
    let request = ocsp_request(leaf, &peer.status.issuer_der)?;
    // One fresh client per read avoids a connection whose peer was vetted under a
    // previous DNS answer. Redirects and environment proxies are closed.
    let client = reqwest::Client::builder()
        .tls_backend_rustls()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(GuardedResolver::with_cidrs(false, private_cidrs.clone()))
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .no_gzip().no_brotli().no_zstd()
        .build().map_err(|_| EnterpriseRefusal::Unavailable)?;
    let mut response = client.post(url)
        .header(CONTENT_TYPE, "application/ocsp-request")
        .header(ACCEPT, "application/ocsp-response")
        .body(request.clone())
        .send().await.map_err(|_| EnterpriseRefusal::Unavailable)?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(EnterpriseRefusal::Unavailable);
    }
    let addr = response.remote_addr().ok_or(EnterpriseRefusal::Unavailable)?;
    if !is_public(addr.ip()) && !private_cidrs.iter().any(|cidr| cidr.contains(&addr.ip())) {
        return Err(EnterpriseRefusal::Invalid);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| EnterpriseRefusal::Unavailable)? {
        if body.len().saturating_add(chunk.len()) > MAX_OCSP_BYTES {
            return Err(EnterpriseRefusal::Invalid);
        }
        body.extend_from_slice(&chunk);
    }
    verify_ocsp_response(&request, &body, leaf, &peer.status.issuer_der, &peer.status.root_der)
}

fn ocsp_request(leaf_der: &[u8], issuer_der: &[u8]) -> Result<Vec<u8>, EnterpriseRefusal> {
    let leaf = Cert::decode(leaf_der)?;
    let issuer = Cert::decode(issuer_der)?;
    let raw = Request::new()?;
    // SAFETY: all pointers belong to live OpenSSL objects. add0 takes ownership
    // only on success; the local CertId remains owned on failure.
    unsafe {
        let id = CertId(OCSP_cert_to_id(EVP_sha1(), leaf.0, issuer.0));
        if id.0.is_null() { return Err(EnterpriseRefusal::Invalid); }
        if OCSP_request_add0_id(raw.0, id.0).is_null() { return Err(EnterpriseRefusal::Invalid); }
        std::mem::forget(id);
        let mut nonce = [0u8; 32];
        if RAND_bytes(nonce.as_mut_ptr(), nonce.len() as c_int) != 1
            || OCSP_request_add1_nonce(raw.0, nonce.as_mut_ptr(), nonce.len() as c_int) != 1 {
            return Err(EnterpriseRefusal::Unavailable);
        }
        let len = i2d_OCSP_REQUEST(raw.0, ptr::null_mut());
        if len <= 0 || len as usize > MAX_OCSP_BYTES { return Err(EnterpriseRefusal::Invalid); }
        let mut der = vec![0u8; len as usize];
        let mut output = der.as_mut_ptr();
        if i2d_OCSP_REQUEST(raw.0, &mut output) != len { return Err(EnterpriseRefusal::Invalid); }
        Ok(der)
    }
}

fn verify_ocsp_response(
    request_der: &[u8], response_der: &[u8], leaf_der: &[u8],
    issuer_der: &[u8], root_der: &[u8],
) -> Result<VerifiedIssuerStatus, EnterpriseRefusal> {
    if response_der.is_empty() || response_der.len() > MAX_OCSP_BYTES {
        return Err(EnterpriseRefusal::Invalid);
    }
    let leaf = Cert::decode(leaf_der)?;
    let issuer = Cert::decode(issuer_der)?;
    let root = Cert::decode(root_der)?;
    // SAFETY: decode receives a pointer to a live slice and retains no borrowed
    // Rust bytes. Every allocated response/basic/store/stack/id is freed by its RAII
    // wrapper below. The stack borrows issuer until this function returns.
    unsafe {
        let mut request_input = request_der.as_ptr();
        let request = Request(d2i_OCSP_REQUEST(ptr::null_mut(), &mut request_input, request_der.len() as c_long));
        if request.0.is_null() || request_input != request_der.as_ptr().add(request_der.len()) {
            return Err(EnterpriseRefusal::Invalid);
        }
        let mut input = response_der.as_ptr();
        let response = Response(d2i_OCSP_RESPONSE(ptr::null_mut(), &mut input, response_der.len() as c_long));
        if response.0.is_null() || input != response_der.as_ptr().add(response_der.len())
            || OCSP_response_status(response.0) != 0 { return Err(EnterpriseRefusal::Invalid); }
        let basic = Basic(OCSP_response_get1_basic(response.0));
        if basic.0.is_null() || OCSP_resp_count(basic.0) != 1 { return Err(EnterpriseRefusal::Invalid); }
        let store = Store(X509_STORE_new());
        let stack = Stack(OPENSSL_sk_new_null());
        if store.0.is_null() || stack.0.is_null()
            || X509_STORE_add_cert(store.0, root.0) != 1
            || OPENSSL_sk_push(stack.0, issuer.0.cast()) != 1
            || OCSP_basic_verify(basic.0, stack.0, store.0, 0) != 1 {
            return Err(EnterpriseRefusal::Invalid);
        }
        if OCSP_check_nonce(request.0, basic.0) != 1 { return Err(EnterpriseRefusal::Invalid); }
        let id = CertId(OCSP_cert_to_id(EVP_sha1(), leaf.0, issuer.0));
        if id.0.is_null() { return Err(EnterpriseRefusal::Invalid); }
        let mut status = -1;
        let mut reason = -1;
        let mut revocation = ptr::null_mut();
        let mut this_update = ptr::null_mut();
        let mut next_update = ptr::null_mut();
        if OCSP_resp_find_status(basic.0, id.0, &mut status, &mut reason,
            &mut revocation, &mut this_update, &mut next_update) != 1
            || (status != 0 && status != 1) || this_update.is_null() || next_update.is_null()
            || OCSP_check_validity(this_update, next_update, 0, STATUS_AGE_SECONDS) != 1 {
            return Err(EnterpriseRefusal::Invalid);
        }
        if status == 1 && revocation.is_null() { return Err(EnterpriseRefusal::Invalid); }
        Ok(if status == 0 { VerifiedIssuerStatus::Good } else { VerifiedIssuerStatus::Revoked })
    }
}

#[repr(C)] struct X509 { _private: [u8; 0] }
#[repr(C)] struct X509Store { _private: [u8; 0] }
#[repr(C)] struct OcspRequestRaw { _private: [u8; 0] }
#[repr(C)] struct OcspResponse { _private: [u8; 0] }
#[repr(C)] struct OcspBasic { _private: [u8; 0] }
#[repr(C)] struct OcspCertId { _private: [u8; 0] }
#[repr(C)] struct EvpMd { _private: [u8; 0] }
#[repr(C)] struct Asn1Time { _private: [u8; 0] }

struct Cert(*mut X509);
impl Cert {
    fn decode(der: &[u8]) -> Result<Self, EnterpriseRefusal> {
        if der.is_empty() || der.len() > 64 * 1024 { return Err(EnterpriseRefusal::Invalid); }
        // SAFETY: d2i_X509 consumes only the provided slice and returns an owned X509.
        unsafe {
            let mut input = der.as_ptr();
            let cert = Self(d2i_X509(ptr::null_mut(), &mut input, der.len() as c_long));
            if cert.0.is_null() || input != der.as_ptr().add(der.len()) { return Err(EnterpriseRefusal::Invalid); }
            Ok(cert)
        }
    }
}
impl Drop for Cert { fn drop(&mut self) { if !self.0.is_null() { unsafe { X509_free(self.0); } } } }
struct Request(*mut OcspRequestRaw);
impl Request { fn new() -> Result<Self, EnterpriseRefusal> { let request = Self(unsafe { OCSP_REQUEST_new() }); if request.0.is_null() { Err(EnterpriseRefusal::Unavailable) } else { Ok(request) } } }
impl Drop for Request { fn drop(&mut self) { if !self.0.is_null() { unsafe { OCSP_REQUEST_free(self.0); } } } }
struct Response(*mut OcspResponse);
impl Drop for Response { fn drop(&mut self) { if !self.0.is_null() { unsafe { OCSP_RESPONSE_free(self.0); } } } }
struct Basic(*mut OcspBasic);
impl Drop for Basic { fn drop(&mut self) { if !self.0.is_null() { unsafe { OCSP_BASICRESP_free(self.0); } } } }
struct CertId(*mut OcspCertId);
impl Drop for CertId { fn drop(&mut self) { if !self.0.is_null() { unsafe { OCSP_CERTID_free(self.0); } } } }
struct Store(*mut X509Store);
impl Drop for Store { fn drop(&mut self) { if !self.0.is_null() { unsafe { X509_STORE_free(self.0); } } } }
struct Stack(*mut c_void);
impl Drop for Stack { fn drop(&mut self) { if !self.0.is_null() { unsafe { OPENSSL_sk_free(self.0); } } } }

#[link(name = "crypto")]
unsafe extern "C" {
    fn d2i_X509(a: *mut *mut X509, input: *mut *const u8, len: c_long) -> *mut X509;
    fn X509_free(cert: *mut X509);
    fn X509_STORE_new() -> *mut X509Store;
    fn X509_STORE_add_cert(store: *mut X509Store, cert: *mut X509) -> c_int;
    fn X509_STORE_free(store: *mut X509Store);
    fn EVP_sha1() -> *const EvpMd;
    fn RAND_bytes(buf: *mut u8, len: c_int) -> c_int;
    fn OCSP_REQUEST_new() -> *mut OcspRequestRaw;
    fn OCSP_REQUEST_free(req: *mut OcspRequestRaw);
    fn OCSP_cert_to_id(digest: *const EvpMd, subject: *mut X509, issuer: *mut X509) -> *mut OcspCertId;
    fn OCSP_CERTID_free(id: *mut OcspCertId);
    fn OCSP_request_add0_id(req: *mut OcspRequestRaw, id: *mut OcspCertId) -> *mut c_void;
    fn OCSP_request_add1_nonce(req: *mut OcspRequestRaw, nonce: *mut u8, len: c_int) -> c_int;
    fn i2d_OCSP_REQUEST(req: *mut OcspRequestRaw, output: *mut *mut u8) -> c_int;
    fn d2i_OCSP_REQUEST(a: *mut *mut OcspRequestRaw, input: *mut *const u8, len: c_long) -> *mut OcspRequestRaw;
    fn d2i_OCSP_RESPONSE(a: *mut *mut OcspResponse, input: *mut *const u8, len: c_long) -> *mut OcspResponse;
    fn OCSP_RESPONSE_free(response: *mut OcspResponse);
    fn OCSP_response_status(response: *mut OcspResponse) -> c_int;
    fn OCSP_response_get1_basic(response: *mut OcspResponse) -> *mut OcspBasic;
    fn OCSP_BASICRESP_free(basic: *mut OcspBasic);
    fn OCSP_resp_count(basic: *mut OcspBasic) -> c_int;
    fn OPENSSL_sk_new_null() -> *mut c_void;
    fn OPENSSL_sk_push(stack: *mut c_void, data: *const c_void) -> c_int;
    fn OPENSSL_sk_free(stack: *mut c_void);
    fn OCSP_basic_verify(basic: *mut OcspBasic, certs: *mut c_void, store: *mut X509Store, flags: c_ulong) -> c_int;
    fn OCSP_check_nonce(req: *mut OcspRequestRaw, basic: *mut OcspBasic) -> c_int;
    fn OCSP_resp_find_status(basic: *mut OcspBasic, id: *mut OcspCertId, status: *mut c_int,
        reason: *mut c_int, revocation: *mut *mut Asn1Time, this_update: *mut *mut Asn1Time,
        next_update: *mut *mut Asn1Time) -> c_int;
    fn OCSP_check_validity(this_update: *mut Asn1Time, next_update: *mut Asn1Time, seconds: c_long, max_seconds: c_long) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    fn openssl(dir: &Path, args: &[&str]) {
        let output = Command::new("openssl").args(args).current_dir(dir).output().expect("openssl installed for OCSP fixture");
        assert!(output.status.success(), "openssl {args:?}: {}", String::from_utf8_lossy(&output.stderr));
    }

    #[test]
    fn nonce_issuer_serial_and_revocation_bind_signed_good_status() {
        let temp = tempfile::tempdir().expect("fixture directory");
        let dir = temp.path();
        fs::write(dir.join("ca.conf"), "[ca]\ndefault_ca=main\n[main]\ndatabase=index.txt\nserial=serial\nnew_certs_dir=.\ncertificate=ca.pem\nprivate_key=ca.key\ndefault_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n").unwrap();
        fs::write(dir.join("index.txt"), "").unwrap();
        fs::write(dir.join("serial"), "01\n").unwrap();
        openssl(dir, &["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=issuer", "-days", "2", "-keyout", "ca.key", "-out", "ca.pem"]);
        openssl(dir, &["req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=leaf", "-keyout", "leaf.key", "-out", "leaf.csr"]);
        openssl(dir, &["ca", "-batch", "-config", "ca.conf", "-days", "2", "-in", "leaf.csr", "-out", "leaf.pem"]);
        openssl(dir, &["x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der"]);
        openssl(dir, &["x509", "-in", "leaf.pem", "-outform", "DER", "-out", "leaf.der"]);
        let root = fs::read(dir.join("ca.der")).unwrap();
        let leaf = fs::read(dir.join("leaf.der")).unwrap();
        let request = ocsp_request(&leaf, &root).expect("nonce request");
        fs::write(dir.join("status.req"), &request).unwrap();
        openssl(dir, &["ocsp", "-index", "index.txt", "-rsigner", "ca.pem", "-rkey", "ca.key", "-CA", "ca.pem", "-reqin", "status.req", "-nmin", "2", "-respout", "good.resp"]);
        let good = fs::read(dir.join("good.resp")).unwrap();
        assert_eq!(verify_ocsp_response(&request, &good, &leaf, &root, &root).ok(), Some(VerifiedIssuerStatus::Good), "valid issuer-signed good status");
        let other_request = ocsp_request(&leaf, &root).unwrap();
        assert!(verify_ocsp_response(&other_request, &good, &leaf, &root, &root).is_err(), "wrong nonce/replay");
        openssl(dir, &["req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=other", "-keyout", "other.key", "-out", "other.csr"]);
        openssl(dir, &["ca", "-batch", "-config", "ca.conf", "-days", "2", "-in", "other.csr", "-out", "other.pem"]);
        openssl(dir, &["x509", "-in", "other.pem", "-outform", "DER", "-out", "other.der"]);
        let other_leaf = fs::read(dir.join("other.der")).unwrap();
        assert!(verify_ocsp_response(&request, &good, &other_leaf, &root, &root).is_err(), "wrong serial");
        openssl(dir, &["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=wrong-issuer", "-days", "2", "-keyout", "wrong.key", "-out", "wrong.pem"]);
        openssl(dir, &["x509", "-in", "wrong.pem", "-outform", "DER", "-out", "wrong.der"]);
        let wrong = fs::read(dir.join("wrong.der")).unwrap();
        assert!(verify_ocsp_response(&request, &good, &leaf, &wrong, &wrong).is_err(), "wrong issuer");
        openssl(dir, &["ca", "-config", "ca.conf", "-revoke", "leaf.pem"]);
        openssl(dir, &["ocsp", "-index", "index.txt", "-rsigner", "ca.pem", "-rkey", "ca.key", "-CA", "ca.pem", "-reqin", "status.req", "-nmin", "2", "-respout", "revoked.resp"]);
        let revoked = fs::read(dir.join("revoked.resp")).unwrap();
        assert_eq!(verify_ocsp_response(&request, &revoked, &leaf, &root, &root).ok(), Some(VerifiedIssuerStatus::Revoked), "committed revocation is a distinct verified status, never a grant");
    }
}
