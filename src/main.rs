//! HTTPS GET with TLS 1.3 client authentication, signing the handshake with the ML-DSA-65 key in
//! the PQC Ready YubiKey beta's PIV authentication slot (9A).
//!
//! Usage: `rustls-yubikey <host> <port> <path> <client-cert.der> <server-root.pem> [pin]`
//!
//! The client certificate is read from a file rather than from the card, whose copy is too large
//! for some tools to read back. The server is verified against the root in `server-root.pem`. The
//! PIN defaults to the PIV default, 123456, and is verified immediately before each signature, as
//! a PIN-always slot requires.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use rustls::client::ResolvesClientCert;
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{ClientConfig, ClientConnection, RootCertStore, SignatureAlgorithm, SignatureScheme};
use yubikey::piv::{self, AlgorithmId, SlotId};
use yubikey::YubiKey;

#[derive(Debug)]
struct Card {
    yubikey: Mutex<YubiKey>,
    pin: Vec<u8>,
}

/// The card's key in slot 9A, offering ML-DSA-65 and nothing else.
#[derive(Debug)]
struct CardKey(Arc<Card>);

impl SigningKey for CardKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        eprintln!("server offers: {offered:?}");
        offered
            .contains(&SignatureScheme::ML_DSA_65)
            .then(|| Box::new(CardSigner(self.0.clone())) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        // No TLS SignatureAlgorithm value exists for ML-DSA; this is used only by TLS 1.2.
        SignatureAlgorithm::Unknown(0)
    }
}

#[derive(Debug)]
struct CardSigner(Arc<Card>);

impl Signer for CardSigner {
    /// Pure ML-DSA over the whole message: the card does no hashing and neither does the host.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let card_error =
            |what: &str, e: yubikey::Error| rustls::Error::General(format!("card {what}: {e:?}"));
        let mut yubikey = self.0.yubikey.lock().expect("card lock");
        yubikey
            .verify_pin(&self.0.pin)
            .map_err(|e| card_error("PIN verification", e))?;
        let signature = piv::sign_data(
            &mut yubikey,
            message,
            AlgorithmId::MlDsa65,
            SlotId::Authentication,
        )
        .map_err(|e| card_error("signing", e))?;
        eprintln!(
            "card signed {} bytes; signature {} bytes",
            message.len(),
            signature.len()
        );
        Ok(signature.to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ML_DSA_65
    }
}

#[derive(Debug)]
struct CardIdentity(Arc<CertifiedKey>);

impl ResolvesClientCert for CardIdentity {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        sigschemes
            .contains(&SignatureScheme::ML_DSA_65)
            .then(|| self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        eprintln!(
            "usage: {} <host> <port> <path> <client-cert.der> <server-root.pem> [pin]",
            args[0]
        );
        std::process::exit(2);
    }
    let (host, port, path) = (&args[1], &args[2], &args[3]);
    let client_cert = std::fs::read(&args[4]).expect("read client certificate");
    let pin = args
        .get(6)
        .map_or(b"123456".to_vec(), |p| p.as_bytes().to_vec());

    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&args[5]).expect("read server root") {
        roots
            .add(cert.expect("parse server root"))
            .expect("add server root");
    }

    let yubikey = YubiKey::open().expect("open YubiKey");
    eprintln!("YubiKey serial {}", yubikey.serial());
    let card = Arc::new(Card {
        yubikey: Mutex::new(yubikey),
        pin,
    });
    let identity = CertifiedKey::new(
        vec![CertificateDer::from(client_cert)],
        Arc::new(CardKey(card)),
    );

    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_root_certificates(roots)
            .with_client_cert_resolver(Arc::new(CardIdentity(Arc::new(identity))));

    let server_name = ServerName::try_from(host.clone()).expect("server name");
    let mut conn = ClientConnection::new(Arc::new(config), server_name).expect("TLS client");
    let mut sock = TcpStream::connect(format!("{host}:{port}")).expect("connect");
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    write!(
        tls,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .expect("send request");
    let mut response = Vec::new();
    if let Err(e) = tls.read_to_end(&mut response) {
        // A server that closes without close_notify still delivered its response.
        if response.is_empty() {
            panic!("read response: {e}");
        }
    }
    let response = String::from_utf8_lossy(&response);
    println!("{}", response.lines().next().unwrap_or("(no response)"));
}
