//! Answers one TLS connection on localhost with this provider, using
//! a certificate and key in DER: by default the P-256 ones the tests
//! use, under the test CA in `tests/data/ecdsa-p256/ca.der`.
//!
//! ```text
//! cargo run -p rustls-scytale --example server
//! openssl s_client -connect localhost:8443 -verify_return_error \
//!     -CAfile <(openssl x509 -inform DER \
//!         -in rustls-scytale/tests/data/ecdsa-p256/ca.der)
//! ```
//!
//! or with a certificate and a PKCS#8 key of your own:
//!
//! ```text
//! cargo run -p rustls-scytale --example server -- cert.der key.der
//! ```

use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use rustls::crypto::Identity;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, VecInput};
use rustls_util::Stream;

fn main() -> Result<(), Box<dyn Error>> {
    let data = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ecdsa-p256");
    let mut args = std::env::args().skip(1);
    let cert = args.next().unwrap_or_else(|| format!("{data}/end.der"));
    let key = args
        .next()
        .unwrap_or_else(|| format!("{data}/end.pkcs8.der"));

    let identity = Identity::from_cert_chain(vec![CertificateDer::from(
        std::fs::read(&cert)?,
    )])?;
    let key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::fs::read(&key)?));
    let config =
        ServerConfig::builder(Arc::new(rustls_scytale::DEFAULT_PROVIDER))
            .with_no_client_auth()
            .with_single_cert(Arc::new(identity), key)?;

    let listener = TcpListener::bind("localhost:8443")?;
    eprintln!("listening on {}", listener.local_addr()?);
    let (mut sock, peer) = listener.accept()?;
    let mut conn = ServerConnection::new(Arc::new(config))?;
    let mut input = VecInput::default();
    let mut tls = Stream::new(&mut input, &mut conn, &mut sock);

    tls.write_all(b"hello from rustls-scytale\n")?;
    tls.flush()?;
    let mut buf = [0u8; 256];
    let n = tls.read(&mut buf)?;
    eprintln!(
        "{peer}: {:?}, {:?}, {:?}, sent {:?}",
        conn.protocol_version(),
        conn.negotiated_cipher_suite().map(|s| s.suite()),
        conn.negotiated_key_exchange_group().map(|g| g.name()),
        String::from_utf8_lossy(&buf[..n])
    );
    Ok(())
}
