//! One TLS connection on localhost, as client or server, with this
//! provider limited to one named cipher suite; it fails unless that
//! suite is the one negotiated and a line goes each way. The driver
//! `scripts/test-openssl-interop` runs against OpenSSL, so that
//! another implementation reads every record this one writes.
//!
//! ```text
//! interop server PORT SUITE CERT.der KEY.pkcs8.der
//! interop client PORT SUITE CA.der
//! ```
//!
//! SUITE is the name rustls prints, such as
//! `TLS13_AES_128_CCM_SHA256`; every suite the crate has is
//! accepted, the CCM_8 ones included.

use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use rustls::crypto::{CryptoProvider, Identity};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{
    ClientConfig, Connection, RootCertStore, ServerConfig, ServerConnection,
    SupportedCipherSuite, VecInput,
};
use rustls_scytale::cipher_suite as cs;
use rustls_util::Stream;

const USAGE: &str = "usage: interop client|server PORT SUITE FILE...";

/// Every suite, by the name rustls gives it.
fn suite(name: &str) -> Option<SupportedCipherSuite> {
    use SupportedCipherSuite::{Tls12, Tls13};
    [
        Tls13(cs::TLS13_AES_128_GCM_SHA256),
        Tls13(cs::TLS13_AES_256_GCM_SHA384),
        Tls13(cs::TLS13_CHACHA20_POLY1305_SHA256),
        Tls13(cs::TLS13_AES_128_CCM_SHA256),
        Tls13(cs::TLS13_AES_128_CCM_8_SHA256),
        Tls12(cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
        Tls12(cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
        Tls12(cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
        Tls12(cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
        Tls12(cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
        Tls12(cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
        Tls12(cs::TLS_ECDHE_ECDSA_WITH_AES_128_CCM),
        Tls12(cs::TLS_ECDHE_ECDSA_WITH_AES_256_CCM),
        Tls12(cs::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8),
        Tls12(cs::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8),
    ]
    .into_iter()
    .find(|s| format!("{:?}", s.suite()) == name)
}

/// The default provider with `suite` as its only suite, so that the
/// handshake cannot settle on another.
fn provider(
    suite: SupportedCipherSuite,
) -> Result<Arc<CryptoProvider>, Box<dyn Error>> {
    let base = rustls_scytale::DEFAULT_PROVIDER;
    Ok(Arc::new(match suite {
        SupportedCipherSuite::Tls13(s) => CryptoProvider {
            tls13_cipher_suites: vec![s].into(),
            tls12_cipher_suites: Vec::new().into(),
            ..base
        },
        SupportedCipherSuite::Tls12(s) => CryptoProvider {
            tls12_cipher_suites: vec![s].into(),
            tls13_cipher_suites: Vec::new().into(),
            ..base
        },
        _ => return Err("a suite of neither TLS 1.2 nor 1.3".into()),
    }))
}

/// Sends `line`, reads one back, and checks the suite.
fn talk(
    conn: &mut impl Connection,
    sock: &mut TcpStream,
    suite: SupportedCipherSuite,
    line: &str,
) -> Result<String, Box<dyn Error>> {
    let mut input = VecInput::default();
    let mut tls = Stream::new(&mut input, conn, sock);
    tls.write_all(line.as_bytes())?;
    tls.flush()?;
    let mut reply = String::new();
    BufReader::new(&mut tls).read_line(&mut reply)?;
    let got = conn.negotiated_cipher_suite();
    if got != Some(suite) {
        return Err(format!("negotiated {got:?}").into());
    }
    conn.send_close_notify();
    let mut input = VecInput::default();
    Stream::new(&mut input, conn, sock).flush()?;
    Ok(reply)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [role, port, name, files @ ..] = &args[..] else {
        return Err(USAGE.into());
    };
    let suite = suite(name).ok_or(format!("no suite {name}"))?;
    let provider = provider(suite)?;
    let reply = match (role.as_str(), files) {
        ("server", [cert, key]) => {
            let identity =
                Identity::from_cert_chain(vec![CertificateDer::from(
                    std::fs::read(cert)?,
                )])?;
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                std::fs::read(key)?,
            ));
            let config = ServerConfig::builder(provider)
                .with_no_client_auth()
                .with_single_cert(Arc::new(identity), key)?;
            let listener = TcpListener::bind(("localhost", port.parse()?))?;
            // The driver waits for this before starting the client.
            eprintln!("listening");
            let (mut sock, _) = listener.accept()?;
            let mut conn = ServerConnection::new(Arc::new(config))?;
            talk(&mut conn, &mut sock, suite, "hello from rustls-scytale\n")?
        }
        ("client", [ca]) => {
            let mut roots = RootCertStore::empty();
            roots.add(CertificateDer::from(std::fs::read(ca)?))?;
            let config = ClientConfig::builder(provider)
                .with_root_certificates(roots)
                .with_no_client_auth()?;
            let mut sock = TcpStream::connect(("localhost", port.parse()?))?;
            let mut conn =
                Arc::new(config).connect("localhost".try_into()?).build()?;
            talk(&mut conn, &mut sock, suite, "hello from rustls-scytale\n")?
        }
        _ => {
            return Err(USAGE.into());
        }
    };
    if reply.is_empty() {
        return Err("no reply".into());
    }
    eprintln!("{name}: {}", reply.trim_end());
    Ok(())
}
