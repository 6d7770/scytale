//! Full handshakes with this provider on both ends: every cipher
//! suite, every key exchange group and every key type, with client
//! authentication and with resumption, over certificates and keys
//! that OpenSSL made (`tests/data/generate`).

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::crypto::kx::SupportedKxGroup;
use rustls::crypto::{CryptoProvider, Identity};
use rustls::enums::ProtocolVersion;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer,
    PrivateSec1KeyDer, ServerName,
};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, ClientConnection, Connection, HandshakeKind, RootCertStore,
    ServerConfig, ServerConnection, SupportedCipherSuite, VecInput,
};
use rustls_scytale as provider;

/// The key types, by their directory under `tests/data`.
const KEY_TYPES: [&str; 7] = [
    "ecdsa-p256",
    "ecdsa-p384",
    "ecdsa-p521",
    "ed25519",
    "rsa-2048",
    "rsa-3072",
    "rsa-4096",
];

fn read(dir: &str, file: &str) -> Vec<u8> {
    let path =
        format!("{}/tests/data/{dir}/{file}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn identity(dir: &str) -> Arc<Identity<'static>> {
    let end = CertificateDer::from(read(dir, "end.der"));
    Arc::new(Identity::from_cert_chain(vec![end]).unwrap())
}

fn roots(dir: &str) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(read(dir, "ca.der")))
        .unwrap();
    Arc::new(roots)
}

/// The key in each form OpenSSL wrote it in.
fn keys(dir: &str) -> Vec<PrivateKeyDer<'static>> {
    let mut keys = vec![PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(read(
        dir,
        "end.pkcs8.der",
    )))];
    if dir.starts_with("rsa") {
        keys.push(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(read(
            dir,
            "end.pkcs1.der",
        ))));
    }
    if dir.starts_with("ecdsa") {
        keys.push(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(read(
            dir,
            "end.sec1.der",
        ))));
    }
    keys
}

fn key(dir: &str) -> PrivateKeyDer<'static> {
    keys(dir).remove(0)
}

fn server_config(
    provider: &Arc<CryptoProvider>,
    dir: &str,
    client_auth: bool,
) -> ServerConfig {
    let builder = ServerConfig::builder(provider.clone());
    let builder = if client_auth {
        let verifier = WebPkiClientVerifier::builder(roots(dir), provider)
            .build()
            .unwrap();
        builder.with_client_cert_verifier(Arc::new(verifier))
    } else {
        builder.with_no_client_auth()
    };
    let mut config = builder.with_single_cert(identity(dir), key(dir)).unwrap();
    config.ticketer = Some(provider.ticketer_factory.ticketer().unwrap());
    config
}

fn client_config(
    provider: &Arc<CryptoProvider>,
    dir: &str,
    client_auth: bool,
) -> ClientConfig {
    let builder = ClientConfig::builder(provider.clone())
        .with_root_certificates(roots(dir));
    if client_auth {
        builder
            .with_client_auth_cert(identity(dir), key(dir))
            .unwrap()
    } else {
        builder.with_no_client_auth().unwrap()
    }
}

/// Moves everything one side has to send into the other's input.
fn transfer(from: &mut impl Connection, to: &mut VecInput) {
    let mut buf = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut buf).unwrap();
    }
    let mut rest = &buf[..];
    while !rest.is_empty() {
        to.read(&mut rest).unwrap();
    }
}

/// A connected pair, handshake done, and the inputs each reads from.
struct Pair {
    client: ClientConnection,
    server: ServerConnection,
    client_in: VecInput,
    server_in: VecInput,
}

impl Pair {
    fn connect(client: &Arc<ClientConfig>, server: &Arc<ServerConfig>) -> Self {
        let name = ServerName::try_from("localhost").unwrap();
        let mut pair = Pair {
            client: client.connect(name).build().unwrap(),
            server: ServerConnection::new(server.clone()).unwrap(),
            client_in: VecInput::default(),
            server_in: VecInput::default(),
        };
        while pair.client.is_handshaking() || pair.server.is_handshaking() {
            pair.round().unwrap();
        }
        // The ticket, if any, follows the handshake.
        pair.round().unwrap();
        pair
    }

    fn round(&mut self) -> Result<(), rustls::Error> {
        transfer(&mut self.client, &mut self.server_in);
        self.server.process_new_packets(&mut self.server_in)?;
        transfer(&mut self.server, &mut self.client_in);
        self.client.process_new_packets(&mut self.client_in)?;
        Ok(())
    }

    /// Application data each way, enough for several records.
    fn exchange(&mut self) {
        let message: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
        self.client.writer().write_all(&message).unwrap();
        self.server.writer().write_all(b"and back").unwrap();
        self.round().unwrap();
        let mut got = vec![0u8; message.len()];
        self.server.reader().read_exact(&mut got).unwrap();
        assert_eq!(got, message);
        let mut back = [0u8; 8];
        self.client.reader().read_exact(&mut back).unwrap();
        assert_eq!(&back, b"and back");
    }
}

fn with_suite(suite: SupportedCipherSuite) -> Arc<CryptoProvider> {
    let base = provider::DEFAULT_PROVIDER;
    Arc::new(match suite {
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
        _ => unreachable!("only TLS 1.2 and 1.3"),
    })
}

fn all_suites() -> Vec<SupportedCipherSuite> {
    let tls13 = provider::ALL_TLS13_CIPHER_SUITES
        .iter()
        .map(|s| SupportedCipherSuite::Tls13(s));
    let tls12 = provider::ALL_TLS12_CIPHER_SUITES
        .iter()
        .map(|s| SupportedCipherSuite::Tls12(s));
    tls13.chain(tls12).collect()
}

/// Whether a key type can sign for a TLS 1.2 suite: ECDHE_RSA
/// suites take RSA keys, ECDHE_ECDSA suites the rest.
fn fits(suite: SupportedCipherSuite, dir: &str) -> bool {
    match suite {
        SupportedCipherSuite::Tls12(s) => {
            let rsa_suite = format!("{:?}", s.common.suite).contains("_RSA_");
            rsa_suite == dir.starts_with("rsa")
        }
        _ => true,
    }
}

/// Every suite with every key type it can use, data both ways,
/// and the suite and version the handshake says it chose.
#[test]
fn every_suite_with_every_key_type() {
    for suite in all_suites() {
        let provider = with_suite(suite);
        for dir in KEY_TYPES.iter().filter(|d| fits(suite, d)) {
            let server = Arc::new(server_config(&provider, dir, false));
            let client = Arc::new(client_config(&provider, dir, false));
            let mut pair = Pair::connect(&client, &server);
            assert_eq!(
                pair.client.negotiated_cipher_suite(),
                Some(suite),
                "{dir}"
            );
            pair.exchange();
        }
    }
}

/// Every group, over TLS 1.3, and the classical ones over TLS 1.2,
/// where ML-KEM and the hybrids are not defined.
#[test]
fn every_key_exchange_group() {
    for group in provider::ALL_KX_GROUPS {
        for version in [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2] {
            if !group.name().usable_for_version(version) {
                continue;
            }
            let base = match version {
                ProtocolVersion::TLSv1_3 => provider::DEFAULT_TLS13_PROVIDER,
                _ => provider::DEFAULT_TLS12_PROVIDER,
            };
            let groups: Vec<&'static dyn SupportedKxGroup> = vec![*group];
            let provider = Arc::new(CryptoProvider {
                kx_groups: groups.into(),
                ..base
            });
            let server =
                Arc::new(server_config(&provider, "ecdsa-p256", false));
            let client =
                Arc::new(client_config(&provider, "ecdsa-p256", false));
            let mut pair = Pair::connect(&client, &server);
            assert_eq!(
                pair.client
                    .negotiated_key_exchange_group()
                    .map(|g| g.name()),
                Some(group.name())
            );
            assert_eq!(pair.client.protocol_version(), Some(version));
            pair.exchange();
        }
    }
}

/// The defaults agree on the hybrid, TLS 1.3 and AES-128-GCM.
#[test]
fn defaults_negotiate_post_quantum() {
    let provider = Arc::new(provider::DEFAULT_PROVIDER);
    let server = Arc::new(server_config(&provider, "ed25519", false));
    let client = Arc::new(client_config(&provider, "ed25519", false));
    let mut pair = Pair::connect(&client, &server);
    assert_eq!(
        pair.client
            .negotiated_key_exchange_group()
            .map(|g| g.name()),
        Some(provider::kx_group::X25519MLKEM768.name())
    );
    assert_eq!(
        pair.client.protocol_version(),
        Some(ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        pair.client.negotiated_cipher_suite(),
        Some(SupportedCipherSuite::Tls13(
            provider::cipher_suite::TLS13_AES_128_GCM_SHA256
        ))
    );
    pair.exchange();
}

/// Each key form loads, and the client authenticates with each key
/// type, over both versions.
#[test]
fn client_authentication_with_every_key_form() {
    for base in [
        provider::DEFAULT_TLS13_PROVIDER,
        provider::DEFAULT_TLS12_PROVIDER,
    ] {
        let provider = Arc::new(base);
        for dir in KEY_TYPES {
            for key in keys(dir) {
                let server = Arc::new(server_config(&provider, dir, true));
                let client = ClientConfig::builder(provider.clone())
                    .with_root_certificates(roots(dir))
                    .with_client_auth_cert(identity(dir), key)
                    .unwrap();
                let mut pair = Pair::connect(&Arc::new(client), &server);
                assert!(pair.server.peer_identity().is_some(), "{dir}");
                pair.exchange();
            }
        }
    }
}

/// A second connection resumes from the first's ticket, in both
/// versions.
#[test]
fn resumption_with_tickets() {
    for base in [
        provider::DEFAULT_TLS13_PROVIDER,
        provider::DEFAULT_TLS12_PROVIDER,
    ] {
        let provider = Arc::new(base);
        let server = Arc::new(server_config(&provider, "ecdsa-p384", false));
        // The default client keeps sessions in memory.
        let client = Arc::new(client_config(&provider, "ecdsa-p384", false));
        let first = Pair::connect(&client, &server);
        assert_eq!(first.client.handshake_kind(), Some(HandshakeKind::Full));
        let mut second = Pair::connect(&client, &server);
        assert_eq!(
            second.client.handshake_kind(),
            Some(HandshakeKind::Resumed)
        );
        second.exchange();
    }
}

/// A certificate under another CA is refused.
#[test]
fn wrong_root_is_refused() {
    let provider = Arc::new(provider::DEFAULT_PROVIDER);
    let server = Arc::new(server_config(&provider, "ecdsa-p256", false));
    let client = Arc::new(client_config(&provider, "ecdsa-p384", false));
    let name = ServerName::try_from("localhost").unwrap();
    let mut pair = Pair {
        client: client.connect(name).build().unwrap(),
        server: ServerConnection::new(server).unwrap(),
        client_in: VecInput::default(),
        server_in: VecInput::default(),
    };
    let mut failed = false;
    for _ in 0..4 {
        if pair.round().is_err() {
            failed = true;
            break;
        }
    }
    assert!(failed);
}
