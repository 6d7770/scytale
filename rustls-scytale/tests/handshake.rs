//! Full handshakes with this provider on both ends: every cipher
//! suite, every key exchange group and every key type, with client
//! authentication and with resumption, over certificates and keys
//! that OpenSSL made (`tests/data/generate`).

use std::sync::Arc;

use rustls::crypto::kx::SupportedKxGroup;
use rustls::crypto::{CipherSuite, CryptoProvider, Identity};
use rustls::enums::ProtocolVersion;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer,
    PrivateSec1KeyDer, ServerName,
};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, ClientSide, Connection, HandshakeKind, RootCertStore,
    ServerConfig, ServerSide, SupportedCipherSuite, Tcp, VecInput,
};
use rustls_scytale as provider;

/// The key types, by their directory under `tests/data`.
const KEY_TYPES: [&str; 10] = [
    "ecdsa-p256",
    "ecdsa-p384",
    "ecdsa-p521",
    "ed25519",
    "rsa-2048",
    "rsa-3072",
    "rsa-4096",
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
];

/// ML-DSA is defined for TLS 1.3 only (draft-ietf-tls-mldsa).
fn tls13_only(dir: &str) -> bool {
    dir.starts_with("ml-dsa")
}

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

/// Moves everything one side has queued into the other's input.
fn transfer(from: &mut Vec<u8>, to: &mut VecInput) {
    let mut rest = &from[..];
    while !rest.is_empty() {
        to.read(&mut rest).unwrap();
    }
    from.clear();
}

/// One end: its connection, the input it reads from, what it has
/// queued to send, and the application data it has received.
struct End<Side: rustls::SideData> {
    conn: Connection<Side, Tcp>,
    input: VecInput,
    output: Vec<u8>,
    received: Vec<u8>,
}

impl<Side: rustls::SideData> End<Side> {
    fn new(conn: Connection<Side, Tcp>, output: Vec<u8>) -> Self {
        End {
            conn,
            input: VecInput::default(),
            output,
            received: Vec::new(),
        }
    }

    fn process(&mut self) -> Result<(), rustls::Error> {
        self.conn
            .read_tls(&mut self.input, &mut self.output)
            .handle_all(&mut self.received)?;
        Ok(())
    }

    fn write(&mut self, data: &[u8]) {
        self.conn.write(data.into(), &mut self.output).unwrap();
    }
}

/// A connected pair.
struct Pair {
    client: End<ClientSide>,
    server: End<ServerSide>,
}

impl Pair {
    /// A pair whose client has sent its hello and nothing more.
    fn start(client: &Arc<ClientConfig>, server: &Arc<ServerConfig>) -> Self {
        let name = ServerName::try_from("localhost").unwrap();
        let mut hello = Vec::new();
        let client = client.connect(name).build(&mut hello).unwrap();
        Pair {
            client: End::new(client, hello),
            server: End::new(
                Connection::new(server.clone()).unwrap(),
                Vec::new(),
            ),
        }
    }

    /// A pair with the handshake done.
    fn connect(client: &Arc<ClientConfig>, server: &Arc<ServerConfig>) -> Self {
        let mut pair = Pair::start(client, server);
        while pair.client.conn.is_handshaking()
            || pair.server.conn.is_handshaking()
        {
            pair.round().unwrap();
        }
        // The ticket, if any, follows the handshake.
        pair.round().unwrap();
        pair
    }

    fn round(&mut self) -> Result<(), rustls::Error> {
        transfer(&mut self.client.output, &mut self.server.input);
        self.server.process()?;
        transfer(&mut self.server.output, &mut self.client.input);
        self.client.process()
    }

    /// Application data each way, enough for several records.
    fn exchange(&mut self) {
        let message: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
        self.client.write(&message);
        self.server.write(b"and back");
        self.round().unwrap();
        assert_eq!(self.server.received, message);
        assert_eq!(self.client.received, b"and back");
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

/// The CCM_8 suites, which no list holds: a program names them.
fn short_tag_suites() -> [SupportedCipherSuite; 3] {
    use provider::cipher_suite as cs;
    [
        SupportedCipherSuite::Tls13(cs::TLS13_AES_128_CCM_8_SHA256),
        SupportedCipherSuite::Tls12(cs::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8),
        SupportedCipherSuite::Tls12(cs::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8),
    ]
}

/// Every suite the crate has: the `ALL_*` lists and the CCM_8 suites.
fn all_suites() -> Vec<SupportedCipherSuite> {
    let tls13 = provider::ALL_TLS13_CIPHER_SUITES
        .iter()
        .map(|s| SupportedCipherSuite::Tls13(s));
    let tls12 = provider::ALL_TLS12_CIPHER_SUITES
        .iter()
        .map(|s| SupportedCipherSuite::Tls12(s));
    tls13.chain(tls12).chain(short_tag_suites()).collect()
}

/// An 8-byte tag is never in a list a program might take whole, and
/// no CCM suite is a default: a program gets one only by naming it.
#[test]
fn short_tags_only_by_name() {
    let names = |suites: &mut dyn Iterator<Item = CipherSuite>| {
        suites.map(|s| format!("{s:?}")).collect::<Vec<_>>()
    };
    let all = names(
        &mut provider::ALL_TLS13_CIPHER_SUITES
            .iter()
            .map(|s| s.common.suite)
            .chain(
                provider::ALL_TLS12_CIPHER_SUITES
                    .iter()
                    .map(|s| s.common.suite),
            ),
    );
    let defaults = names(
        &mut provider::DEFAULT_TLS13_CIPHER_SUITES
            .iter()
            .map(|s| s.common.suite)
            .chain(
                provider::DEFAULT_TLS12_CIPHER_SUITES
                    .iter()
                    .map(|s| s.common.suite),
            ),
    );
    assert_eq!(all.iter().filter(|n| n.contains("CCM")).count(), 3);
    assert!(all.iter().all(|n| !n.contains("CCM_8")), "{all:?}");
    assert!(defaults.iter().all(|n| !n.contains("CCM")), "{defaults:?}");
    for suite in short_tag_suites() {
        assert!(format!("{:?}", suite.suite()).contains("CCM_8"));
    }
}

/// Whether a key type can sign for a suite: in TLS 1.2, ECDHE_RSA
/// suites take RSA keys and ECDHE_ECDSA suites the curves; TLS 1.3
/// suites take any.
fn fits(suite: SupportedCipherSuite, dir: &str) -> bool {
    match suite {
        SupportedCipherSuite::Tls12(s) => {
            let rsa_suite = format!("{:?}", s.common.suite).contains("_RSA_");
            !tls13_only(dir) && rsa_suite == dir.starts_with("rsa")
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
                pair.client.conn.negotiated_cipher_suite(),
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
                    .conn
                    .negotiated_key_exchange_group()
                    .map(|g| g.name()),
                Some(group.name())
            );
            assert_eq!(pair.client.conn.protocol_version(), Some(version));
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
            .conn
            .negotiated_key_exchange_group()
            .map(|g| g.name()),
        Some(provider::kx_group::X25519MLKEM768.name())
    );
    assert_eq!(
        pair.client.conn.protocol_version(),
        Some(ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        pair.client.conn.negotiated_cipher_suite(),
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
        let tls12 = base.tls13_cipher_suites.is_empty();
        let provider = Arc::new(base);
        for dir in KEY_TYPES {
            if tls12 && tls13_only(dir) {
                continue;
            }
            for key in keys(dir) {
                let server = Arc::new(server_config(&provider, dir, true));
                let client = ClientConfig::builder(provider.clone())
                    .with_root_certificates(roots(dir))
                    .with_client_auth_cert(identity(dir), key)
                    .unwrap();
                let mut pair = Pair::connect(&Arc::new(client), &server);
                assert!(pair.server.conn.peer_identity().is_some(), "{dir}");
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
        assert_eq!(
            first.client.conn.handshake_kind(),
            Some(HandshakeKind::Full)
        );
        let mut second = Pair::connect(&client, &server);
        assert_eq!(
            second.client.conn.handshake_kind(),
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
    let mut pair = Pair::start(&client, &server);
    let mut failed = false;
    for _ in 0..4 {
        if pair.round().is_err() {
            failed = true;
            break;
        }
    }
    assert!(failed);
}
