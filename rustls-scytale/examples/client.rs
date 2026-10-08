//! Fetches a page over TLS with this provider, and says what was
//! negotiated: by default, against a server that speaks the hybrid,
//! TLS 1.3 under X25519MLKEM768.
//!
//! ```text
//! cargo run -p rustls-scytale --example client -- www.rust-lang.org
//! ```

use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore, VecInput};
use rustls_util::Stream;

fn main() -> Result<(), Box<dyn Error>> {
    let host = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "www.rust-lang.org".into());

    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    let config =
        ClientConfig::builder(Arc::new(rustls_scytale::DEFAULT_PROVIDER))
            .with_root_certificates(roots)
            .with_no_client_auth()?;

    let mut conn =
        Arc::new(config).connect(host.clone().try_into()?).build()?;
    let mut sock = TcpStream::connect((host.as_str(), 443))?;
    let mut input = VecInput::default();
    let mut tls = Stream::new(&mut input, &mut conn, &mut sock);

    let request = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\
         Accept-Encoding: identity\r\n\r\n"
    );
    tls.write_all(request.as_bytes())?;
    let mut response = Vec::new();
    // Many servers close the socket without TLS's close_notify. That
    // leaves a truncation undetected, which matters to a body read to
    // its end; for the status line printed here it does not.
    match tls.read_to_end(&mut response) {
        Err(e)
            if e.kind() == std::io::ErrorKind::UnexpectedEof
                && !response.is_empty() => {}
        other => {
            other?;
        }
    }

    eprintln!("protocol:     {:?}", conn.protocol_version());
    eprintln!(
        "cipher suite: {:?}",
        conn.negotiated_cipher_suite().map(|s| s.suite())
    );
    eprintln!(
        "key exchange: {:?}",
        conn.negotiated_key_exchange_group().map(|g| g.name())
    );
    let status = response.split(|&b| b == b'\n').next().unwrap_or_default();
    println!("{}", String::from_utf8_lossy(status).trim_end());
    Ok(())
}
