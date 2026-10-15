//! A TLS connection over a blocking TCP socket, as `Read` and
//! `Write`, for the examples.
//!
//! rustls-util's `Stream` does this, but it has no release for rustls
//! 0.24.0-dev.2. This is the least of it the examples need: one
//! blocking socket, no backpressure, no early data.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use rustls::{Connection, SideData, Tcp, VecInput};

pub struct Tls<'a, S: SideData> {
    pub conn: &'a mut Connection<S, Tcp>,
    sock: &'a mut TcpStream,
    input: VecInput,
    /// Application data received and not yet read.
    plain: Vec<u8>,
    /// TLS records waiting to be sent.
    output: Vec<u8>,
    /// The peer has sent close_notify: what is in `plain` is all.
    closed: bool,
}

impl<'a, S: SideData> Tls<'a, S> {
    /// `output` is what the connection queued as it was built: a
    /// client's hello, nothing for a server.
    pub fn new(
        conn: &'a mut Connection<S, Tcp>,
        sock: &'a mut TcpStream,
        output: Vec<u8>,
    ) -> Self {
        Tls {
            conn,
            sock,
            input: VecInput::default(),
            plain: Vec::new(),
            output,
            closed: false,
        }
    }

    /// Sends close_notify, so the peer can tell the end of the data
    /// from a connection cut short.
    pub fn close(&mut self) -> io::Result<()> {
        self.conn
            .send_close_notify(&mut self.output)
            .map_err(invalid)?;
        self.send()
    }

    fn send(&mut self) -> io::Result<()> {
        self.sock.write_all(&self.output)?;
        self.output.clear();
        Ok(())
    }

    /// Reads from the socket once and handles every complete record;
    /// false at the end of the stream.
    fn receive(&mut self) -> io::Result<bool> {
        let n = self.input.read(&mut *self.sock)?;
        let state = self
            .conn
            .read_tls(&mut self.input, &mut self.output)
            .handle_all(&mut self.plain);
        // A failure queues an alert saying why; it goes out before the
        // error is returned.
        let sent = self.send();
        self.closed = state.map_err(invalid)?.peer_has_closed();
        sent?;
        Ok(n > 0)
    }

    fn handshake(&mut self) -> io::Result<()> {
        self.send()?;
        while self.conn.is_handshaking() {
            if !self.receive()? {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        Ok(())
    }
}

impl<S: SideData> Read for Tls<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.handshake()?;
        while self.plain.is_empty() && !self.closed {
            if !self.receive()? {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed the connection without close_notify",
                ));
            }
        }
        let n = buf.len().min(self.plain.len());
        buf[..n].copy_from_slice(&self.plain[..n]);
        self.plain.drain(..n);
        Ok(n)
    }
}

impl<S: SideData> Write for Tls<'_, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.handshake()?;
        self.conn
            .write(buf.into(), &mut self.output)
            .map_err(invalid)?;
        self.send()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

fn invalid(e: rustls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}
