// A minimal blocking HTTP/1.1 client over TcpStream. Every request sends
// `Connection: close`; response bodies are read either up to Content-Length or
// until the server closes the socket. This mirrors the streaming semantics of
// the Python daemon (tar / gzip streams have no Content-Length).

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub struct Response {
    pub status: u16,
    stream: TcpStream,
    leftover: Vec<u8>,
    content_length: Option<u64>,
}

impl Response {
    pub fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    /// Consume the response and return a reader over the body.
    pub fn into_body(self) -> BodyReader {
        BodyReader {
            stream: self.stream,
            leftover: self.leftover,
            pos: 0,
            remaining: self.content_length,
        }
    }

    /// Read the entire body into memory.
    pub fn read_to_vec(self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.into_body().read_to_end(&mut buf)?;
        Ok(buf)
    }
}

pub struct BodyReader {
    stream: TcpStream,
    leftover: Vec<u8>,
    pos: usize,
    remaining: Option<u64>,
}

impl Read for BodyReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.leftover.len() {
            let avail = &self.leftover[self.pos..];
            let mut take = out.len().min(avail.len());
            if let Some(r) = self.remaining {
                take = take.min(r as usize);
            }
            if take == 0 {
                return Ok(0);
            }
            out[..take].copy_from_slice(&avail[..take]);
            self.pos += take;
            if let Some(r) = self.remaining.as_mut() {
                *r -= take as u64;
            }
            return Ok(take);
        }
        match self.remaining {
            Some(0) => Ok(0),
            Some(r) => {
                let cap = (out.len() as u64).min(r) as usize;
                let n = self.stream.read(&mut out[..cap])?;
                self.remaining = Some(r - n as u64);
                Ok(n)
            }
            None => self.stream.read(out),
        }
    }
}

/// Issue an HTTP request. `read_timeout` of None means block indefinitely.
pub fn request(
    method: &str,
    host: &str,
    port: u16,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    connect_timeout: Duration,
    read_timeout: Option<Duration>,
) -> io::Result<Response> {
    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no address"))?;
    let mut stream = TcpStream::connect_timeout(&addr, connect_timeout)?;
    stream.set_read_timeout(read_timeout)?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    let mut req = format!("{} {} HTTP/1.1\r\n", method, path);
    req.push_str(&format!("Host: {}:{}\r\n", host, port));
    for (k, v) in headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("Connection: close\r\n\r\n");

    stream.write_all(req.as_bytes())?;
    if let Some(b) = body {
        stream.write_all(b)?;
    }
    stream.flush()?;

    read_response(stream)
}

fn read_response(stream: TcpStream) -> io::Result<Response> {
    let mut reader = BufReader::new(stream);

    // Status line.
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let status = parse_status(&status_line)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad status line"))?;

    // Header lines until a blank line.
    let mut content_length = None;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse::<u64>().ok();
            }
        }
    }

    // Any bytes BufReader already pulled past the header block belong to the body.
    let buffered = reader.buffer().to_vec();
    let stream = reader.into_inner();

    Ok(Response {
        status,
        stream,
        leftover: buffered,
        content_length,
    })
}

fn parse_status(line: &str) -> Option<u16> {
    let mut parts = line.split_whitespace();
    let _version = parts.next()?;
    parts.next()?.parse::<u16>().ok()
}
