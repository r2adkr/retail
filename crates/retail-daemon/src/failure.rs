//! Why the server could not be reached, from the errors' kinds rather than
//! their text (Windows words its errors in the system's language)

use std::error::Error as StdError;
use std::io;

use retail_proto::api::FailReason;
use tokio_tungstenite::tungstenite;

/// A reason the error's kind does not carry, such as a proxy's 407
#[derive(Debug)]
pub struct Tagged {
    pub reason: FailReason,
    pub msg: String,
}

impl std::fmt::Display for Tagged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl StdError for Tagged {}

pub fn tagged(reason: FailReason, msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Tagged { reason, msg: msg.into() })
}

/// A failed name lookup, kept inside the `io::Error` it travels in
pub fn name_lookup(host: &str, e: impl std::fmt::Display) -> io::Error {
    io::Error::other(Tagged { reason: FailReason::Dns, msg: format!("looking up {host}: {e}") })
}

/// How much a reason tells: an answer from the server beats one from
/// something in between, which beats silence
fn rank(r: FailReason) -> u8 {
    match r {
        FailReason::Rejected => 9,
        FailReason::ServerError => 8,
        FailReason::Intercepted => 7,
        FailReason::ProxyAuth => 6,
        FailReason::Refused => 5,
        FailReason::Reset => 4,
        FailReason::Timeout => 3,
        FailReason::Dns => 2,
        FailReason::Unreachable => 1,
        FailReason::Other => 0,
    }
}

pub fn classify(e: &anyhow::Error) -> FailReason {
    e.chain().map(one).max_by_key(|r| rank(*r)).unwrap_or(FailReason::Other)
}

/// The more telling of two errors
pub fn better(a: anyhow::Error, b: anyhow::Error) -> anyhow::Error {
    if rank(classify(&b)) > rank(classify(&a)) { b } else { a }
}

/// The more telling of two I/O errors
pub fn better_io(a: io::Error, b: io::Error) -> io::Error {
    if rank(of_io(&b)) > rank(of_io(&a)) { b } else { a }
}

fn one(cause: &(dyn StdError + 'static)) -> FailReason {
    if let Some(t) = cause.downcast_ref::<Tagged>() {
        return t.reason;
    }
    if let Some(e) = cause.downcast_ref::<io::Error>() {
        return of_io(e);
    }
    if cause.downcast_ref::<rustls::Error>().is_some() {
        return FailReason::Intercepted;
    }
    match cause.downcast_ref::<tungstenite::Error>() {
        Some(tungstenite::Error::Http(resp)) => of_status(resp.status().as_u16()),
        Some(tungstenite::Error::Io(e)) => of_io(e),
        Some(tungstenite::Error::Tls(_)) => FailReason::Intercepted,
        Some(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => FailReason::Reset,
        _ => FailReason::Other,
    }
}

pub fn of_status(status: u16) -> FailReason {
    match status {
        401 | 403 => FailReason::Rejected,
        407 => FailReason::ProxyAuth,
        500.. => FailReason::ServerError,
        _ => FailReason::Other,
    }
}

fn of_io(e: &io::Error) -> FailReason {
    // io::Error hides what it wraps from `source()`
    if let Some(inner) = e.get_ref() {
        if let Some(t) = inner.downcast_ref::<Tagged>() {
            return t.reason;
        }
        if inner.downcast_ref::<rustls::Error>().is_some() {
            return FailReason::Intercepted;
        }
    }
    use io::ErrorKind::*;
    match e.kind() {
        TimedOut | WouldBlock => FailReason::Timeout,
        ConnectionRefused => FailReason::Refused,
        ConnectionReset | ConnectionAborted | BrokenPipe | UnexpectedEof => FailReason::Reset,
        HostUnreachable | NetworkUnreachable | NetworkDown | AddrNotAvailable => FailReason::Unreachable,
        _ => FailReason::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn reads_kinds_not_words() {
        let refused = anyhow::Error::from(io::Error::from(io::ErrorKind::ConnectionRefused)).context("HTTPS");
        assert_eq!(classify(&refused), FailReason::Refused);
        let tls = anyhow::Error::from(io::Error::new(io::ErrorKind::InvalidData, rustls::Error::DecryptError)).context("HTTPS");
        assert_eq!(classify(&tls), FailReason::Intercepted);
        let dns = anyhow::Error::from(name_lookup("vpn.example.com", "nodename nor servname provided"));
        assert_eq!(classify(&dns), FailReason::Dns);
        let proxy: anyhow::Result<()> = Err(tagged(FailReason::ProxyAuth, "proxy wants a sign-in"));
        assert_eq!(classify(&proxy.context("via proxy").unwrap_err()), FailReason::ProxyAuth);
        let resp = tungstenite::http::Response::builder().status(401).body(None).unwrap();
        assert_eq!(classify(&anyhow::Error::from(tungstenite::Error::Http(Box::new(resp)))), FailReason::Rejected);
        assert_eq!(classify(&anyhow::anyhow!("something odd")), FailReason::Other);
    }

    #[test]
    fn keeps_the_telling_error() {
        let timeout = anyhow::Error::from(io::Error::from(io::ErrorKind::TimedOut));
        let refused = anyhow::Error::from(io::Error::from(io::ErrorKind::ConnectionRefused));
        assert_eq!(classify(&better(timeout, refused)), FailReason::Refused);
        let v6 = io::Error::from(io::ErrorKind::NetworkUnreachable);
        let v4 = io::Error::from(io::ErrorKind::TimedOut);
        assert_eq!(better_io(v6, v4).kind(), io::ErrorKind::TimedOut);
    }
}
