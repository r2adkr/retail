use std::net::SocketAddr;

use anyhow::{Context, Result};
use retail_proto::stun;
use tokio::net::UdpSocket;

pub async fn run(sock: std::net::UdpSocket) -> Result<()> {
    let sock = UdpSocket::from_std(sock).context("STUN socket")?;
    tracing::info!("STUN listening on udp/{}", sock.local_addr()?);
    let mut buf = [0u8; 1500];
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            // Windows reports ICMP port-unreachable as a recv error
            Err(e) => {
                tracing::debug!("STUN recv error: {e}");
                continue;
            }
        };
        if let Some(tx) = stun::parse_binding_request(&buf[..n]) {
            // IPv4 clients on a dual-stack socket appear as ::ffff:a.b.c.d but
            // need their plain IPv4 address to learn a usable endpoint
            let mapped = SocketAddr::new(src.ip().to_canonical(), src.port());
            let resp = stun::binding_response(&tx, mapped);
            if let Err(e) = sock.send_to(&resp, src).await {
                tracing::debug!("STUN send to {src} failed: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dual_stack_reports_ipv4_clients_as_ipv4() {
        let probe = std::net::UdpSocket::bind("[::]:0").expect("IPv6 available");
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let sock = crate::net::bind_udp(SocketAddr::from(([0u16; 8], port))).unwrap();
        tokio::spawn(run(sock));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tx = [7u8; 12];
        let mut buf = [0u8; 512];
        for _ in 0..50 {
            client.send_to(&stun::binding_request(&tx), ("127.0.0.1", port)).await.unwrap();
            if let Ok(Ok(n)) = tokio::time::timeout(std::time::Duration::from_millis(100), client.recv(&mut buf)).await {
                let (got_tx, addr) = stun::parse_binding_response(&buf[..n]).expect("binding response");
                assert_eq!(got_tx, tx);
                assert_eq!(addr, client.local_addr().unwrap(), "reported as plain IPv4");
                return;
            }
        }
        panic!("no STUN response");
    }
}
