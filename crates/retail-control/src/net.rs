use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};

fn socket(addr: SocketAddr, ty: Type, proto: Protocol) -> io::Result<Socket> {
    let sock = Socket::new(Domain::for_address(addr), ty, Some(proto))?;
    // Serve IPv4 on `[::]` too, which Windows unlike Linux defaults to IPv6 only
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        sock.set_only_v6(false)?;
    }
    sock.set_nonblocking(true)?;
    Ok(sock)
}

pub fn bind_udp(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let sock = socket(addr, Type::DGRAM, Protocol::UDP)?;
    sock.bind(&addr.into())?;
    Ok(sock.into())
}

pub fn bind_tcp(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    let sock = socket(addr, Type::STREAM, Protocol::TCP)?;
    sock.set_reuse_address(true)?;
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    Ok(sock.into())
}
