#!/usr/bin/env python3
"""A corporate proxy that decrypts TLS, for the `inspect` scenario.

- CONNECT: answers 200, then requires TLS inside, terminates it with its own
  certificate and re-originates TLS upstream, verifying the server against the
  system's certificate authorities. A self-signed server is refused, the way
  inspecting proxies block untrusted sites. Plain bytes inside CONNECT are
  refused too.
- Plain HTTP in absolute form (GET http://host:port/path) is forwarded with
  `Upgrade` stripped, so WebSockets never get through.

Usage: mitm_proxy.py LISTEN_IP PORT CERT KEY
"""
import socket
import ssl
import sys
import threading

LISTEN_IP, PORT, CERT, KEY = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
HOP = {"upgrade", "connection", "proxy-connection", "keep-alive", "proxy-authorization"}


def read_head(sock, buf):
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            return None, buf
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    return head.decode("latin-1"), rest


def read_body(sock, buf, headers):
    n = int(headers.get("content-length", "0") or 0)
    while len(buf) < n:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
    return buf[:n], buf[n:]


def parse(head):
    lines = head.split("\r\n")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return lines[0], lines[1:], headers


def pipe(a, b):
    def one(src, dst):
        try:
            while True:
                d = src.recv(65536)
                if not d:
                    break
                dst.sendall(d)
        except OSError:
            pass
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    t = threading.Thread(target=one, args=(b, a), daemon=True)
    t.start()
    one(a, b)
    t.join()


def handle_connect(c, target):
    c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    first = c.recv(1, socket.MSG_PEEK)
    if first != b"\x16":
        print(f"CONNECT {target}: not TLS, refused", flush=True)
        return
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(CERT, KEY)
    try:
        tls = server_ctx.wrap_socket(c, server_side=True)
    except (ssl.SSLError, OSError) as e:
        print(f"CONNECT {target}: client TLS failed: {e}", flush=True)
        return
    host, port = target.rsplit(":", 1)
    host = host.strip("[]")
    try:
        up = socket.create_connection((host, int(port)), timeout=5)
        ups = ssl.create_default_context().wrap_socket(up, server_hostname=host)
    except (ssl.SSLError, OSError) as e:
        print(f"CONNECT {target}: upstream refused ({e})", flush=True)
        tls.close()
        return
    pipe(tls, ups)


def handle_forward(c, first_head, buf):
    upstream = None
    upstream_buf = b""
    head = first_head
    while head is not None:
        request_line, lines, headers = parse(head)
        method, url, version = request_line.split(" ", 2)
        body, buf = read_body(c, buf, headers)
        if not url.startswith("http://"):
            c.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        rest = url[len("http://"):]
        authority, _, path = rest.partition("/")
        host, _, port = authority.rpartition(":") if ":" in authority.strip("]") else (authority, "", "80")
        host = host.strip("[]")
        if upstream is None:
            upstream = socket.create_connection((host, int(port or 80)), timeout=30)
        kept = [l for l in lines if l.split(":", 1)[0].strip().lower() not in HOP]
        req = f"{method} /{path} {version}\r\n" + "".join(l + "\r\n" for l in kept) + "Connection: keep-alive\r\n\r\n"
        upstream.sendall(req.encode("latin-1") + body)
        resp_head, upstream_buf = read_head(upstream, upstream_buf)
        if resp_head is None:
            return
        status_line, rlines, rheaders = parse(resp_head)
        rbody, upstream_buf = read_body(upstream, upstream_buf, rheaders)
        kept = [l for l in rlines if l.split(":", 1)[0].strip().lower() not in HOP]
        if " 101 " in status_line + " ":
            # A real inspecting proxy would not let the upgrade through
            c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        c.sendall((status_line + "\r\n" + "".join(l + "\r\n" for l in kept) + "\r\n").encode("latin-1") + rbody)
        head, buf = read_head(c, buf)


def handle(c):
    try:
        head, buf = read_head(c, b"")
        if head is None:
            return
        request_line = head.split("\r\n", 1)[0]
        method, target, _ = request_line.split(" ", 2)
        if method == "CONNECT":
            handle_connect(c, target)
        else:
            handle_forward(c, head, buf)
    except Exception as e:  # noqa: BLE001
        print(f"error: {e}", flush=True)
    finally:
        try:
            c.close()
        except OSError:
            pass


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN_IP, PORT))
    s.listen(128)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


main()
