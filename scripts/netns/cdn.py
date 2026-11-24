#!/usr/bin/env python3
"""A CDN edge for the `cdn` scenario: terminates TLS for its own name with its
own certificate and forwards the bytes to the origin over a new TLS connection
that does not check the origin's certificate (like "Full" mode at common CDNs).

asyncio, because Python's SSL sockets must not be read and written from two
threads at once.

Usage: cdn.py LISTEN_IP PORT CERT KEY ORIGIN_HOST ORIGIN_PORT
"""
import asyncio
import ssl
import sys

LISTEN_IP, PORT, CERT, KEY, ORIGIN, ORIGIN_PORT = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], int(sys.argv[6])


async def pump(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, ssl.SSLError, OSError):
        pass
    finally:
        try:
            writer.close()
        except (ConnectionError, ssl.SSLError, OSError):
            pass


async def handle(client_reader, client_writer):
    origin_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    origin_ctx.check_hostname = False
    origin_ctx.verify_mode = ssl.CERT_NONE
    try:
        origin_reader, origin_writer = await asyncio.wait_for(
            asyncio.open_connection(ORIGIN, ORIGIN_PORT, ssl=origin_ctx), 10
        )
    except (OSError, ssl.SSLError, asyncio.TimeoutError) as e:
        print(f"edge: origin: {e}", flush=True)
        client_writer.close()
        return
    await asyncio.gather(pump(client_reader, origin_writer), pump(origin_reader, client_writer))


async def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    ctx.set_alpn_protocols(["http/1.1"])
    server = await asyncio.start_server(handle, LISTEN_IP, PORT, ssl=ctx)
    async with server:
        await server.serve_forever()


asyncio.run(main())
