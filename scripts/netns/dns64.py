#!/usr/bin/env python3
"""The DNS64 side of an IPv6-only network, for the `nat64` scenario: answers
AAAA for ipv4only.arpa with the NAT64 prefix (RFC 7050) and nothing else.

Usage: dns64.py LISTEN_IPV6 PREFIX (e.g. 64:ff9b::)
"""
import ipaddress
import socket
import struct
import sys

LISTEN, PREFIX = sys.argv[1], ipaddress.IPv6Address(sys.argv[2])


def answer(query):
    tid, flags, qd = struct.unpack("!HHH", query[:6])
    i = 12
    labels = []
    while query[i] != 0:
        n = query[i]
        labels.append(query[i + 1 : i + 1 + n].decode("ascii", "replace").lower())
        i += 1 + n
    qname_end = i + 1
    qtype, _ = struct.unpack("!HH", query[qname_end : qname_end + 4])
    question = query[12 : qname_end + 4]
    name = ".".join(labels)
    answers = b""
    count = 0
    if name == "ipv4only.arpa" and qtype == 28:
        for last in (170, 171):
            addr = int(PREFIX) | (0xC0000000 + last)
            answers += b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 60, 16) + ipaddress.IPv6Address(addr).packed
            count += 1
    rcode = 0 if name == "ipv4only.arpa" else 3
    header = struct.pack("!HHHHHH", tid, 0x8180 | rcode, 1, count, 0, 0)
    return header + question + answers


def main():
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.bind((LISTEN, 53))
    while True:
        q, addr = s.recvfrom(512)
        try:
            s.sendto(answer(q), addr)
        except (IndexError, struct.error):
            pass


main()
