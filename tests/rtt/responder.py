#!/usr/bin/env python3
"""L2 ICMP/ICMPv6 echo responder (stdlib only), run inside the responder netns.

Answers every echo request seen on IFACE for the destination prefixes given,
at the Ethernet level, so it works for IPv6 without a kernel IPv6 stack.
Optionally damages the echoed payload:

  --mode ok               echo the payload unchanged
  --mode magic            flip the first payload byte
  --mode tag              flip the last payload byte
  --mode truncate:N       keep only N payload bytes
  --mode nopayload        empty payload
  --mode mixed            cycle ok/magic/tag/truncate:10/nopayload per request

  --err unreach|timex     answer with an ICMP(v6) error quoting the request
                          instead of an echo reply (quote = full request)
  --err-quote N           quote only the first N bytes after the inner IP header

Usage: responder.py IFACE [--prefix 10.99.0. --prefix fd99::] [--mode ...]
"""
import argparse, socket, struct, sys

ETH_P_ALL = 0x0003


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def damage(payload, mode, n):
    if mode == "mixed":
        mode = ["ok", "magic", "tag", "truncate:10", "nopayload"][n % 5]
    if mode == "ok":
        return payload
    if mode == "magic":
        return bytes([payload[0] ^ 0xFF]) + payload[1:] if payload else payload
    if mode == "tag":
        return payload[:-1] + bytes([payload[-1] ^ 0xFF]) if payload else payload
    if mode.startswith("truncate:"):
        return payload[: int(mode.split(":")[1])]
    if mode == "nopayload":
        return b""
    raise SystemExit("bad mode " + mode)


def v4_reply(frame, args, n):
    eth, ip = frame[:14], frame[14:]
    ihl = (ip[0] & 15) * 4
    if ip[9] != 1 or ip[ihl] != 8:
        return None
    src, dst = ip[12:16], ip[16:20]
    if not socket.inet_ntoa(dst).startswith(tuple(args.prefix)):
        return None
    icmp = ip[ihl:]
    mac = eth[6:12] + eth[0:6] + eth[12:14]
    if args.err:
        quote = ip[: ihl + 8 + args.err_quote]
        typ, code = (3, 1) if args.err == "unreach" else (11, 0)
        body = struct.pack("!BBHI", typ, code, 0, 0) + quote
        body = body[:2] + struct.pack("!H", csum(body)) + body[4:]
    else:
        payload = damage(icmp[8:], args.mode, n)
        body = struct.pack("!BBH", 0, 0, 0) + icmp[4:8] + payload
        body = body[:2] + struct.pack("!H", csum(body)) + body[4:]
    hdr = bytearray(ip[:20])
    hdr[2:4] = struct.pack("!H", 20 + len(body))
    hdr[8] = 64
    hdr[10:12] = b"\0\0"
    hdr[12:16], hdr[16:20] = dst, src
    hdr[10:12] = struct.pack("!H", csum(bytes(hdr)))
    return mac + bytes(hdr) + body


def v6_reply(frame, args, n):
    eth, ip = frame[:14], frame[14:]
    if ip[6] != 58 or ip[40] != 128:
        return None
    src, dst = ip[8:24], ip[24:40]
    if not socket.inet_ntop(socket.AF_INET6, dst).startswith(tuple(args.prefix)):
        return None
    icmp = ip[40:]
    mac = eth[6:12] + eth[0:6] + eth[12:14]
    if args.err:
        quote = ip[: 40 + 8 + args.err_quote]
        typ, code = (1, 0) if args.err == "unreach" else (3, 0)
        body = struct.pack("!BBHI", typ, code, 0, 0) + quote
    else:
        payload = damage(icmp[8:], args.mode, n)
        body = struct.pack("!BBH", 129, 0, 0) + icmp[4:8] + payload
    pseudo = dst + src + struct.pack("!I3xB", len(body), 58)
    body = body[:2] + struct.pack("!H", csum(pseudo + body)) + body[4:]
    hdr = bytearray(ip[:40])
    hdr[4:6] = struct.pack("!H", len(body))
    hdr[7] = 64
    hdr[8:24], hdr[24:40] = dst, src
    return mac + bytes(hdr) + body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("iface")
    ap.add_argument("--prefix", action="append", default=[])
    ap.add_argument("--mode", default="ok")
    ap.add_argument("--err", choices=["unreach", "timex"])
    ap.add_argument("--err-quote", type=int, default=10**6)
    args = ap.parse_args()
    if not args.prefix:
        args.prefix = ["10.99.0.", "fd99::"]
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((args.iface, 0))
    n = 0
    print("responder ready", file=sys.stderr, flush=True)
    while True:
        frame, addr = s.recvfrom(65535)
        if addr[2] == socket.PACKET_OUTGOING:
            continue
        et = frame[12:14]
        out = None
        if et == b"\x08\x00":
            out = v4_reply(frame, args, n)
        elif et == b"\x86\xdd":
            out = v6_reply(frame, args, n)
        if out:
            s.send(out)
            n += 1


if __name__ == "__main__":
    main()
