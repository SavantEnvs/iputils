#!/usr/bin/env python3
"""mayhem/gen_inputs.py — writes the seed corpora and the test.sh oracle inputs.

Usage: python3 -I mayhem/gen_inputs.py <repo root>

Not run by build.sh: its output is committed (mayhem/<target>/testsuite/, mayhem/tests/*.in).
Record format: see mayhem/netshim.c. The mock pid is 4242, so ping's raw-socket identifier is
htons(4242); virtual time starts at 1700000000.000000 and moves only when the tool waits.
"""
import os
import struct
import sys

TS, ERR, HOPS, PORT, LL, COPYID, ANYTIME, COPYNONCE = 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80
BASE = 1700000000
IDENT = 4242


def rec(flags, data):
    return struct.pack('<BH', flags, len(data)) + data


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(payload, ttl=64, proto=1, src='127.0.0.1', dst='127.0.0.1', opts=b''):
    ihl = 5 + len(opts) // 4
    a = bytes(map(int, src.split('.')))
    d = bytes(map(int, dst.split('.')))
    h = struct.pack('!BBHHHBBH4s4s', 0x40 | ihl, 0, 4 * ihl + len(payload), 0, 0, ttl, proto, 0, a, d) + opts
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def echo_data(sec, usec, datalen=56):
    tv = struct.pack('<qq', sec, usec)
    return (tv + bytes(i & 0xff for i in range(16, datalen)))[:datalen]


def icmp4(typ, code, rest, data):
    p = struct.pack('!BBH', typ, code, 0) + rest + data
    return p[:2] + struct.pack('!H', csum(p)) + p[4:]


def echo_reply4(seq, sec, usec=0, datalen=56, ident=IDENT):
    return icmp4(0, 0, struct.pack('!HH', ident, seq), echo_data(sec, usec, datalen))


def recv_delay(usec):
    # NS_TS: the packet arrives usec microseconds from now; the shim stamps SO_TIMESTAMP with
    # the virtual clock at that moment (the kernel's clock, not the sender's)
    return struct.pack('<I', usec)


def echo_reply6(seq, sec, usec=0, datalen=56, ident=IDENT):
    return struct.pack('!BBHHH', 129, 0, 0, ident, seq) + echo_data(sec, usec, datalen)


def ee(errno_, origin, typ, code, info=0, icmp_len=0):
    # icmp_len: the ICMP header's RFC 4884 length field (32-bit words, 64-bit for ICMPv6)
    return struct.pack('<IBBBBIB3x', errno_, origin, typ, code, 0, info, icmp_len)


def hops(n):
    return bytes([n])


def addr4(a):
    return bytes(map(int, a.split('.'))) + b'\0' * 12


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)


def ping4_inputs():
    # three replies, the third arriving 12.345 ms after it is read for (SO_TIMESTAMP receive time)
    t3 = rec(TS, recv_delay(12345) + ip4(echo_reply4(3, BASE + 2, 0)))
    basic = bytes([0]) + rec(0, ip4(echo_reply4(1, BASE))) + rec(0, ip4(echo_reply4(2, BASE + 1))) + t3
    # reply 1, a duplicate of it, a destination-unreachable for seq 2, reply 3
    unreach_inner = ip4(icmp4(8, 0, struct.pack('!HH', IDENT, 2), echo_data(BASE + 1, 0)), src='127.0.0.1')
    # (the kernel queues ICMP errors on the error queue: IP_RECVERR, offender 10.0.0.1)
    req2 = icmp4(8, 0, struct.pack('!HH', IDENT, 2), echo_data(BASE + 1, 0))
    redirect = ip4(icmp4(5, 1, bytes([10, 0, 0, 254]), unreach_inner[:28]), src='10.0.0.1')
    errs = bytes([1]) + rec(0, ip4(echo_reply4(1, BASE))) + rec(ANYTIME, ip4(echo_reply4(1, BASE))) \
        + rec(ERR, ee(113, 2, 3, 1) + addr4('10.0.0.1') + req2) \
        + rec(ANYTIME, redirect) + rec(0, ip4(echo_reply4(3, BASE + 2)))
    # -R: reply with a record-route option holding two hops
    rr = bytes([7, 11, 12]) + bytes([10, 0, 0, 1]) + bytes([10, 0, 0, 2]) + b'\x00'
    rr_in = bytes([2]) + rec(0, ip4(echo_reply4(1, BASE), opts=rr)) + rec(0, ip4(echo_reply4(2, BASE + 1), opts=rr))
    # -T tsonly: timestamp option with two stamps
    ts = bytes([68, 12, 13, 0]) + struct.pack('!II', 1000, 2000) + b''
    ts += b'\0' * ((4 - len(ts) % 4) % 4)
    ts_in = bytes([3]) + rec(0, ip4(echo_reply4(1, BASE), opts=ts)) + rec(0, ip4(echo_reply4(2, BASE + 1), opts=ts))
    json_in = bytes([6]) + rec(0, ip4(echo_reply4(1, BASE))) + rec(0, ip4(echo_reply4(2, BASE + 1)))
    big = bytes([7]) + rec(0, ip4(echo_reply4(1, BASE, datalen=2000)))
    # time-exceeded from a router, then a reply with an absurd sent timestamp (RTT overflow path)
    tex_inner = ip4(icmp4(8, 0, struct.pack('!HH', IDENT, 1), echo_data(BASE, 0)))
    req1 = icmp4(8, 0, struct.pack('!HH', IDENT, 1), echo_data(BASE, 0))
    tex = bytes([1]) + rec(0, ip4(icmp4(11, 0, b'\0' * 4, tex_inner[:28]), src='10.9.9.9')) \
        + rec(ERR, ee(113, 2, 11, 0) + addr4('10.9.9.9') + req1) \
        + rec(0, ip4(echo_reply4(2, -(1 << 62), 0))) + rec(0, ip4(echo_reply4(3, BASE + 2, 999999)))
    return {'basic': basic, 'errors': errs, 'rr': rr_in, 'ts': ts_in, 'json': json_in, 'big': big, 'timeexceeded': tex}


def ping6_inputs():
    basic = bytes([0]) + rec(HOPS, hops(61) + echo_reply6(1, BASE)) \
        + rec(0, echo_reply6(2, BASE + 1)) + rec(TS, recv_delay(7000) + echo_reply6(3, BASE + 2))
    # NI reply (type 140) to "-N name": qtype 2 (NODENAME), nonce copied from the query.
    def ni_reply(qtype, data):
        return struct.pack('!BBHHH', 140, 0, 0, qtype, 0) + b'\0' * 8 + data
    name = struct.pack('!I', 0) + b'\x04host\x07example\x03org\x00'
    ni_name = bytes([2]) + rec(COPYNONCE, ni_reply(2, name)) + rec(COPYNONCE, ni_reply(2, name))
    addrs = struct.pack('!I', 30) + bytes(15) + b'\x01'
    ni_addr = bytes([3]) + rec(COPYNONCE, ni_reply(3, addrs)) + rec(COPYNONCE, ni_reply(3, addrs))
    ni_v4 = bytes([4]) + rec(COPYNONCE, ni_reply(4, struct.pack('!I', 30) + bytes([127, 0, 0, 1])))
    req2 = struct.pack('!BBHHH', 128, 0, 0, IDENT, 2) + echo_data(BASE + 1, 0)
    err = bytes([1]) + rec(0, echo_reply6(1, BASE)) \
        + rec(ERR, ee(113, 3, 1, 4) + bytes([0xfe, 0x80] + [0] * 13 + [1]) + req2) \
        + rec(0, echo_reply6(3, BASE + 2))
    return {'basic': basic, 'ni-name': ni_name, 'ni-addr': ni_addr, 'ni-ipv4': ni_v4, 'errors': err}


def args_inputs():
    def a(*args):
        return b''.join(x.encode() + b'\0' for x in args) + b'\0'
    reply = rec(0, ip4(echo_reply4(1, BASE)))
    return {
        'count': a('-n', '-c', '1') + reply,
        'size': a('-n', '-c', '1', '-s', '127992') + reply,
        'pattern': a('-n', '-c', '1', '-p', 'deadbeef', '-Q', '0x10', '-t', '7') + reply,
        'ni': a('-6', '-N', 'subject-fqdn=www.example.org', '-c', '1'),
        'bad': a('-c', '0'),
        'interval': a('-n', '-c', '1', '-i', '0.5', '-W', '0.1', '-w', '2'),
    }


def tracepath_inputs():
    # Probe header as sent: int ttl, struct timespec (i64 sec, i64 nsec).
    def probe(ttl, sec, nsec):
        return struct.pack('<iqq', ttl, sec, nsec)
    # hop 1: time exceeded from 10.0.0.1; hop 2: port unreachable from the target (reached).
    h1 = rec(ERR | HOPS | PORT, ee(113, 2, 11, 0) + addr4('10.0.0.1') + hops(63)
             + struct.pack('!H', 44444) + probe(1, 1000, 500000))
    h2 = rec(ERR | HOPS | PORT, ee(111, 2, 3, 3) + addr4('127.0.0.1') + hops(62)
             + struct.pack('!H', 44445) + probe(2, 1000, 900000))
    basic = bytes([0]) + h1 + h2
    # with -e: an RFC 4884 extension (interface information object) after a 128-byte original datagram
    # (ICMP length field 39 words = 156 bytes, less the 20-byte IP and 8-byte UDP headers)
    # (class 2 = interface information, c-type 0xCC = role "nxt" + ifIndex + IP address: ifindex 7,
    # AFI 1 = IPv4 10.0.0.1), behind a version-2 extension header with a valid checksum
    ext_obj = struct.pack('!HBB', 16, 2, 0xCC) + struct.pack('!I', 7) + struct.pack('!HH', 1, 0) + bytes([10, 0, 0, 1])
    ext = struct.pack('!HH', 0x2000, 0) + ext_obj
    ext = ext[:2] + struct.pack('!H', csum(ext)) + ext[4:]
    h1e = rec(ERR | HOPS | PORT, ee(113, 2, 11, 0, icmp_len=39) + addr4('10.0.0.1') + hops(63)
              + struct.pack('!H', 44444) + probe(1, 1000, 500000) + bytes(128 - 20) + ext)
    exti = bytes([1]) + h1e + h2
    pmtu = bytes([5]) + rec(ERR | PORT, ee(90, 2, 3, 4, info=1280) + addr4('10.0.0.1') + struct.pack('!H', 4000)) \
        + rec(ERR | HOPS | PORT, ee(111, 2, 3, 3) + addr4('127.0.0.1') + hops(60)
              + struct.pack('!H', 4000) + probe(1, 1000, 1))
    return {'basic': basic, 'ext': exti, 'pmtu': pmtu}


def clockdiff_inputs():
    # ICMP timestamp replies (type 14): id = getpid() = 4242, seq counts from 1; times in ms since midnight UTC.
    ms = (BASE % 86400) * 1000
    def tsreply(seq, otime, rtime, ttime):
        return ip4(icmp4(14, 0, struct.pack('!HH', IDENT, seq), struct.pack('!III', otime, rtime, ttime)))
    recs = b''.join(rec(COPYID, tsreply(s, ms + s, ms + s + 3, ms + s + 3)) for s in range(1, 56))
    # -o: echo replies carrying a prespecified IP timestamp option (4 slots: us, them, them, us)
    def tsopt(t):
        o = bytes([68, 36, 37, 3])
        for v in (t, t + 2, t + 2, t + 1):
            o += bytes([127, 0, 0, 1]) + struct.pack('!I', v)
        return o
    opt = b''.join(rec(COPYID, ip4(icmp4(0, 0, struct.pack('!HH', 0, 0), bytes(12)), opts=tsopt(ms + s)))
                   for s in range(1, 56))
    return {'basic': bytes([0]) + recs, 'tsopt': bytes([1]) + opt}


def arping_inputs():
    me = bytes([2, 0, 0, 0, 0, 1])
    peer = bytes([2, 0, 0, 0, 0, 0x99])
    def arp(op, sha, spa, tha, tpa, hrd=1):
        return struct.pack('!HHBBH', hrd, 0x0800, 6, 4, op) + sha + bytes(spa) + tha + bytes(tpa)
    reply = arp(2, peer, [10, 0, 0, 1], me, [10, 0, 0, 2])
    basic = bytes([0]) + rec(0, reply) + rec(0, reply)
    dad = bytes([1]) + rec(0, arp(2, peer, [10, 0, 0, 1], me, [0, 0, 0, 0]))
    # broadcast reply from a link-layer sender given explicitly (sockaddr_ll: pkttype BROADCAST)
    ll = struct.pack('<HHiHBB8s', 17, 0x0608, 2, 1, 1, 6, peer + b'\0\0')
    bcast = bytes([2]) + rec(LL, ll + reply) + rec(0, reply) + rec(ANYTIME, arp(1, peer, [10, 0, 0, 1], me, [10, 0, 0, 2]))
    return {'basic': basic, 'dad': dad, 'bcast': bcast}


def main(root):
    sets = {
        'ping4': ping4_inputs(), 'ping6': ping6_inputs(), 'ping-args': args_inputs(),
        'tracepath': tracepath_inputs(), 'clockdiff': clockdiff_inputs(), 'arping': arping_inputs(),
    }
    for target, inputs in sets.items():
        for name, data in inputs.items():
            write(os.path.join(root, 'mayhem', target, 'testsuite', name), data)
            write(os.path.join(root, 'mayhem', 'tests', f'{target}-{name}.in'), data)


if __name__ == '__main__':
    main(sys.argv[1])
