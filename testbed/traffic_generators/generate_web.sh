#!/usr/bin/env bash

set -euo pipefail

SAMPLE_ID="${1:-}"
REQUESTS="${2:-}"
INTERVAL="${3:-}"
PORT="${4:-8081}"
PATH_TARGET="${5:-/}"

if [[ -z "$SAMPLE_ID" || -z "$REQUESTS" || -z "$INTERVAL" ]]; then
    echo "Usage: $0 <sample_id> <requests> <interval_seconds> [port] [path]"
    exit 1
fi

if ! [[ "$REQUESTS" =~ ^[0-9]+$ ]]; then
    echo "REQUESTS must be an integer"
    exit 1
fi

if ! [[ "$INTERVAL" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "INTERVAL must be a positive number"
    exit 1
fi

if ! ip netns list | grep -q "^vpn-a"; then
    echo "vpn-a namespace does not exist"
    exit 1
fi

if ! ip netns list | grep -q "^vpn-b"; then
    echo "vpn-b namespace does not exist"
    exit 1
fi

OUTPUT="ml/datasets/pcaps/${SAMPLE_ID}.pcap"

mkdir -p ml/datasets/pcaps

echo "Sample ID : $SAMPLE_ID"
echo "Requests  : $REQUESTS"
echo "Interval  : ${INTERVAL}s"
echo "Server    : 10.10.10.2:${PORT}"
echo "Path      : $PATH_TARGET"
echo "Output    : $OUTPUT"

sudo bash -c \
    "exec ip netns exec vpn-a tcpdump -i veth-a -nn -s 0 -w '$OUTPUT' 'esp' >/tmp/ipsec_web_capture.log 2>&1" &

TCPDUMP_PID=$!

cleanup() {
    if kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        sudo kill "$TCPDUMP_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT

sleep 1

echo "Generating WEB traffic..."

sudo bash -c \
    "exec ip netns exec vpn-a bash -c 'for i in \$(seq 1 $REQUESTS); do curl -fsS -o /dev/null http://10.10.10.2:${PORT}${PATH_TARGET}; sleep ${INTERVAL}; done' >/tmp/ipsec_web_requests.log 2>&1"

sleep 1

cleanup

wait "$TCPDUMP_PID" 2>/dev/null || true

if [[ ! -s "$OUTPUT" ]]; then
    echo "ERROR: capture file was not created"
    exit 1
fi

if ! tshark -r "$OUTPUT" -Y esp -c 1 >/dev/null 2>&1; then
    echo "ERROR: capture contains no ESP packets"
    exit 1
fi

echo
echo "Capture successful:"
ls -lh "$OUTPUT"

echo
echo "ESP packet count:"
tshark -r "$OUTPUT" -Y esp -T fields -e frame.number | wc -l
