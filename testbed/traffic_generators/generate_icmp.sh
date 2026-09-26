#!/usr/bin/env bash

set -euo pipefail

SAMPLE_ID="${1:-}"
COUNT="${2:-}"
INTERVAL="${3:-}"

if [[ -z "$SAMPLE_ID" || -z "$COUNT" || -z "$INTERVAL" ]]; then
    echo "Usage: $0 <sample_id> <count> <interval_seconds>"
    exit 1
fi

if ! [[ "$COUNT" =~ ^[0-9]+$ ]]; then
    echo "COUNT must be an integer"
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
echo "Packets   : $COUNT"
echo "Interval  : ${INTERVAL}s"
echo "Output    : $OUTPUT"

sudo ip netns exec vpn-a \
    tcpdump -i veth-a -nn -s 0 -w "$OUTPUT" 'esp' \
    >/tmp/ipsec_icmp_capture.log 2>&1 &

TCPDUMP_PID=$!

cleanup() {
    if kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        sudo kill "$TCPDUMP_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT

sleep 1

echo "Generating ICMP traffic..."

sudo ip netns exec vpn-a \
    ping -c "$COUNT" -i "$INTERVAL" 10.10.10.2 \
    >/tmp/ipsec_icmp_ping.log 2>&1

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
