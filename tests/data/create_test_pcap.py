from scapy.all import IP, TCP, wrpcap


packets = []

for port in range(8000, 8005):
    packet = IP(
        src="10.0.0.1",
        dst="10.0.0.2",
    ) / TCP(
        sport=50000 + port,
        dport=port,
    )

    packets.append(packet)


output_file = "tests/data/basic_traffic.pcap"

wrpcap(output_file, packets)

print(f"Created {output_file}")
print(f"Packets: {len(packets)}")
