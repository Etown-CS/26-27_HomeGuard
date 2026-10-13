#!/usr/bin/env python3
"""
Setup:
    pip install scapy
    python3 sniffer.py --list-ifaces
    sudo python3 sniffer.py -i eth0 -c 50 -o capture.csv

Run (needs root/admin to sniff):
    sudo python3 sniffer.py                          # default interface
    sudo python3 sniffer.py -i wlan0                 # pick an interface
    sudo python3 sniffer.py -c 100                   # stop after 100 packets
    sudo python3 sniffer.py -f "host 192.168.1.24"   # BPF filter
    sudo python3 sniffer.py -o capture.csv           # also save to CSV
    python3 sniffer.py --list-ifaces                 # show interfaces
"""

import argparse
import csv
import sys
from datetime import datetime

from scapy.all import sniff, conf, get_if_list
from scapy.error import Scapy_Exception
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR

CSV_FIELDS = [
    "timestamp", "src_mac", "dst_mac", "src_ip", "dst_ip",
    "protocol", "src_port", "dst_port", "length", "tcp_flags", "info",
]

csv_writer = None
packet_count = 0


def parse_packet(pkt):
    # Pull the useful fields out of a packet into a dict
    row = {f: "" for f in CSV_FIELDS}
    row["timestamp"] = datetime.fromtimestamp(float(pkt.time)).isoformat(timespec="milliseconds")
    row["length"] = len(pkt)

    if pkt.haslayer(Ether):
        row["src_mac"] = pkt[Ether].src
        row["dst_mac"] = pkt[Ether].dst

    # Network layer
    if pkt.haslayer(IP):
        row["src_ip"] = pkt[IP].src
        row["dst_ip"] = pkt[IP].dst
        row["protocol"] = "IP"
    elif pkt.haslayer(IPv6):
        row["src_ip"] = pkt[IPv6].src
        row["dst_ip"] = pkt[IPv6].dst
        row["protocol"] = "IPv6"
    elif pkt.haslayer(ARP):
        row["src_ip"] = pkt[ARP].psrc
        row["dst_ip"] = pkt[ARP].pdst
        row["protocol"] = "ARP"
        row["info"] = "who-has" if pkt[ARP].op == 1 else "is-at"

    # Transport layer
    if pkt.haslayer(TCP):
        row["protocol"] = "TCP"
        row["src_port"] = pkt[TCP].sport
        row["dst_port"] = pkt[TCP].dport
        row["tcp_flags"] = str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        row["protocol"] = "UDP"
        row["src_port"] = pkt[UDP].sport
        row["dst_port"] = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        row["protocol"] = "ICMP"

    # Application layer
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        row["protocol"] = "DNS"
        qname = pkt[DNSQR].qname
        row["info"] = qname.decode(errors="ignore") if isinstance(qname, bytes) else str(qname)

    return row


def handle_packet(pkt):
    global packet_count
    packet_count += 1
    row = parse_packet(pkt)

    src = f"{row['src_ip']}:{row['src_port']}" if row["src_port"] != "" else row["src_ip"]
    dst = f"{row['dst_ip']}:{row['dst_port']}" if row["dst_port"] != "" else row["dst_ip"]
    extra = f" [{row['tcp_flags']}]" if row["tcp_flags"] else ""
    info = f" {row['info']}" if row["info"] else ""
    print(f"{row['timestamp']}  {row['protocol']:<5} {src or row['src_mac']} -> "
          f"{dst or row['dst_mac']}  {row['length']}B{extra}{info}")

    if csv_writer:
        csv_writer.writerow(row)


def main():
    global csv_writer

    parser = argparse.ArgumentParser(description="HomeGuard basic packet tracer")
    parser.add_argument("-i", "--iface", help="network interface (default: Scapy's default)")
    parser.add_argument("-c", "--count", type=int, default=0, help="packets to capture (0 = until Ctrl+C)")
    parser.add_argument("-f", "--filter", default="", help='BPF filter, e.g. "tcp port 443"')
    parser.add_argument("-o", "--output", help="save packets to this CSV file")
    parser.add_argument("--list-ifaces", action="store_true", help="list interfaces and exit")
    args = parser.parse_args()

    if args.list_ifaces:
        print("\n".join(get_if_list()))
        return

    iface = args.iface or conf.iface
    print(f"[*] Sniffing on {iface}  filter='{args.filter or 'none'}'  (Ctrl+C to stop)\n")

    csv_file = None
    if args.output:
        csv_file = open(args.output, "w", newline="")
        csv_writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)
        csv_writer.writeheader()

    try:
        sniff(
            iface=iface,
            filter=args.filter or None,
            prn=handle_packet,
            count=args.count,
            store=False,  # dont keep packets in memory
        )
    except PermissionError:
        print("[!] Permission denied. Run with sudo (Linux/macOS) or as Administrator (Windows).")
        sys.exit(1)
    except Scapy_Exception as e:
        print(f"[!] Scapy error: {e}")
        if "libpcap" in str(e):
            print("    -f filters need libpcap. Linux: sudo apt install libpcap-dev tcpdump | "
                  "Windows: install Npcap | or run without -f.")
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        if csv_file:
            csv_file.close()
        print(f"\n[*] Done. Captured {packet_count} packets.")
        if args.output:
            print(f"[*] Saved to {args.output}")


if __name__ == "__main__":
    main()