#!/usr/bin/env python3
# Stream-aware TLS SNI Logger (Tool Version)
# Use only on authorized networks.

from scapy.all import sniff, TCP, Raw
from datetime import datetime
import argparse
import logging
import json
from collections import defaultdict
import threading

# -----------------------
# CLI
# -----------------------
def get_args():
    parser = argparse.ArgumentParser(description="SNI Stream Monitoring Tool")

    parser.add_argument("--iface", default=None, help="Network interface")
    parser.add_argument("--log", default="sni_log.txt", help="Log file path")
    parser.add_argument("--json", action="store_true", help="Enable JSON logging")
    parser.add_argument("--quiet", action="store_true", help="Disable console output")
    parser.add_argument("--max-buffer", type=int, default=65535, help="Max per-flow buffer size")
    parser.add_argument("--stats", action="store_true", help="Show runtime stats on exit")

    return parser.parse_args()


args = get_args()

# -----------------------
# Logging
# -----------------------
logger = logging.getLogger("sni-tool")
logger.setLevel(logging.INFO)

# file logging
file_handler = logging.FileHandler(args.log)
file_handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(file_handler)

# console logging
if not args.quiet:
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(asctime)s [SNI] %(message)s"))
    logger.addHandler(console)

# -----------------------
# Runtime state
# -----------------------
streams = defaultdict(bytearray)
seen_sni = set()
lock = threading.Lock()

stats = {
    "packets": 0,
    "sni_found": 0
}

# -----------------------
# Flow key
# -----------------------
def flow_key(packet):
    ip = packet.payload
    tcp = packet[TCP]
    return (ip.src, tcp.sport, ip.dst, tcp.dport)

# -----------------------
# SNI parser (unchanged core logic)
# -----------------------
def extract_sni(data: bytes):
    try:
        if len(data) < 50 or data[0] != 0x16:
            return None

        pos = 5

        if len(data) < pos + 4:
            return None
        pos += 4

        session_len = data[pos]
        pos += 1 + session_len

        if pos + 2 > len(data):
            return None

        cipher_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2 + cipher_len

        if pos >= len(data):
            return None

        comp_len = data[pos]
        pos += 1 + comp_len

        if pos + 2 > len(data):
            return None

        ext_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2

        end = pos + ext_len
        if end > len(data):
            return None

        while pos + 4 <= end:
            ext_type = int.from_bytes(data[pos:pos + 2], "big")
            ext_size = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4

            if ext_type == 0:
                block = data[pos:pos + ext_size]

                if len(block) < 5:
                    return None

                name_len = int.from_bytes(block[3:5], "big")
                name = block[5:5 + name_len].decode(errors="ignore")

                return name.lower().strip()

            pos += ext_size

    except Exception:
        return None

    return None

# -----------------------
# Packet handler
# -----------------------
def process_packet(packet):
    if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
        return

    try:
        with lock:
            stats["packets"] += 1

        key = flow_key(packet)
        payload = bytes(packet[Raw].load)

        streams[key] += payload

        # prevent memory explosion
        if len(streams[key]) > args.max_buffer:
            streams[key] = streams[key][-args.max_buffer:]

        sni = extract_sni(streams[key])

        if sni:
            with lock:
                stats["sni_found"] += 1

            if sni in seen_sni:
                return
            seen_sni.add(sni)

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if args.json:
                output = json.dumps({
                    "time": timestamp,
                    "sni": sni
                })
            else:
                output = f"[{timestamp}] {sni}"

            logger.info(output)

            # cleanup stream after success
            del streams[key]

    except Exception as e:
        logger.error(f"Error: {e}")

# -----------------------
# Stats
# -----------------------
def show_stats():
    print("\n--- SNI TOOL STATS ---")
    print(f"Packets     : {stats['packets']}")
    print(f"SNI Found   : {stats['sni_found']}")
    print(f"Unique SNI  : {len(seen_sni)}")
    print("----------------------\n")

# -----------------------
# Main
# -----------------------
def main():
    print("===================================")
    print(" TLS SNI Stream Monitor Tool")
    print("===================================")
    print(f"Interface : {args.iface or 'auto'}")
    print(f"Log file  : {args.log}")
    print(f"JSON mode : {args.json}")
    print("Press CTRL+C to stop\n")

    try:
        sniff(
            filter="tcp port 443",
            prn=process_packet,
            store=False,
            iface=args.iface
        )
    except KeyboardInterrupt:
        if args.stats:
            show_stats()
        print("Stopped.")


if __name__ == "__main__":
    main()
