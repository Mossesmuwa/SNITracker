#!/usr/bin/env python3
# DNS Monitor Tool
# Use only on authorized networks.

from scapy.all import sniff, DNSQR
from datetime import datetime, timedelta
import argparse
import logging
import json
import threading
import signal
import sys
import re
from logging.handlers import RotatingFileHandler

# ----------------------------
# CLI
# ----------------------------
def get_args():
    parser = argparse.ArgumentParser(
        description="DNS Monitor Tool - inspect DNS traffic in real time"
    )

    parser.add_argument("--iface", help="Network interface (e.g. eth0, wlan0)", default=None)
    parser.add_argument("--log", help="Log file path", default="dns_log.txt")
    parser.add_argument("--json", action="store_true", help="Output JSON logs")
    parser.add_argument("--timeout", type=int, default=300, help="Deduplication window (seconds)")
    parser.add_argument("--quiet", action="store_true", help="Hide console output")
    parser.add_argument("--stats", action="store_true", help="Show live stats on exit")

    return parser.parse_args()


args = get_args()

# ----------------------------
# Block rules
# ----------------------------
BLOCKLIST = ["adult", "porn", "gambling", "casino"]
BLOCK_REGEX = re.compile("|".join(BLOCKLIST), re.IGNORECASE)

# ----------------------------
# Logging
# ----------------------------
logger = logging.getLogger("dns-monitor")
logger.setLevel(logging.INFO)

formatter = logging.Formatter("[%(asctime)s] %(message)s")

file_handler = RotatingFileHandler(args.log, maxBytes=2_000_000, backupCount=3)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

if not args.quiet:
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

# ----------------------------
# State
# ----------------------------
seen = {}
lock = threading.Lock()

stats = {
    "packets": 0,
    "domains": 0,
    "blocked": 0
}

running = True


# ----------------------------
# Cleanup
# ----------------------------
def cleanup():
    cutoff = datetime.now() - timedelta(seconds=args.timeout)

    with lock:
        for d in list(seen.keys()):
            if seen[d] < cutoff:
                del seen[d]


# ----------------------------
# Packet handler
# ----------------------------
def handle_packet(packet):
    if not packet.haslayer(DNSQR):
        return

    try:
        domain = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
        now = datetime.now()

        with lock:
            stats["packets"] += 1

            last = seen.get(domain)
            if last and (now - last).total_seconds() < args.timeout:
                return

            seen[domain] = now
            stats["domains"] += 1

        flagged = bool(BLOCK_REGEX.search(domain))

        if flagged:
            stats["blocked"] += 1

        log_data = {
            "time": now.isoformat(),
            "domain": domain,
            "flagged": flagged
        }

        if args.json:
            output = json.dumps(log_data)
        else:
            output = f"{now:%Y-%m-%d %H:%M:%S} | {domain}" + (" [BLOCKED]" if flagged else "")

        logger.info(output)

        if stats["domains"] % 50 == 0:
            cleanup()

    except Exception as e:
        logger.error(f"Error: {e}")


# ----------------------------
# Stats display
# ----------------------------
def print_stats():
    print("\n--- DNS MONITOR STATS ---")
    print(f"Packets  : {stats['packets']}")
    print(f"Domains  : {stats['domains']}")
    print(f"Blocked  : {stats['blocked']}")
    print("-------------------------\n")


# ----------------------------
# Shutdown handler
# ----------------------------
def shutdown(sig, frame):
    global running
    running = False

    print("\nStopping DNS Monitor...")

    if args.stats:
        print_stats()

    sys.exit(0)


signal.signal(signal.SIGINT, shutdown)


# ----------------------------
# Main tool runtime
# ----------------------------
def main():
    print("===================================")
    print(" DNS Monitor Tool v1.0")
    print("===================================")
    print(f"Interface : {args.iface or 'auto'}")
    print(f"Log file  : {args.log}")
    print(f"JSON mode : {args.json}")
    print("Press CTRL+C to stop\n")

    sniff(
        filter="udp port 53",
        prn=handle_packet,
        store=False,
        iface=args.iface
    )


if __name__ == "__main__":
    main()
