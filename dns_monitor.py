# DNS Monitor (Improved Version)
# Use responsibly. Monitor only networks you own or have permission to inspect.

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
# Argument Parsing
# ----------------------------
parser = argparse.ArgumentParser(description="DNS Traffic Monitor")
parser.add_argument("--iface", help="Network interface to sniff on", default=None)
parser.add_argument("--log", help="Log file", default="dns_log.txt")
parser.add_argument("--json", action="store_true", help="Log in JSON format")
parser.add_argument("--timeout", type=int, default=300, help="Deduplication timeout (seconds)")
args = parser.parse_args()

# ----------------------------
# Blocklist (compiled regex)
# ----------------------------
BLOCKLIST = [
    "adult",
    "porn",
    "gambling",
    "casino",
]

BLOCK_REGEX = re.compile("|".join(BLOCKLIST), re.IGNORECASE)

# ----------------------------
# Logging setup
# ----------------------------
logger = logging.getLogger("dns-monitor")
logger.setLevel(logging.INFO)

formatter = logging.Formatter("[%(asctime)s] %(message)s")

file_handler = RotatingFileHandler(args.log, maxBytes=2_000_000, backupCount=3)
file_handler.setFormatter(formatter)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)

# ----------------------------
# Runtime state
# ----------------------------
seen = {}  # {domain: last_seen_time}
lock = threading.Lock()

stats = {
    "packets": 0,
    "domains": 0
}

running = True


# ----------------------------
# Cleanup old entries
# ----------------------------
def cleanup_seen():
    """Remove old entries to prevent memory growth."""
    now = datetime.now()
    expired = now - timedelta(seconds=args.timeout)

    with lock:
        to_delete = [d for d, t in seen.items() if t < expired]
        for d in to_delete:
            del seen[d]


# ----------------------------
# Packet handler
# ----------------------------
def process_packet(packet):
    global stats

    if not packet.haslayer(DNSQR):
        return

    try:
        stats["packets"] += 1

        domain = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
        now = datetime.now()

        with lock:
            # dedupe within timeout window
            last = seen.get(domain)
            if last and (now - last).total_seconds() < args.timeout:
                return
            seen[domain] = now

        stats["domains"] += 1

        warning = ""
        if BLOCK_REGEX.search(domain):
            warning = " [FLAGGED]"

        if args.json:
            log_entry = json.dumps({
                "time": now.isoformat(),
                "domain": domain,
                "flagged": bool(warning),
            })
        else:
            log_entry = f"{now:%Y-%m-%d %H:%M:%S} - {domain}{warning}"

        logger.info(log_entry)

        # periodic cleanup
        if stats["domains"] % 50 == 0:
            cleanup_seen()

    except Exception as e:
        logger.error(f"Error processing packet: {e}")


# ----------------------------
# Graceful shutdown
# ----------------------------
def shutdown(sig, frame):
    global running
    running = False
    print("\nStopping DNS monitor...")
    print(f"Packets seen: {stats['packets']}")
    print(f"Domains logged: {stats['domains']}")
    sys.exit(0)


signal.signal(signal.SIGINT, shutdown)


# ----------------------------
# Start sniffing
# ----------------------------
print("DNS Monitor started")
print(f"Log file: {args.log}")
print("Press CTRL+C to stop\n")

sniff(
    filter="udp port 53",
    prn=process_packet,
    store=False,
    iface=args.iface
)
