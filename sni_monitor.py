# sni_stream_logger.py
# Stream-aware TLS SNI logger (improved version)

from scapy.all import sniff, TCP, Raw
from datetime import datetime
import logging
from collections import defaultdict

LOG_FILE = "sni_log.txt"

# -----------------------
# Logging setup
# -----------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("sni-logger")

# -----------------------
# Per-flow stream storage
# -----------------------
streams = defaultdict(bytearray)

MAX_BUFFER = 65535


# -----------------------
# Flow identifier
# -----------------------
def flow_key(packet):
    ip = packet.payload
    tcp = packet[TCP]

    return (ip.src, tcp.sport, ip.dst, tcp.dport)


# -----------------------
# TLS SNI extractor (safe parser)
# -----------------------
def extract_sni(data: bytes):
    try:
        if len(data) < 50:
            return None

        # TLS handshake record check
        if data[0] != 0x16:
            return None

        pos = 5  # TLS record header skip

        # handshake header
        if len(data) < pos + 4:
            return None
        pos += 4

        # session id
        session_len = data[pos]
        pos += 1 + session_len

        if pos + 2 > len(data):
            return None

        # cipher suites
        cipher_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2 + cipher_len

        if pos >= len(data):
            return None

        # compression methods
        comp_len = data[pos]
        pos += 1 + comp_len

        if pos + 2 > len(data):
            return None

        # extensions length
        ext_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2

        end = pos + ext_len
        if end > len(data):
            return None

        # parse extensions
        while pos + 4 <= end:
            ext_type = int.from_bytes(data[pos:pos + 2], "big")
            ext_size = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4

            # SNI extension
            if ext_type == 0:
                block = data[pos:pos + ext_size]

                if len(block) < 5:
                    return None

                name_len = int.from_bytes(block[3:5], "big")
                name = block[5:5 + name_len].decode(errors="ignore")

                return name.lower().strip()

            pos += ext_size

    except Exception as e:
        log.debug(f"SNI parse error: {e}")

    return None


# -----------------------
# Packet processing
# -----------------------
def process_packet(packet):
    if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
        return

    try:
        key = flow_key(packet)
        payload = bytes(packet[Raw].load)

        # append stream data
        streams[key] += payload

        # prevent memory growth
        if len(streams[key]) > MAX_BUFFER:
            streams[key] = streams[key][-MAX_BUFFER:]

        # attempt SNI extraction
        sni = extract_sni(streams[key])

        if sni:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            line = f"[{timestamp}] {sni}"

            print(line)

            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")

            # clear stream after success
            del streams[key]

    except Exception as e:
        log.error(f"Packet processing error: {e}")


# -----------------------
# Main
# -----------------------
def main():
    print("TLS SNI Stream Logger started")
    print(f"Log file: {LOG_FILE}")
    print("Press CTRL+C to stop\n")

    sniff(
        filter="tcp port 443",
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    main()
