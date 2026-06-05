# sni_stream_logger.py
# Improved TLS SNI logger (stream-aware)

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
# Per-flow buffer storage
# -----------------------
streams = defaultdict(bytearray)


# -----------------------
# Safe SNI extractor
# -----------------------
def extract_sni(data: bytes):
    try:
        if len(data) < 50:
            return None

        if data[0] != 0x16:  # TLS handshake
            return None

        # skip record header + handshake header
        pos = 5

        if len(data) < pos + 4:
            return None

        pos += 4

        # session id
        session_len = data[pos]
        pos += 1 + session_len

        if pos + 2 > len(data):
            return None

        cipher_len = int.from_bytes(data[pos:pos+2], "big")
        pos += 2 + cipher_len

        if pos >= len(data):
            return None

        comp_len = data[pos]
        pos += 1 + comp_len

        if pos + 2 > len(data):
            return None

        ext_len = int.from_bytes(data[pos:pos+2], "big")
        pos += 2

        end = pos + ext_len
        if end > len(data):
            return None

        while pos + 4 <= end:
            ext_type = int.from_bytes(data[pos:pos+2], "big")
            ext_size = int.from_bytes(data[pos+2:pos+4], "big")
            pos += 4

            # SNI extension
            if ext_type == 0:
                block = data[pos:pos+ext_size]

                if len(block) < 5:
                    return None

                name_len = int.from_bytes(block[3:5], "big")
                server_name = block[5:5+name_len].decode(errors="ignore")

                return server_name.lower()

            pos += ext_size

    except Exception as e:
        log.debug(f"SNI parse error: {e}")

    return None


# -----------------------
# Flow key builder
# -----------------------
def flow_key(packet):
    ip = packet.payload
    tcp = packet[TCP]

    return (
        ip.src,
        tcp.sport,
        ip.dst,
        tcp.dport
    )


# -----------------------
# Packet handler
# -----------------------
def packet_callback(packet):
    if not packet.haslayer(TCP):
        return

    if not packet.haslayer(Raw):
        return

    try:
        key = flow_key(packet)
        payload = bytes(packet[Raw].load)

        # append stream data
        streams[key] += payload

        # limit buffer size (prevent memory abuse)
        if len(streams[key]) > 65535:
            streams[key] = streams[key][-65535:]

        # attempt SNI extraction
        sni = extract_sni(streams[key])

        if sni:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            line = f"[{timestamp}] {sni}"

            print(line)

            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")

            # cleanup stream after success
            del streams[key]

    except Exception as e:
        log.error(f"Packet error: {e}")


# -----------------------
# Start sniffing
# -----------------------
print("TLS SNI Stream Logger started...")
print(f"Logging to: {LOG_FILE}")
print("Press CTRL+C to stop\n")

sniff(
    filter="tcp port 443",
    prn=packet_callback,
    store=False
)
