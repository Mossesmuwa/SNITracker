import socket
import threading
import logging
import struct
from concurrent.futures import ThreadPoolExecutor

# -------------------------
# Config
# -------------------------
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8443

WARNING_IP = "1.1.1.1"
WARNING_PORT = 8080

BLOCKED_DOMAINS = {
    "badsite.com",
    "exampleadult.com",
    "malware.test",
}

BUFFER_SIZE = 8192
MAX_THREADS = 100

# -------------------------
# Logging
# -------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("sni-filter")


# -------------------------
# SNI extraction
# -------------------------
def extract_sni(data: bytes):
    try:
        if len(data) < 5 or data[0] != 0x16:
            return None

        idx = 5  # TLS record header

        if len(data) < idx + 4:
            return None

        idx += 4  # handshake header

        # session ID
        session_len = data[idx]
        idx += 1 + session_len

        if idx + 2 > len(data):
            return None

        # cipher suites
        cs_len = struct.unpack("!H", data[idx:idx + 2])[0]
        idx += 2 + cs_len

        if idx >= len(data):
            return None

        # compression
        comp_len = data[idx]
        idx += 1 + comp_len

        if idx + 2 > len(data):
            return None

        # extensions
        ext_len = struct.unpack("!H", data[idx:idx + 2])[0]
        idx += 2

        end = idx + ext_len
        if end > len(data):
            return None

        # parse extensions
        while idx + 4 <= end:
            ext_type = struct.unpack("!H", data[idx:idx + 2])[0]
            ext_size = struct.unpack("!H", data[idx + 2:idx + 4])[0]
            idx += 4

            if ext_type == 0:  # SNI
                block = data[idx:idx + ext_size]

                if len(block) < 5:
                    return None

                name_len = struct.unpack("!H", block[3:5])[0]
                name = block[5:5 + name_len].decode(errors="ignore")

                return name.lower().strip()

            idx += ext_size

    except Exception as e:
        log.debug(f"SNI parse error: {e}")

    return None


# -------------------------
# Domain matching
# -------------------------
def is_blocked(hostname: str) -> bool:
    if not hostname:
        return False

    hostname = hostname.lower().strip()

    return any(
        hostname == d or hostname.endswith("." + d)
        for d in BLOCKED_DOMAINS
    )


# -------------------------
# Data piping (proxy tunnel)
# -------------------------
def pipe(src, dst):
    try:
        src.settimeout(10)

        while True:
            data = src.recv(BUFFER_SIZE)
            if not data:
                break
            dst.sendall(data)

    except Exception:
        pass
    finally:
        try:
            src.close()
        except:
            pass
        try:
            dst.close()
        except:
            pass


# -------------------------
# Handle client connection
# -------------------------
def handle_client(client_socket):
    remote = None

    try:
        client_socket.settimeout(5)

        # peek TLS handshake for SNI
        data = client_socket.recv(BUFFER_SIZE, socket.MSG_PEEK)
        hostname = extract_sni(data)

        log.info(f"SNI: {hostname}")

        if not hostname:
            log.warning("No SNI found - closing connection")
            client_socket.close()
            return

        # routing decision
        if is_blocked(hostname):
            log.warning(f"BLOCKED: {hostname}")
            remote = socket.create_connection(
                (WARNING_IP, WARNING_PORT),
                timeout=5
            )
        else:
            remote = socket.create_connection(
                (hostname, 443),
                timeout=5
            )

        # start bidirectional tunnel
        threading.Thread(target=pipe, args=(client_socket, remote), daemon=True).start()
        threading.Thread(target=pipe, args=(remote, client_socket), daemon=True).start()

    except Exception as e:
        log.error(f"Connection error: {e}")

        try:
            client_socket.close()
        except:
            pass

        if remote:
            try:
                remote.close()
            except:
                pass


# -------------------------
# Server
# -------------------------
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(200)

    log.info(f"SNI filter running on {LISTEN_HOST}:{LISTEN_PORT}")

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        while True:
            client, addr = server.accept()
            executor.submit(handle_client, client)


if __name__ == "__main__":
    main()
