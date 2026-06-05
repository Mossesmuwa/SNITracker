#!/usr/bin/env python3
# Warning / Block Page Server
# Use for network policy enforcement in authorized environments only.

from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime
import logging
import argparse

# -----------------------
# CLI
# -----------------------
def get_args():
    parser = argparse.ArgumentParser(description="Warning Page Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    parser.add_argument("--port", type=int, default=8080, help="Bind port")
    parser.add_argument("--message", default="This site is not allowed.", help="Block message")
    return parser.parse_args()


args = get_args()

# -----------------------
# Logging
# -----------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BLOCK-SERVER] %(message)s"
)

log = logging.getLogger("warning-server")


# -----------------------
# HTML builder
# -----------------------
def build_page(message: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Access Blocked</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            text-align: center;
            background: #f4f4f4;
            padding-top: 80px;
        }}
        .box {{
            background: #fff;
            padding: 30px;
            display: inline-block;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #d9534f;
            margin-bottom: 10px;
        }}
        p {{
            color: #333;
        }}
        small {{
            color: #777;
        }}
    </style>
</head>
<body>
    <div class="box">
        <h1>Access Blocked</h1>
        <p>{message}</p>
        <small>{timestamp}</small>
    </div>
</body>
</html>
""".encode("utf-8")


HTML_PAGE = build_page(args.message)


# -----------------------
# Request Handler
# -----------------------
class BlockHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        # cleaner logging output
        log.info("%s - %s", self.address_string(), format % args)

    def _send_page(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(HTML_PAGE)

    def do_GET(self):
        self._send_page()
        log.info(f"Served block page to {self.client_address[0]} ({self.path})")

    def do_POST(self):
        self._send_page()


# -----------------------
# Server
# -----------------------
def main():
    server = HTTPServer((args.host, args.port), BlockHandler)

    print("===================================")
    print(" Warning / Block Page Server")
    print("===================================")
    print(f"URL   : http://{args.host}:{args.port}")
    print(f"Msg   : {args.message}")
    print("Press CTRL+C to stop\n")

    log.info(f"Server started on {args.host}:{args.port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down server...")
        server.server_close()


if __name__ == "__main__":
    main()
