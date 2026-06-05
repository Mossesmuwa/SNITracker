# warning_server.py (upgraded)

from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime
import logging
import argparse

# -----------------------
# CLI arguments
# -----------------------
parser = argparse.ArgumentParser(description="Warning / Block Page Server")
parser.add_argument("--host", default="0.0.0.0")
parser.add_argument("--port", type=int, default=8080)
parser.add_argument("--message", default="This website is not allowed.")
args = parser.parse_args()


# -----------------------
# Logging
# -----------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BLOCK-SERVER] %(message)s"
)
log = logging.getLogger("warning-server")


# -----------------------
# HTML template
# -----------------------
def build_html(message: str):
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Blocked</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            text-align: center;
            padding-top: 60px;
            background: #f4f4f4;
        }}
        .box {{
            background: white;
            display: inline-block;
            padding: 30px 40px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #d9534f;
        }}
        p {{
            color: #333;
        }}
    </style>
</head>
<body>
    <div class="box">
        <h1>Access Blocked</h1>
        <p>{message}</p>
        <small>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</small>
    </div>
</body>
</html>
""".encode("utf-8")


HTML = build_html(args.message)


# -----------------------
# Request Handler
# -----------------------
class BlockHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        # override default noisy logging
        log.info("%s - %s" % (self.address_string(), format % args))

    def do_GET(self):
        self.send_response(200)

        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")

        self.end_headers()
        self.wfile.write(HTML)

        log.info(f"Blocked page served to {self.client_address[0]} path={self.path}")

    def do_POST(self):
        # same response for POST requests
        self.do_GET()


# -----------------------
# Server start
# -----------------------
def main():
    server = HTTPServer((args.host, args.port), BlockHandler)

    log.info(f"Warning server running on http://{args.host}:{args.port}")
    log.info("Press CTRL+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down server...")
        server.server_close()


if __name__ == "__main__":
    main()
