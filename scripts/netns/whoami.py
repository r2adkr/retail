"""A web server that answers with the client's address, for checking what a
host on a routed network sees. Usage: whoami.py ADDRESS PORT"""
import http.server
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.client_address[0].encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


http.server.HTTPServer((sys.argv[1], int(sys.argv[2])), Handler).serve_forever()
