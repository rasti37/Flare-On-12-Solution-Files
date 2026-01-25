# based on https://gist.github.com/mdonkers/63e115cc0c79b4f6b8b3a6b797e485c7

from http.server import BaseHTTPRequestHandler, HTTPServer
from good_cipher import encrypt
import logging, json

class S(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        if self.path != "/good":
            self.send_error(404, "Not Found noob")
            return
        
        logging.info("\nGET request,\nPath: %s\nHeaders:\n%s", str(self.path), str(self.headers))
        self.send_response(200)
        self.send_header('Server', 'SimpleHTTP/0.6 Python/3.10.11')
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        payload = json.dumps({'sta': 'excellent', 'ack': 'peanut@theannualtraditionofstaringatdisassemblyforweeks.torealizetheflagwasjustxoredwiththefilenamethewholetime.com:8080'})
        self.wfile.write(json.dumps({"d": encrypt(payload.encode()).hex()}).encode())

def run(server_class=HTTPServer, handler_class=S, port=8080):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')

if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()