# based on https://gist.github.com/mdonkers/63e115cc0c79b4f6b8b3a6b797e485c7

from http.server import BaseHTTPRequestHandler, HTTPServer
from good_cipher import encrypt
import logging, json
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwn import xor

IDENTIFIER = b"peanut"
# replace with your <username>@<domain>
PC_NAME = b"r4sti@DESKTOP-J6GEJCI"
# replace with the exact (UTC) hour (%H) that you run the binary (range: [00, 23])
H = b"01"

h1 = sha256(PC_NAME).digest()
h2 = sha256(IDENTIFIER + H).digest()

KEY = xor(h1, h2)
IV = bytes(range(16))

n = 0
messages = [
    {"sta": "ok"},
    {"msg":"no_op"},
    {"msg": "cmd", "d": {"cid": 6, "dt": 1, "np": "TheBoss@THUNDERNODE"}},
    {"msg": "cmd", "d": {"cid": 2, "line": "whoami"}},
    {"msg":"no_op"},
]

class S(BaseHTTPRequestHandler):
    def do_GET(self):
        logging.info("\n\nGET Request!\nPath: %s\nHeaders:\n%s", str(self.path), str(self.headers))
        self.send_response(200)
        self.send_header('Server', 'SimpleHTTP/0.6 Python/3.10.11')
        self.send_header('Date', 'Wed, 20 Aug 2025 06:12:07 GMT')
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        global n
        enc_message = AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(json.dumps(messages[n]).encode(), 16)).hex()
        payload = json.dumps({'d': enc_message}).encode()
        print(f'[+] Sending encrypted command {payload = }')
        print(f'[DEBUG] Plaintext command = {messages[n]}')
        n += 1
        self.wfile.write(payload)

    def do_POST(self):
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        logging.info("\n\nPOST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n", str(self.path), str(self.headers), post_data.decode('utf-8'))
        self.send_response(200)
        self.send_header('Server', 'SimpleHTTP/0.6 Python/3.10.11')
        self.send_header('Date', 'Wed, 20 Aug 2025 06:12:07 GMT')
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        global n
        enc_message = AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(json.dumps(messages[n]).encode(), 16)).hex()
        payload = json.dumps({'d': enc_message}).encode()
        print(f'[+] Sending encrypted command {payload = }')
        print(f'[DEBUG] Plaintext command = {messages[n]}')
        n += 1
        self.wfile.write(payload)

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