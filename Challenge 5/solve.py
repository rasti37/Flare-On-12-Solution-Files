obf_graph = eval(open('graph.txt').read())
ncases = len(obf_graph)

def traverse(src, pwd):
    if len(pwd) == 16:
        print(pwd)
        return
    
    for dst in obf_graph[src]:
        nxt = dst[0]
        ch = dst[1]
        traverse(nxt, pwd+ch)

'''
Generates random valid passwords of length < 16

pwd = ''
path = []
i = 0
while len(pwd) != 15:
    dst = obf_graph[i][0]
    pwd += dst[1]
    path.append(i)
    i = dst[0]
    print(f'{path = }')
print(pwd)
'''

pwd = 'iqg0nSeCHnOMPm2Q' # traverse(0, '')

from Crypto.Cipher import AES
import hashlib

KEY = hashlib.sha256(pwd.encode()).digest()
enc_data = bytes.fromhex('81a829124fa62d0dfb28e5f1783d5c699cafad1c6f8ef523f1b890adb4d71e66625f85f80ff61e27d3909c0da8a05dee12555fd4e6726c220b22709ff1676721')
assert len(enc_data) % 16 == 0
IV, enc_flag = enc_data[:16], enc_data[16:]
print(AES.new(KEY, AES.MODE_CBC, IV).decrypt(enc_flag))
