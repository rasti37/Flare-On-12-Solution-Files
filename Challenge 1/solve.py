encoded = b'\xd0\xc7\xdf\xdb\xd4\xd0\xd4\xdc\xe3\xdb\xd1\xcd\x9f\xb5\xa7\xa7\xa0\xac\xa3\xb4\x88\xaf\xa6\xaa\xbe\xa8\xe3\xa0\xbe\xff\xb1\xbc\xb9'

for k in range(256):
    plaintext = b''
    for i, e in enumerate(encoded):
        plaintext += bytes([e^(k+i)])
    if b'@flare-on.com' in plaintext:
        print(k, plaintext)
        break