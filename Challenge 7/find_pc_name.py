from good_cipher import decrypt, sbox

enc_good = bytes.fromhex('085d8ea282da6cf76bb2765bc3b26549a1f6bdf08d8da2a62e05ad96ea645c685da48d66ed505e2e28b968d15dabed15ab1500901eb9da4606468650f72550483f1e8c58ca13136bb8028f976bedd36757f705ea5f74ace7bd8af941746b961c45bcac1eaf589773cecf6f1c620e0e37ac1dfc9611aa8ae6e6714bb79a186f47896f18203eddce97f496b71a630779b136d7bf0c82d560')
known_pt = b'@theannualtraditionofstaringatdisassemblyforweeks.torealizetheflagwasjustxoredwiththefilenamethewholetime.com:8080'

for i in range(len(enc_good) - len(known_pt)):
    candidate_ct = enc_good[i:len(known_pt)+i]
    assert len(candidate_ct) == len(known_pt)
    enc_seq = [(sbox[c] - (j+i+1)) & 0xff for j, c in enumerate(candidate_ct)]
    pc_name = [a ^ b for a, b in zip(enc_seq, known_pt)]
    if all(0x20 < k < 0x7e for k in pc_name):
        print('FOUND PC NAME:', bytes(pc_name))