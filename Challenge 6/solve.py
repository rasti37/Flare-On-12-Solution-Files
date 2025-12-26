from Crypto.Util.number import GCD, bytes_to_long, long_to_bytes, isPrime
from Crypto.PublicKey import RSA
import json, math

xor = lambda a, b : bytes(x^y for x, y in zip(a, b))

def extract_lcg_parameters(states):
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zeroes = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    n = GCD(*zeroes)
    m = (states[3] - states[2]) * pow(states[2] - states[1], -1, n) % n
    c = (states[4] - m * states[3]) % n
    assert isPrime(n)
    # assert isPrime(m)
    assert isPrime(c)
    return m, c, n

class LCGOracle:
    def __init__(self, m, c, n, seed):
        self.m = m
        self.c = c
        self.n = n
        self.state = seed
    
    def get_next(self):
        self.state = (self.m * self.state + self.c) % self.n
        return self.state

def get_rsa_primes(N, m, c, n, seed):
    print('[RSA] Generating RSA key from on-chain LCG primes...')
    lcg_for_rsa = LCGOracle(m, c, n, seed)
    primes = []
    iteration_limit = 10000
    iterations = 0
    while len(primes) < 8 and iterations < iteration_limit:
        candidate = lcg_for_rsa.get_next()
        iterations += 1
        if candidate.bit_length() == 256 and isPrime(candidate):
            if N % candidate == 0:
                primes.append(candidate)
                # print(f'{candidate = }')
    return primes

logs = json.loads(open('chat_log.json', 'rb').read())

ciphertexts = []
conversation_times = []
plaintexts = []
for l in logs:
    if l['mode'] == 'LCG-XOR':
        ciphertexts.append(bytes.fromhex(l['ciphertext']))
        conversation_times.append(int.to_bytes(l['conversation_time'], length=32, byteorder='big'))
        pt = l['plaintext'].encode()
        plaintexts.append(pt + b'\x00'*(32-len(pt)))

states = []
for ct, c, pt in zip(ciphertexts, conversation_times, plaintexts):
    states.append(bytes_to_long(xor(xor(ct, c), pt)))

m, c, n = extract_lcg_parameters(states)
print(f'{m = }')
print(f'{c = }')
print(f'{n = }')

key = RSA.import_key(open('public.pem', 'rb').read())
N, e = key.n, key.e
primes = get_rsa_primes(N, m, c, n, states[6])

final_prime = N // math.prod(primes)
assert isPrime(final_prime) and final_prime.bit_length() == 256
primes.append(final_prime)
assert N == math.prod(primes)

phi = math.prod([p-1 for p in primes])

rsa_ciphertexts = [
    bytes.fromhex(logs[-2]['ciphertext']),
    bytes.fromhex(logs[-1]['ciphertext'])
]

d = pow(e, -1, phi)

for rsa_ct in rsa_ciphertexts:
    ct = bytes_to_long(rsa_ct[::-1])
    msg = long_to_bytes(pow(ct, d, N))
    print(msg)