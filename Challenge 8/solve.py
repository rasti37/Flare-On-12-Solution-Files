from z3 import *

MSK32 = 0xffffffff
MSK64 = 0xffffffffffffffff
target = 0x0BC42D5779FEC401
LENGTH = 25
BITS = 4
LOWER_BOUND = 0 if BITS == 4 else 0x30
UPPER_BOUND = 9 if BITS == 4 else 0x39

def H(d):
    x = d ^ 61
    C = (0x27D4EB79 * (((x + 8*x) >> 4) ^ (x + 8*x))) & MSK32
    return (((C >> 0x0f) ^ C) >> 4) & MSK32

def H_z3(d):
    msk = MSK32
    t = d ^ BitVecVal(61, 32)
    u = (t + (t << 3)) & BitVecVal(msk, 32)
    v = LShR(u, 4) ^ u
    C = (BitVecVal(0x27D4EB79, 32) * v) & BitVecVal(MSK32, 32)
    w = LShR(C, 15) ^ C
    res = LShR(w, 4)
    return res

def compute_pwd_hash(pwd):
    h = 0
    for i, ch in enumerate(pwd):
        l = i + 1
        h = (h + H(256*l + ch) * H(l)) & MSK64
    return h

# Sanity Check #
assert compute_pwd_hash(b'1341269870425878547834758') == 0x0614A9810FC5F5D0
################

def lookup_conditional_sum(ch, vals):
    terms = []
    for d in range(10):
        is_d = (ch == BitVecVal(d, BITS))
        terms.append(If(is_d, vals[d], BitVecVal(0, 64)))
    return Sum(terms)

LOOKUP_TABLE = {l: [(H(256*l + 0x30 + d) * H(l)) & MSK64 for d in range(LOWER_BOUND, UPPER_BOUND + 1)] for l in range(1, LENGTH+1)}

s = Solver()

inp = [BitVec(f'x{i}', BITS) for i in range(LENGTH)]

for ch in inp:
    s.add(ULE(ch, BitVecVal(UPPER_BOUND, BITS)))

h = BitVecVal(0, 64)
for i, ch in enumerate(inp):
    l = i+1
    vals = [BitVecVal(LOOKUP_TABLE[l][d], 64) for d in range(10)]
    sm = lookup_conditional_sum(ch, vals)
    h = h + sm

s.add(h == BitVecVal(target, 64))

import time
start = int(time.time())
if s.check() == sat:
    total = int(time.time()) - start
    model = s.model()
    password = ''.join(str(v) for v in [model[b].as_long() for b in inp]).encode()
    print(f'{password = }')
    assert compute_pwd_hash(password) == target
    print(f'{compute_pwd_hash(password) = :x}')
    print(f'{total = }')
else:
    print("UNSAT — no solution with the current constraints.")