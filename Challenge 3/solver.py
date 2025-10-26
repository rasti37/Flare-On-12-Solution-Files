import hashlib, struct, zlib
from Crypto.Cipher import AES

def AES_CBC_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)

def AES_ECB_decrypt(key: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).decrypt(data)

def AES_CBC_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)

def verify_perms(key: bytes, perms: bytes, p: int, metadata_encrypted: bool) -> bool:
    b8 = b"T" if metadata_encrypted else b"F"
    p1 = struct.pack("<I", p) + b"\xff\xff\xff\xff" + b8 + b"adb"
    p2 = AES_ECB_decrypt(key, perms)
    return p1 == p2[:12]

def verify_user_password(R: int, password: bytes, u_value: bytes, ue_value: bytes) -> bytes:
    password = password[:127]
    if calculate_hash(R, password, u_value[32:40], b"") != u_value[:32]:
        return b""
    iv = bytes(0 for _ in range(16))
    tmp_key = calculate_hash(R, password, u_value[40:48], b"")
    return AES_CBC_decrypt(tmp_key, iv, ue_value)

def calculate_hash(R: int, password: bytes, salt: bytes, udata: bytes) -> bytes:
    # from https://github.com/qpdf/qpdf/blob/main/libqpdf/QPDF_encryption.cc
    K = hashlib.sha256(password + salt + udata).digest()
    if R < 6:
        return K
    count = 0
    while True:
        count += 1
        K1 = password + K + udata
        E = AES_CBC_encrypt(K[:16], K[16:32], K1 * 64)
        hash_fn = (
            hashlib.sha256,
            hashlib.sha384,
            hashlib.sha512,
        )[sum(E[:16]) % 3]
        K = hash_fn(E).digest()
        if count >= 64 and E[-1] <= count - 32:
            break
    return K[:32]

enc_stream = bytes.fromhex('B10178B86C1CDDC49F5859250096FCDAA9C6AF92DCFAA83F0DC63DFEE8DCD3036D8CB9C1A7B58D951B9C0C46B32ACC84542F97E884956C5738DAF4A5A42F661BC84196F6E2B47F8FA1A1CE9FAFB5F00D0E04FECDD018A8A47A8533ADFF85337ACC75D87EB3F6B5E66A357C2E45C31EE46D9F0EF51844C35719F1BDC62A6785CE14848611BC029DD2EDD704ECBD745423C25FE4B51B1C27A2DFE4F3AD0628D26018EDC298DDC7A758F5EA131FD645E9C8936E232778022CBACA6484A829318CC7DBDE5B940A05BB478AAD7BE0B1B67B69F3788E50A71B179C6D96A2DF8F84E81DB2E2864E20C11435526D03A0DE12373E36082A0B92B42A877D4F1B970FF60A756668A58FE193037BB5035C291752311FADFBCD02AA7300A1D7805D02A755B8BD3DE0735897CAF86FCAAF1115536C00C388C0FAED44895F58365ED384EDD0E8E9')
V = 5
R = 6
P = -1
P = (P + 0x100000000) % 0x100000000
U = bytes.fromhex('18FC6DFEDFF4B5E8E401C248D2BCF8B66BEBBCDA0ECD1D63154254953666D2C5A4C38D549F59144DF11B6A1831324A77')
UE = bytes.fromhex('13D23367FB9F891065947D20FB93834AC4567762B6FBD00672B35748617D3FEB')
O = bytes.fromhex('762FCE975E1C3377E9578858C6F09ADB33C6DC9B30A47E415BDC77767593746D844C6C395760934191698CF21E9F58AB')
OE = bytes.fromhex('DD8B925C5C7A5206F54338C3A9EDB9CBFAA86745F2849FF09C936DC28452CCCAF5')
perms = bytes.fromhex('47B24B909144C7BD8F1BB5F94865B4E2')
password = b''

assert calculate_hash(R, password, U[32:40], b"") == U[:32]
key = verify_user_password(R, password, U, UE)
assert verify_perms(key, perms, P, True)

cipher = AES.new(key, AES.MODE_CBC, enc_stream[:16])
compressed_data = cipher.decrypt(enc_stream[16:])

raw_data = open('strip.jpg', 'rb').read()

from PIL import Image
img = Image.open('strip.jpg').convert('L')

print(bytes(list(img.getdata())))