from Crypto.Cipher import ARC4

LEAD_RESEARCHER_SIGNATURE = b'm\x1b@I\x1dAoe@\x07ZF[BL\rN\n\x0cS'
ENCRYPTED_CHIMERA_FORMULA = b'r2b-\r\x9e\xf2\x1fp\x185\x82\xcf\xfc\x90\x14\xf1O\xad#]\xf3\xe2\xc0L\xd0\xc1e\x0c\xea\xec\xae\x11b\xa7\x8c\xaa!\xa1\x9d\xc2\x90'

user_signature = b''.join(bytes([s ^ (i + 42)]) for i, s in enumerate(LEAD_RESEARCHER_SIGNATURE))

cipher = ARC4.new(user_signature)

print(cipher.decrypt(ENCRYPTED_CHIMERA_FORMULA))