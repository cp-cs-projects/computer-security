import json
from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import number
from Crypto.Util.Padding import pad, unpad
import random

# MITM of diffie helman key exchange 

def Mitm(p, g):
   # Alice sends p,g

   # Alice and Bob randomly select private key
   a = random.randint(1, p - 2)
   b = random.randint(1, p - 2)
   while a == b:  # different private keys
       b = random.randint(1, p - 2)

   # MALLORY TAMPERS W GENERATOR
   g = 1

   # Alice and Bob privately compute public values
   A = pow(g, a, p)
   B = pow(g, b, p)
   # A and B both = 1

   # Alice receives B, Bob receives A, create secretes
   sA = pow(B, a, p)
   sB = pow(A, b, p)
   # secret = 1 for both

   # hash and truncate output to 16b
   kA = SHA256.new(sA.to_bytes(64, 'big'))  # input padded to multiple of 64b
   kA = kA.digest()[:16]

   kB = SHA256.new(sB.to_bytes(64, 'big'))  # input padded to multiple of 64b
   kB = kB.digest()[:16]

   # mallory figures out keys
   kM = SHA256.new((1).to_bytes(64, 'big'))  # input padded to multiple of 64b
   kM = kM.digest()[:16]

   m0 = b"Hi Bob!"
   c0 = AES.new(kA, AES.MODE_CBC)
   c0_bytes = c0.encrypt(pad(m0, AES.block_size))
   iv = b64encode(c0.iv).decode('utf-8')
   ct = b64encode(c0_bytes).decode('utf-8')
   e_m0 = json.dumps({'iv': iv, 'ciphertext': ct})
   print("Alice encrypts msg to Bob:", c0_bytes.hex())

   b64 = json.loads(e_m0)
   iv = b64decode(b64['iv'])
   ct = b64decode(b64['ciphertext'])
   d0 = AES.new(kM, AES.MODE_CBC, iv)
   d_m0 = unpad(d0.decrypt(ct), AES.block_size)
   print("MALLORY decrypts message m0:", d_m0)

   # c1 to alice
   m1 = b"Hi Alice!"
   c1 = AES.new(kB, AES.MODE_CBC)
   c1_bytes = c1.encrypt(pad(m1, AES.block_size))
   iv = b64encode(c1.iv).decode('utf-8')
   ct = b64encode(c1_bytes).decode('utf-8')
   e_m1 = json.dumps({'iv': iv, 'ciphertext': ct})
   print("Bob encrypts msg to Alice:", c1_bytes.hex())

   b64 = json.loads(e_m1)
   iv = b64decode(b64['iv'])
   ct = b64decode(b64['ciphertext'])
   d1 = AES.new(kM, AES.MODE_CBC, iv)
   d_m1 = unpad(d1.decrypt(ct), AES.block_size)
   print("MALLORY decrypts message m1", d_m1)


if __name__ == '__main__':
   p_list = [0xB10B8F96, 0xA080E01D, 0xDE92DE5E, 0xAE5D54EC, 0x52C99FBC, 0xFB06A3C6
       , 0x9A6A9DCA, 0x52D23B61, 0x6073E286, 0x75A23D18, 0x9838EF1E, 0x2EE652C0
       , 0x13ECB4AE, 0xA9061123, 0x24975C3C, 0xD49B83BF, 0xACCBDD7D, 0x90C4BD70
       , 0x98488E9C, 0x219A7372, 0x4EFFD6FA, 0xE5644738, 0xFAA31A4F, 0xF55BCCC0
       , 0xA151AF5F, 0x0DC8B4BD, 0x45BF37DF, 0x365C1A65, 0xE68CFDA7, 0x6D4DA708
       , 0xDF1FB2BC, 0x2E4A4371]
   g_list = [0xA4D1CBD5, 0xC3FD3412, 0x6765A442, 0xEFB99905, 0xF8104DD2, 0x58AC507F
       , 0xD6406CFF, 0x14266D31, 0x266FEA1E, 0x5C41564B, 0x777E690F, 0x5504F213
       , 0x160217B4, 0xB01B886A, 0x5E91547F, 0x9E2749F4, 0xD7FBD7D3, 0xB9A92EE1
       , 0x909D0D22, 0x63F80A76, 0xA6A24C08, 0x7A091F53, 0x1DBF0A01, 0x69B6A28A
       , 0xD662A4D1, 0x8E73AFA3, 0x2D779D59, 0x18D08BC8, 0x858F4DCE, 0xF97C2A24
       , 0x855E6EEB, 0x22B3B2E5]
   for i in range(len(p_list)):
       p = int(p_list[i])
       g = int(p_list[i])
       print('parameters #%d' % (i + 1))
       Mitm(p, g)
