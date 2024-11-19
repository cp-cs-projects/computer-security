
import json
from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import number
from Crypto.Util.Padding import pad, unpad
import random

# RSA with MITM through malleability

def RSA():
   # generate 2 large distinct primes
   p = number.getPrime(1024) #returns random n-bit prime
   q = number.getPrime(1024)

   # Alice sends public key (n,e)
   n = p * q
   phi = (p-1) * (q-1)
   e = 65537
   d = pow(e, -1, phi)

   # Bob computes s for Alice with Alice's public key (n,e)
   s = str(random.randint(0, n))
   encrypted_msg = int.from_bytes(s.encode("ascii"), "little")
   c = pow(encrypted_msg, e, n)

   # MALLORY MANIPULATES WITH CIPHERTEXT
   c_prime = 0 * c

   # Alice computes s
   s = pow(c_prime, d, n)  # 0^d % n will always result in 0. Mallory knows how to compute key.
   kA = SHA256.new(s.to_bytes(1024, 'big'))
   kA = kA.digest()[:16]

   # Mallory computes her key
   kM = SHA256.new((0).to_bytes(1024, 'big'))
   kM = kM.digest()[:16]

   # send and receive c0, adapted from pycryptodome encrypt + decrypt w cbc instructions
   m = b"Hi Bob!"
   c0 = AES.new(kA, AES.MODE_CBC)
   c0_bytes = c0.encrypt(pad(m, AES.block_size))
   iv = b64encode(c0.iv).decode('utf-8')
   ct = b64encode(c0_bytes).decode('utf-8')
   e_m0 = json.dumps({'iv': iv, 'ciphertext': ct})
   print("encrypted msg from alice to bob:", c0_bytes.hex())

   b64 = json.loads(e_m0)
   iv = b64decode(b64['iv'])
   ct = b64decode(b64['ciphertext'])
   d0 = AES.new(kM, AES.MODE_CBC, iv)
   d_m0 = unpad(d0.decrypt(ct), AES.block_size)
   print("MALLORY decrypts message m:", d_m0)

if __name__ == '__main__':
   RSA()