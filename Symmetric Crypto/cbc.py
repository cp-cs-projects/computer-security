from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
iv = get_random_bytes(16)

def cbc(paddedMessage):
   # Generate new AES CBC cipher, using global key and IV
   cbcCipher = AES.new(key, AES.MODE_CBC, iv)
   cipherText = b""


   # Encrypt block by block
   for i in range(0, len(paddedMessage), 16):
       block = paddedMessage[i : i + 16]
       encryptedBlock = cbcCipher.encrypt(block)
       cipherText += encryptedBlock
       cbcCipher = AES.new(key, AES.MODE_CBC, encryptedBlock)


   return cipherText



def submit(userInput):
   # Translate and pre-/post-pend the message
   userInput = userInput.translate({59: "%3B", 61: "%3D"})
   message = b"userid=456;userdata=" + bytes(userInput, encoding = "utf-8") + b";session-id=31337"


   # Pad the message
   padBytes = 16 - (len(message) % 16)
   padText = padBytes.to_bytes(1, "big")
   message += (padText * padBytes)
   print("Padded message: {}".format(message))


   # Encrypt the message
   cipherText = cbc(message)
   print("Cipher text: {}".format(cipherText))
   return cipherText

def verify(cipherText):
   # Generate new AES CBC cipher for decoding
   cbcCipher = AES.new(key, AES.MODE_CBC, iv)
   decoded = b""


   # Decrypt the message
   for i in range(0, len(cipherText), 16):
       block = cipherText[i:i + 16]
       decryptedBlock = cbcCipher.decrypt(block)
       decoded += decryptedBlock
       cbcCipher = AES.new(key, AES.MODE_CBC, block)


   # Return whether the decrypted message has the admin tag
   print("Decoded message: {}".format(decoded))
   return b";admin=true;" in decoded


def modifyCipher(cipherText):
   # Isolate the desired block (first) and get the bits we want to flip
   firstBlock = cipherText[:16]
   flipBits = b"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00"


   # Xor the block with the changed bits and replace that block in the ciphertext
   delta = bytes(a ^ b for (a, b) in zip(firstBlock, flipBits))
   cipherText = delta + cipherText[16:]


   return cipherText


def main():
   userInput = input("Enter a string: ")
   cipherText = submit(userInput)
   manipulatedText = modifyCipher(cipherText)
   isAdmin = verify(manipulatedText)
   print("Is admin: {}".format(isAdmin))
   # :admin<true

if __name__ == "__main__":
   main()
