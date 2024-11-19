# ECB Encryption Code
def ecb():
   # Read in .bmp file
   openFile = open("mustang.bmp", "rb")
   fileContents = openFile.read()


   # Separate header from image data
   header = fileContents[:54]
   data = fileContents[54:]


   # Add padding to byte align
   padBytes = 16 - (len(data) % 16)
   padText = padBytes.to_bytes(1, 'big')
   data += (padText * padBytes)


   # Generate random key and new AES ECB cipher
   key = get_random_bytes(16)
   ecbCipher = AES.new(key, AES.MODE_ECB)


   # Open file and write header
   writeFile = open("encrypted.bmp", "wb")
   writeFile.write(header)


   # Write encrypted data in 128-bit blocks
   for i in range(0, len(data), 16):
       block = data[i:i + 16]
       writeFile.write(ecbCipher.encrypt(block))


   writeFile.close()