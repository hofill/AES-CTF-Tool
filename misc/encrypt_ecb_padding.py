# AES
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

key = os.urandom(16)

aes = AES.new(key, AES.MODE_ECB)
data = b"\x10" * 16
ciphertext = aes.encrypt(pad(data, AES.block_size))
print(ciphertext.hex()[0:32])
print(ciphertext.hex()[32:64])