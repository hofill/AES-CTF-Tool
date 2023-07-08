from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

key = os.urandom(16)

def common_pad(pt):
    if len(pt) % 16 == 0:
        return pt
    else:
        return pt + b"\x00" * (16 - len(pt) % 16)

aes = AES.new(key, AES.MODE_ECB)
data = b"a" * 15
ciphertext = aes.encrypt(pad(data, AES.block_size))
print(ciphertext.hex())
print(len(ciphertext))
ciphertext = aes.encrypt(common_pad(data))
print(ciphertext.hex())
print(len(ciphertext))
print()
aes = AES.new(key, AES.MODE_ECB)
data = b"a" * 16
ciphertext = aes.encrypt(pad(data, AES.block_size))
print(ciphertext.hex())
print(len(ciphertext))
ciphertext = aes.encrypt(common_pad(data))
print(ciphertext.hex())
print(len(ciphertext))