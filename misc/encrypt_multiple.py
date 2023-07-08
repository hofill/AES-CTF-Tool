# Import AES
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Import OS
import os


# Key and IV/Nonce
key = os.urandom(16)
iv = bytes.fromhex("0ef7de99e694b87ccb2db8c249c26695")
nonce = bytes.fromhex("4796ee073c2cbfce")

# Plaintext
plaintext = b''
for i in range(0, 17):
    plaintext += b'a'
    print("Plaintext: " + str(plaintext))
    # Encrypt using AES in ECB, CBC, CFB, OFB, CTR modes
    # ECB
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    print("ECB: " + str(ciphertext.hex()))
    # CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    print("CBC: " + str(ciphertext.hex()))
    # CBC, IV prepended
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    print("CBC, IV prepended: " + str(iv.hex()) + str(ciphertext.hex()))
    # CFB
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(plaintext)
    print("CFB: " + str(ciphertext.hex()))
    # CFV, IV prepended
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(plaintext)
    print("CFB, IV prepended: " + str(iv.hex()) + str(ciphertext.hex()))
    # OFB
    cipher = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher.encrypt(plaintext)
    print("OFB: " + str(ciphertext.hex()))
    # OFB, IV prepended
    cipher = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher.encrypt(plaintext)
    print("OFB, IV prepended: " + str(iv.hex()) + str(ciphertext.hex()))
    # CTR
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    print("CTR: " + str(ciphertext.hex()))
    # CTR, nonce prepended
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    print("CTR, nonce prepended: " + str(nonce.hex()) + str(ciphertext.hex()))
    print()

