#!/usr/bin/env python3
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = b'\xa5\x150W\xe9v\x1f\xd6Ru\xf5\xf7#\xfc\x83\x18'
IV = os.urandom(16)
BLOCK_SIZE = 16
# 3b5129ef8921aec77a5276d6c5aec0a757523712ae0f8946e30ab1f2ed22e4f0


def encrypt_data():
    aes = AES.new(KEY, AES.MODE_CBC, iv=IV)
    data = pad(bytes.fromhex(input("Data (HEX): ").strip()), BLOCK_SIZE)
    encrypted = aes.encrypt(data)
    print(IV.hex() + encrypted.hex())


def decrypt_data():
    data = bytes.fromhex(input("Data (HEX): ").strip())
    iv = data[:16]
    data = data[16:]
    aes = AES.new(KEY, AES.MODE_CBC, iv=iv)
    print(unpad(aes.decrypt(data), BLOCK_SIZE).hex())


if __name__ == "__main__":
    functions = {
        "1": encrypt_data,
        "2": decrypt_data
    }

    options = """
    1. Encrypt Data
    2. Decrypt Data
    q. Quit"""

    while True:
        print(options)
        option = input("> ")
        try:
            if option not in functions.keys():
                quit()
            functions[option]()
        except Exception as e:
            print("Padding is incorrect.")
