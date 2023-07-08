import os

from attacks.Attack import Attack
from utils import replace_block_number, get_block_number, xor
from exceptions import BadPaddingException


class PaddingOracleAttack(Attack):
    def __init__(self, encrypt, decrypt, block_size, server):
        super().__init__(encrypt, decrypt, block_size, server)

    def run(self):
        to_decrypt = bytes.fromhex(input("Enter the ciphertext to decrypt (in hexadecimal): ").strip())
        self.attack(to_decrypt)

    def attack(self, to_decrypt: bytes):
        plaintext = b''
        amount_blocks = len(to_decrypt) // self._block_size

        # go from second to last block to the first block
        for i in range(amount_blocks - 1, 0, -1):
            rand_block = bytearray(os.urandom(self._block_size))
            i_data = bytearray(b'\x00' * self._block_size)
            for j in range(self._block_size - 1, -1, -1):
                for k in range(0xff):
                    rand_block[j] = k
                    replaced = replace_block_number(to_decrypt, i - 1, rand_block, self._block_size)
                    try:
                        self._decrypt(replaced.hex(), self._server)
                        print(f"Found byte: {k}")
                        inter = k ^ (16 - j)
                        print(f"Intermediate value: {inter}")
                        i_data[j] = inter
                        for l in range(j, self._block_size):
                            rand_block[l] = i_data[l] ^ (16 - j + 1)
                        break
                    except BadPaddingException:
                        continue
            plaintext = xor(i_data, get_block_number(to_decrypt, i - 1, self._block_size)) + plaintext
            print(f"Decrypted: {plaintext}")
            to_decrypt = to_decrypt[:-16]

