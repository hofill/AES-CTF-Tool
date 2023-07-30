from attacks.Attack import Attack


class ChosenPlaintextAttack(Attack):
    def __init__(self, encrypt, decrypt, block_size, server):
        super().__init__(encrypt, decrypt, block_size, server)

    def run(self):
        offset = self.find_offset()
        print(f"Offset: {offset} bytes")
        self.attack(offset)

    def find_offset(self):
        k = 0
        while True:
            ciphertext = bytes.fromhex(self._encrypt((b'B' * k + b"A" * self._block_size * 2).hex(), self._server))
            # check if the ciphertext has a repeated block
            for i in range(0, len(ciphertext), self._block_size):
                block = ciphertext[i:i + self._block_size]
                if ciphertext.count(block) > 1:
                    return k
            k += 1
            if k > 100:
                raise Exception("Couldn't find offset")

    def attack(self, offset: int):
        # find the length of the secret
        secret_length_upper = bytes.fromhex(self._encrypt(b'A'.hex(), self._server))
        secret_length_upper = (len(secret_length_upper) // self._block_size + 2) * self._block_size

        data = bytes.fromhex(self._encrypt((b'A' * offset + b'A' * secret_length_upper).hex(), self._server))
        block_number = -1
        for i in range(0, len(data), self._block_size):
            block = data[i:i + self._block_size]
            if data.count(block) > 1:
                # get index of the last block
                block_number = data.rfind(block) // self._block_size
                break

        if block_number == -1:
            raise Exception("Something went wrong")
        print(f"Block number: {block_number}")

        run_at_most = len(data[block_number * self._block_size + self._block_size:])

        i = secret_length_upper + offset
        found = b''
        while i and run_at_most:
            data = bytes.fromhex(self._encrypt((b'A' * (i - 1)).hex(), self._server))
            last_block_value = data[block_number * self._block_size:(block_number + 1) * self._block_size]
            for j in range(self._search_space[0], self._search_space[1]):
                data = bytes.fromhex(self._encrypt((b'A' * (i - 1) + found + bytes([j])).hex(), self._server))
                if data[block_number * self._block_size:(block_number + 1) * self._block_size] == last_block_value:
                    found += bytes([j])
                    print(f"Found: {found.decode()}")
                    break
            i -= 1
            run_at_most -= 1
        if found == b'':
            raise Exception("Couldn't find the secret")

        print(f"Found: {found.decode()}")
