class Attack:
    def __init__(self, encrypt, decrypt, block_size, server):
        self._encrypt = encrypt
        self._decrypt = decrypt
        self._block_size = block_size
        self._server = server
