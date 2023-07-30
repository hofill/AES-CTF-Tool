class Attack:
    def __init__(self, encrypt, decrypt, block_size, server, search_space = (0, 256)):
        self._encrypt = encrypt
        self._decrypt = decrypt
        self._block_size = block_size
        self._server = server
        self._search_space = search_space
