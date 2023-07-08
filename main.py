from BCDetector import BCDetector
from pwn import *

from exceptions import BadPaddingException

context.log_level = 'critical'


class Det(BCDetector):
    def __init__(self):
        super().__init__(save_to_file=True, server=True)

    def decrypt(self, data, server: process):
        server.recvuntil(b"> ")
        server.sendline(b"2")
        server.recvuntil(b": ")
        server.sendline(data.encode())
        response = server.readline().strip()
        if response == b"Padding is incorrect.":
            raise BadPaddingException
        return response.decode()

    def encrypt(self, data, server: process):
        server.recvuntil(b"> ")
        server.sendline(b"1")
        server.sendline(data.encode())
        return server.readline().strip().split(b": ")[1].decode()

    def init_server(self):
        return process(["./test_servers/ecb.py"])


if __name__ == "__main__":
    detector = Det()
    detector.begin()
