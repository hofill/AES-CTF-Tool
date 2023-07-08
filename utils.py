import base64
import string

BLOCK_SIZE = 16

default_probabilities = {
    "ECB": 0,
    "CBC": 0,
    "CFB": 0,
    "OFB": 0,
    "CTR": 0,
}


def chunks(lst, n):
    """Yield successive n-sized chunks from list."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


class Color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


def calculate_color(amt):
    if amt <= .03:
        return Color.RED
    if amt <= .6:
        return Color.YELLOW
    if amt <= .8:
        return Color.GREEN
    else:
        return Color.GREEN + Color.BOLD


def replace_block_number(ciphertext, number, other_block, block_size):
    return ciphertext[:number * block_size] + other_block + ciphertext[(number + 1) * block_size:]


def get_block_number(ciphertext, number, block_size):
    return ciphertext[number * block_size:(number + 1) * block_size]


def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])
