from Certainty import Certainty
from exceptions import *


class BCState:
    """
    Class that holds the state of the detector
    """

    def __init__(self):
        """
        Initialises the state
        """
        self.__certainty = Certainty()
        self.__category = None  # ECB, CBC, ECB_CBC or Stream
        self.__detected_block_cipher_mode = None  # ECB, CBC, CFB, OFB or CTR

        self.__block_size = None
        self.__block_size_combo_history = []

        self.__padding_method = None  # PKCS7, None, Block, Block+
        self.__padding_method_combo_history = []

        self.__provides_iv = None
        self.__past_combos = []

        self.__repeats_iv = False

    def initialize_no_server(self):
        self.__block_size = 16
        self.__padding_method = 'PKCS7'

    def add_combo(self, ciphertext: bytes, plaintext: bytes):
        """
        Adds a combo to the state, and analyses them to determine the block cipher mode.

        :param ciphertext: The ciphertext
        :param plaintext: The plaintext
        :return: True if the block cipher mode is determined
        """
        self.__past_combos.append((ciphertext, plaintext))
        if not self.__certainty.has_certainties():
            if self.__category == "ECB_CBC":
                self.check_category_block(ciphertext)
                if self.__certainty.has_certain_mode():
                    return True
            elif self.__category == "Stream":
                self.check_category_stream(ciphertext, plaintext)
                if self.__certainty.has_certain_mode():
                    return True
            elif self.__category is None:
                self.check_category_block(ciphertext)
                if plaintext is not None:
                    self.check_category_stream(ciphertext, plaintext)
            else:
                self.__certainty.certain(self.__category)

        # Test same IV
        self.__repeats_iv = self.check_repeat_iv()

    def add_combo_simple(self, ciphertext: bytes, plaintext: bytes):
        self.__past_combos.append((ciphertext, plaintext))

        if not self.__certainty.has_certain_mode():
            # Check if the ciphertext is a multiple of the block size
            if len(ciphertext) % self.__block_size != 0:
                self.__category = "Stream"
                if len(plaintext) + 16 == len(ciphertext):
                    probabilities = {
                        "ECB": 0,
                        "CBC": 0,
                        "CFB": 90,
                        "OFB": 90,
                        "CTR": 10,
                    }
                else:
                    probabilities = {
                        "ECB": 0,
                        "CBC": 0,
                        "CFB": 10,
                        "OFB": 10,
                        "CTR": 90,
                    }
                self.__certainty.normalize(probabilities)
                return True
            # Check ECB
            has_identical_blocks = self.check_identical_blocks(ciphertext)
            if has_identical_blocks:
                self.__certainty.certain("ECB")
                self.__detected_block_cipher_mode = "ECB"
                return True

            # Check CBC
            # Check if plaintext has two identical blocks
            if plaintext is not None:
                print(plaintext)
                has_identical_blocks_pt = self.check_identical_blocks(plaintext)
                print(has_identical_blocks_pt)
                has_identical_blocks_ct = self.check_identical_blocks(ciphertext)
                if has_identical_blocks_pt and not has_identical_blocks_ct:
                    self.__certainty.certain("CBC")
                    self.__detected_block_cipher_mode = "CBC"
                    return True

            probabilities = {
                "ECB": 100,
                "CBC": 100,
                "CFB": 10,
                "OFB": 10,
                "CTR": 10,
            }
            self.__certainty.normalize(probabilities)

        # Test repeated IV
        self.__repeats_iv = self.check_repeat_iv()

    def check_repeat_iv(self):
        # Get two identical stored plaintexts
        for i in range(len(self.__past_combos)):
            for j in range(len(self.__past_combos)):
                if i == j:
                    continue
                if self.__past_combos[i] == self.__past_combos[j]:
                    return True
        return False

    def check_category_block(self, ciphertext):
        """
        Determines the block ciphers modes of operation by checking aspects specific to block ciphers like ECB and CBC

        :param ciphertext: The ciphertext to check
        :return: None
        """
        has_identical_blocks = self.check_identical_blocks(ciphertext)
        if has_identical_blocks:
            self.__certainty.certain("ECB")
            self.__detected_block_cipher_mode = "ECB"
        else:
            self.__certainty.certain("CBC")
            self.__detected_block_cipher_mode = "CBC"

    def check_category_stream(self, ciphertext: bytes, plaintext: bytes):
        """
        Determines the block ciphers modes of operation by checking aspects specific to stream ciphers like CFB, OFB and CTR

        :param ciphertext: The ciphertext to check
        :param plaintext: The plaintext to check
        :return: None
        """
        if len(ciphertext) > len(plaintext):
            self.__provides_iv = True
            if len(ciphertext) >= len(plaintext) + 16:
                probabilities = {
                    "ECB": 0,
                    "CBC": 0,
                    "CFB": 75,
                    "OFB": 75,
                    "CTR": 25,
                }
                self.__certainty.normalize(probabilities)
            else:
                probabilities = {
                    "ECB": 0,
                    "CBC": 0,
                    "CFB": 5,
                    "OFB": 5,
                    "CTR": 95,
                }
                self.__certainty.normalize(probabilities)
        elif len(ciphertext) == len(plaintext):
            self.__provides_iv = False
            probabilities = {
                "ECB": 0,
                "CBC": 0,
                "CFB": 33.33,
                "OFB": 33.33,
                "CTR": 33.33,
            }
            self.__certainty.normalize(probabilities)
        else:
            raise Exception("Ciphertext is shorter than plaintext")

    def check_identical_blocks(self, ciphertext):
        """
        Iterates through the ciphertext and checks if there are any repeating blocks

        :param ciphertext: The ciphertext to check
        :return: True if there are repeating blocks, False if there are not
        """
        if len(ciphertext) % self.__block_size != 0:
            return False

        # Check if the ciphertext has any repeating blocks
        for i in range(0, len(ciphertext), self.__block_size):
            block = ciphertext[i:i + self.__block_size]
            if ciphertext.count(block) > 1:
                return True
        return False

    def add_block_size_check(self, plaintext_length, ciphertext):
        """
        Checks the block size of the cipher using many encryption/decryption combos

        :param plaintext_length: The plaintext that was encrypted to get the ciphertext's length
        :param ciphertext: The ciphertext
        :return: True if more checks are needed, False if the block size has been determined
        """
        ciphertext = bytes.fromhex(ciphertext)
        self.__block_size_combo_history.append((plaintext_length, ciphertext))
        if len(self.__block_size_combo_history) == 1:
            return True

        # Compare the new ciphertext to the old ciphertext
        previous_combo = self.__block_size_combo_history[len(self.__block_size_combo_history) - 2]
        old_ciphertext = previous_combo[1]
        if len(ciphertext) == len(old_ciphertext):
            return True
        elif len(ciphertext) == len(old_ciphertext) + 1:
            # The block size is 1
            self.__block_size = 1
            self.__category = 'Stream'
            self.__padding_method = 'None'
            return False
        elif len(ciphertext) > len(old_ciphertext) + 1:
            # The block size is the difference between the two lengths
            self.__block_size = len(ciphertext) - len(old_ciphertext)
            self.__category = 'ECB_CBC'
            return False
        else:
            raise BlockSizeUnidentifiableException("The block size is not findable")

    def check_padding(self, encrypt_method, instance):
        """
        Checks the padding method of the cipher using many encryption/decryption combos

        :param plaintext: The plaintext that was encrypted to get the ciphertext
        :param ciphertext: The ciphertext
        :return: None
        """
        if self.__padding_method is not None:
            return

        if self.__block_size is None:
            return

        if self.__block_size == 1:
            self.__padding_method = 'None'
            return

        to_encrypt = b'\x10' * (self.__block_size - 1)
        ciphertext_full_minus_one = bytes.fromhex(encrypt_method(to_encrypt.hex(), instance))
        ciphertext_full = bytes.fromhex(encrypt_method((to_encrypt + b'\x10').hex(), instance))
        if len(ciphertext_full) - len(ciphertext_full_minus_one) == self.__block_size:
            self.__padding_method = 'Block+'
        else:
            self.__padding_method = 'Block'
            return

        if self.__padding_method == 'Block+' and self.__detected_block_cipher_mode == 'ECB':
            # get last block and second to last block
            last_block = ciphertext_full[-self.__block_size:]
            second_to_last_block = ciphertext_full[-(self.__block_size * 2):-(self.__block_size)]
            if last_block == second_to_last_block:
                self.__padding_method = 'PKCS7'
                return
            return

    def check_padding_method_determinable(self, encrypt_method, instance):
        """
        Checks if the padding method can be determined

        :param encrypt_method: The encryption method to use
        :param instance: The server instance to use
        :return: True if the padding method can be determined, False otherwise
        """
        # The padding method can be determined if
        # 1. The block size is known
        # 2. There is no message concatenated to the plaintext
        # 3. If there is a message concatenated to the plaintext, that message is known or is a multiple of the block
        # size

        if self.__block_size is None:
            return False

        to_encrypt = b'A' * (self.__block_size - 1)
        ciphertext_full_minus_one = bytes.fromhex(encrypt_method(to_encrypt.hex(), instance))
        ciphertext_full = bytes.fromhex(encrypt_method((to_encrypt + b'A').hex(), instance))
        ciphertext_full_plus_one = bytes.fromhex(encrypt_method((to_encrypt + b'AA').hex(), instance))
        if len(ciphertext_full) == len(ciphertext_full_minus_one) == len(ciphertext_full_plus_one):
            return False
        else:
            return True

    def get_block_size(self):
        return self.__block_size

    def get_padding_method(self):
        return self.__padding_method

    def get_block_cipher_mode_category(self):
        return self.__category

    def get_block_cipher_mode(self):
        return self.__detected_block_cipher_mode

    def get_certainty(self):
        return self.__certainty

    def get_reuse_iv(self):
        return self.__repeats_iv
