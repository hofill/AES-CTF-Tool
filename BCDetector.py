from BCState import BCState
from Logger import Logger
from attacks.Attack import Attack
from attacks.ChosenPlaintext import ChosenPlaintextAttack
from attacks.PaddingOracle import PaddingOracleAttack
from exceptions import *


class BCDetector:
    """
    Base class for all detectors. This class should be inherited from and the
    `analyse_server`, `encrypt` and `decrypt` methods should be implemented.

    The `begin` method should be called to start the detector. The analyse_server
    method should return a process object that is used to communicate with the server,
    which will be passed to the encrypt and decrypt method.

    :param save_to_file: Whether to save the results to a file
    :param server: Whether to use a server to decrypt the data
    """

    def __init__(self, **kwargs):
        self.save_to_file = bool(kwargs.get('save_to_file', False))
        self.server = bool(kwargs.get('server', False))
        self.__history = []
        self.__state = BCState()
        self.__logger = Logger(log_to_file=self.save_to_file)
        if not self.server:
            self.__state.initialize_no_server()

        self.__server_instance = None

    def encrypt(self, data, server):
        """
        Unimplemented method that should encrypt the data using the server.

        :param data: The data to encrypt, as hex
        :param server: The server to use
        :return: The encrypted data as bytes
        """
        raise NotImplementedError

    def decrypt(self, data, server):
        """
        Unimplemented method that should decrypt the data using the server.

        :param data: The data to decrypt, as hex
        :param server: The server to use
        :return: The decrypted data as bytes
        """
        raise NotImplementedError

    def init_server(self):
        """
        Unimplemented method that should return a process object that is used to
        communicate with the server.

        :return: A process object
        """
        raise NotImplementedError

    def begin(self):
        """
        Starts the detector. This method should be called after the detector has been
        initialized. This method will call the `analyse_server` method to get the server
        object, then call the `detect` method to start the detection process. If the
        init_server method is not implemented, it will exit with an error.

        If the `save_to_file` parameter is set, the results will be saved to a file.


        :return: None
        """
        try:
            self.__server_instance = self.init_server()
        except NotImplementedError:
            print("ERROR: init_server method not implemented")
            return None
        # Check 3 base encrypted strings to determine ECB, CBC, ECB_CBC or Stream
        self.analyze()

    def check_block_size(self):
        """
        Checks the block size of the cipher using many encryption combos

        :return: None
        """
        max_attempts = 129
        to_encrypt = b''
        while max_attempts:
            to_encrypt += b'\x00'
            encrypted_data = self.encrypt(to_encrypt.hex(), self.__server_instance)
            try:
                if not self.__state.add_block_size_check(len(to_encrypt), encrypted_data):
                    break
            except BlockSizeUnidentifiableException:
                raise BlockSizeUnidentifiableException("Could not determine block size")
            max_attempts -= 1
        if max_attempts == 0:
            raise BlockSizeUnidentifiableException("Could not determine block size")
        else:
            return self.__state.get_block_size()

    def check_block_cipher_mode(self):
        # Get Category
        category = self.__state.get_block_cipher_mode_category()

        if category == "ECB_CBC":
            # Check ECB
            block_size = self.__state.get_block_size()
            to_encrypt = b'\x00' * block_size * 3
            encrypted_data = bytes.fromhex(self.encrypt(to_encrypt.hex(), self.__server_instance))
            self.__state.add_combo(encrypted_data, to_encrypt)
            if self.__state.get_block_cipher_mode() == "ECB" or self.__state.get_block_cipher_mode() == "CBC":
                return self.__state.get_block_cipher_mode()
            else:
                raise BlockCipherModeUnidentifiableException("Could not determine block cipher mode")
        else:
            to_encrypt = b'\x00'
            encrypted_data = bytes.fromhex(self.encrypt(to_encrypt.hex(), self.__server_instance))
            self.__state.add_combo(encrypted_data, to_encrypt)
            return self.__state.get_block_cipher_mode()

    def check_padding_method(self):
        """
        Checks the padding method of the cipher using many encryption combos

        :return: The padding method, None if not found/not applicable
        """
        if not self.__state.check_padding_method_determinable(self.encrypt, self.__server_instance):
            return None

        self.__state.check_padding(self.encrypt, self.__server_instance)
        return self.__state.get_padding_method()

    def analyze(self):
        """
        This method will be called exactly once and will:
        1. Determine the block size
        2. Determine the category of block cipher used (ECB, CBC, ECB_CBC, Stream)
        3. Attempt to determine the block cipher mode used
        4. Determine the padding method

        :return: None
        """
        self.__logger.log("Starting initial cryptanalysis.")
        self.__logger.log("Determining block size.")
        try:
            self.__logger.log(f"Found block size: {self.check_block_size()}.", "X")
        except BlockSizeUnidentifiableException as e:
            self.__logger.log(f"Could not determine block size: {e}.", "ERROR")
            return
        self.__logger.log("Determining block cipher category.")
        if self.__state.get_block_cipher_mode_category():
            self.__logger.log(f"Found block cipher category: {self.__state.get_block_cipher_mode_category()}.", "X")
        else:
            self.__logger.log("Could not determine block cipher category.", "ERROR")
            return
        self.__logger.log("Starting fingerprinting.")
        self.__logger.log("Determining block cipher mode.")
        detected = self.check_block_cipher_mode()
        if detected:
            self.__logger.log(f"Found block cipher mode: {detected}.", "X")
        else:
            self.__logger.log("Could not determine block cipher mode, providing a list of probable modes.")
        self.__state.get_certainty().print_certainty(self.__logger)
        if not (detected == "ECB" or detected == "CBC"):
            self.__logger.log("Block cipher mode is not ECB or CBC, skipping padding method detection.")
        else:
            self.__logger.log("ECB/CBC detected. Determining padding method.")
            detected = self.check_padding_method()
            if detected:
                self.__logger.log(f"Found padding method: {detected}.", "X")
            else:
                self.__logger.log("Could not determine padding method.")
        if not self.__state.get_block_cipher_mode() == "ECB":
            self.__logger.log("Checking if the IV is reused for each encryption.")
            first = self.encrypt(b'A'.hex(), self.__server_instance)
            second = self.encrypt(b'A'.hex(), self.__server_instance)
            self.__state.add_combo(bytes.fromhex(first), b'A')
            self.__state.add_combo(bytes.fromhex(second), b'A')
            self.__logger.log(f"Reuses IV: {self.__state.get_reuse_iv()}.")
        self.__logger.log("Fingerprinting complete.")
        most_probable = self.__state.get_certainty().get_most_certain()
        if most_probable == "ECB":
            attack = ChosenPlaintextAttack(self.encrypt, self.decrypt, self.__state.get_block_size(), self.__server_instance)
            attack_string = "Chosen Plaintext Attack"
        else:
            attack = PaddingOracleAttack(self.encrypt, self.decrypt, self.__state.get_block_size(), self.__server_instance)
            attack_string = "Padding Oracle Attack"

        answered_yes = lambda a: a.strip().lower() == "y" or not a or a == "\n"

        ans = input(f"Would you like to perform a {attack_string}? (Y/n) ")
        
        print(ans)
        if answered_yes(ans):
            if most_probable == "ECB":
                ans = input(f"Optimize search space for printable ascii? (Y/n) ")
                print(ans)
                attack._search_space = (32, 127) if answered_yes(ans) else (0, 256)
            self.__logger.log(f"Starting {attack_string}.")
            attack.run()
            self.__logger.log(f"{attack_string} complete.")
        else:
            self.__logger.log("Skipping attack.")

    def analyze_string(self, ciphertext, plaintext=None):
        self.__state.add_combo_simple(bytes.fromhex(ciphertext), plaintext)

    def print_certainty(self):
        return self.__state.get_certainty().print_certainty(self.__logger)
