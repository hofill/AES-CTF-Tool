import utils


class Certainty:
    def __init__(self, certainty=0):
        self.__round = 0
        self.__certainty = {
            "ECB": certainty,
            "CBC": certainty,
            "CFB": certainty,
            "OFB": certainty,
            "CTR": certainty,
        }

    def get_certainty_string(self, bctype: str):
        if self.__certainty[bctype] == 0:
            return "Certainly not"
        if self.__certainty[bctype] < 0.1:
            return "Probably not"
        if self.__certainty[bctype] < 0.5:
            return "Maybe"
        if self.__certainty[bctype] < 0.8:
            return "Probably"
        if self.__certainty[bctype] == 1:
            return "Surely"

    def print_certainty(self, logger):
        sorted_certainties = {k: v for k, v in sorted(self.__certainty.items(), reverse=True, key=lambda item: item[1])}
        logger.log_simple(f"{utils.Color.BOLD + utils.Color.BLUE}======= Probabilities ======={utils.Color.END}")
        for block_cipher_mode, percentage in sorted_certainties.items():
            logger.log_simple(
                f"{utils.calculate_color(percentage)}{block_cipher_mode}{utils.Color.END}: {round(percentage * 100, 3)}%")
        logger.log_simple(f"{utils.Color.BOLD + utils.Color.BLUE}============================={utils.Color.END}")

    def get_certainty(self):
        return self.__certainty

    def increase_round(self):
        self.__round += 1

    def normalize(self, probabilities: dict):
        """
        Normalizes the probabilities and adds them to the current certainty

        :param probabilities: The list of probabilities to add
        :return: None
        """
        total = sum(probabilities.values())
        for key in self.__certainty:
            self.__certainty[key] += probabilities[key] / total
        total = sum(self.__certainty.values())
        self.__certainty = {key: value / total for key, value in self.__certainty.items()}

    def add_certainty(self, mode: str, amount: float):
        """
        Adds certainty to a block cipher mode

        :param mode: The block cipher mode to add certainty to
        :param amount: The amount of certainty to add
        :return: None
        """
        self.__certainty[mode] += amount

    def certain(self, mode: str):
        self.__certainty[mode] = 1
        for key in self.__certainty:
            if key != mode:
                self.__certainty[key] = 0

    def has_certain_mode(self):
        for key in self.__certainty:
            if self.__certainty[key] == 1:
                return True
        return False

    def has_certainties(self):
        for key in self.__certainty:
            if self.__certainty[key] > 0:
                return True
        return False

    def get_most_certain(self):
        return max(self.__certainty, key=self.__certainty.get)
