class Logger:
    def __init__(self, log_to_file=False):
        self.__log_file = "log.txt"
        self.__log_to_file = log_to_file

    def log(self, message, category="INFO"):
        message = f"[{category}] {message}"
        if self.__log_to_file:
            with open(self.__log_file, 'a') as f:
                f.write(message + "\n")
        print(message)

    def log_simple(self, message):
        if self.__log_to_file:
            with open(self.__log_file, 'a') as f:
                f.write(message + "\n")
        print(message)