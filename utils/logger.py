import datetime


class Logger:

    @staticmethod
    def info(message):
        print(f"[+] {message}")

    @staticmethod
    def warn(message):
        print(f"[!] {message}")

    @staticmethod
    def error(message):
        print(f"[x] {message}")

    @staticmethod
    def success(message):
        print(f"[✓] {message}")

    @staticmethod
    def timestamp():
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")