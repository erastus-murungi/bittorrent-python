import logging
import sys


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s : %(thread)d : %(levelname)s - %(message)s",
    stream=sys.stderr,
)


def log(message: str) -> None:
    logging.info(message)
    # print(message, file=sys.stderr)
    return None
