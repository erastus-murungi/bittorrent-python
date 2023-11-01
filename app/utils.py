import logging
import sys


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s:%(levelname)s: %(message)s",
    stream=sys.stderr,
)


def log(message: str) -> None:
    logging.info(message)
    return None
