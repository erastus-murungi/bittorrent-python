import logging
import sys


def check_state(condition: bool, error_message: str) -> None:
    if not condition:
        raise ValueError(error_message)
    return None


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s : %(thread)d : %(levelname)s - %(message)s",
    stream=sys.stderr,
)


def log(message: str) -> None:
    logging.info(message)
    # print(message, file=sys.stderr)
    return None
