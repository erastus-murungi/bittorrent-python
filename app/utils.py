def check_state(condition: bool, error_message: str) -> None:
    if not condition:
        raise ValueError(error_message)
    return None
