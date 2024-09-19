from math import ceil, floor


def align_down(value: int, factor: int) -> int:
    return floor(value / factor) * factor


def align_up(value: int, factor: int) -> int:
    return ceil(value / factor) * factor
