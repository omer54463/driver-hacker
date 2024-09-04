from dataclasses import dataclass


@dataclass(frozen=True)
class DataOperand:
    address: int
