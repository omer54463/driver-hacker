from dataclasses import dataclass


@dataclass(frozen=True)
class NearCodeOperand:
    offset: int
