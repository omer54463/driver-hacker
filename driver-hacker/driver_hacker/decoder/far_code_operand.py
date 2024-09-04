from dataclasses import dataclass


@dataclass(frozen=True)
class FarCodeOperand:
    address: int
