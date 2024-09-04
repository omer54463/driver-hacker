from dataclasses import dataclass


@dataclass(frozen=True)
class ImmediateOperand:
    value: int
