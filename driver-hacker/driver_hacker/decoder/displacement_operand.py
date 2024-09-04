from dataclasses import dataclass


@dataclass(frozen=True)
class DisplacementOperand:
    base_register: str | None
    index_register: str | None
    scale: int
    displacement: int
