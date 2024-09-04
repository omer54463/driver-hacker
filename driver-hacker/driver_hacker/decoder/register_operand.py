from dataclasses import dataclass


@dataclass(frozen=True)
class RegisterOperand:
    register: str
