from dataclasses import dataclass


@dataclass(frozen=True)
class PhraseOperand:
    base_register: str | None
    index_register: str | None
    scale: int
