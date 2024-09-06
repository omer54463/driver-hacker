from dataclasses import dataclass
from typing import final


@final
@dataclass(frozen=True)
class ImmediateOperand:
    value: int

    def __str__(self) -> str:
        return f"{self.value:#x}"

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.value:#x})"
