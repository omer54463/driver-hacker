from dataclasses import dataclass
from typing import final


@final
@dataclass(frozen=True)
class FarCodeOperand:
    address: int

    def __str__(self) -> str:
        return f"far code [{self.address:#x}]"

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.address:#x})"
