from dataclasses import dataclass
from typing import final


@final
@dataclass(frozen=True)
class DataOperand:
    address: int

    def __str__(self) -> str:
        return f"data [{self.address:#x}]"

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.address:#x})"
