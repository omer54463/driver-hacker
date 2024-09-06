from dataclasses import dataclass
from typing import final


@final
@dataclass(frozen=True)
class NearCodeOperand:
    offset: int

    def __str__(self) -> str:
        return f"near code [{self.offset:#x}]"

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.offset:#x})"
