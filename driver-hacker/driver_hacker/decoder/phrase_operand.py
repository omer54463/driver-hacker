from dataclasses import dataclass
from typing import final


@final
@dataclass(frozen=True)
class PhraseOperand:
    base_register: str | None
    index_register: str | None
    scale: int

    def __str__(self) -> str:
        parts = []

        if self.base_register is not None:
            parts.append(f"{self.base_register}")

        if self.index_register is not None:
            if self.scale > 1:
                parts.append(f"{self.index_register} * {self.scale}")

            else:
                parts.append(f"{self.index_register}")

        return f"[{' + '.join(parts)}]"

    def __repr__(self) -> str:
        parts = (f"{self.base_register!r}", f"{self.index_register!r}", f"{self.scale:#x}")
        return f"{type(self).__name__}({', '.join(parts)})"
