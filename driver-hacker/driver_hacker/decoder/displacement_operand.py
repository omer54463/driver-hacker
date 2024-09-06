from dataclasses import dataclass
from typing import final


@final
@dataclass(frozen=True)
class DisplacementOperand:
    base_register: str | None
    index_register: str | None
    scale: int
    displacement: int

    def __str__(self) -> str:
        parts = []

        if self.base_register is not None:
            parts.append(f"{self.base_register}")

        if self.index_register is not None:
            if self.scale > 1:
                parts.append(f"{self.index_register} * {self.scale}")

            else:
                parts.append(f"{self.index_register}")

        if self.displacement != 0:
            parts.append(f"{self.displacement:#x}")

        return f"[{' + '.join(parts)}]"

    def __repr__(self) -> str:
        parts = (
            f"{self.base_register!r}",
            f"{self.index_register!r}",
            f"{self.scale:#x}",
            f"{self.displacement!r}",
        )

        return f"{type(self).__name__}({', '.join(parts)})"
