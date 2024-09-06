from dataclasses import dataclass
from typing import final


@final
@dataclass(frozen=True)
class RegisterOperand:
    register: str

    def __str__(self) -> str:
        return self.register

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.register!r})"
