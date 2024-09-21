from enum import Enum, auto
from typing import assert_never, final

import unicorn  # type: ignore[import-untyped]


@final
class HookType(Enum):
    INSTRUCTION = auto()
    INTERRUPT = auto()
    INVALID_INSTRUCTION = auto()
    BLOCK = auto()
    CODE = auto()

    def to_uc(self) -> int:
        hook_type: int

        match self:
            case HookType.INSTRUCTION:
                hook_type = unicorn.UC_HOOK_INSN

            case HookType.INTERRUPT:
                hook_type = unicorn.UC_HOOK_INTR

            case HookType.INVALID_INSTRUCTION:
                hook_type = unicorn.UC_HOOK_INSN_INVALID

            case HookType.CODE:
                hook_type = unicorn.UC_HOOK_CODE

            case HookType.BLOCK:
                hook_type = unicorn.UC_HOOK_BLOCK

            case never:
                assert_never(never)

        return hook_type
