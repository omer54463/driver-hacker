from enum import Enum, auto
from typing import assert_never, final

import unicorn  # type: ignore[import-untyped]


@final
class InstructionHookType(Enum):
    IN = auto()
    OUT = auto()
    SYSCALL = auto()
    SYSENTER = auto()
    CPUID = auto()

    def to_uc(self) -> int:
        hook_type: int

        match self:
            case InstructionHookType.IN:
                hook_type = unicorn.x86_const.UC_X86_INS_IN

            case InstructionHookType.OUT:
                hook_type = unicorn.x86_const.UC_X86_INS_OUT

            case InstructionHookType.SYSCALL:
                hook_type = unicorn.x86_const.UC_X86_INS_SYSCALL

            case InstructionHookType.SYSENTER:
                hook_type = unicorn.x86_const.UC_X86_INS_SYSENTER

            case InstructionHookType.CPUID:
                hook_type = unicorn.x86_const.UC_X86_INS_CPUID

            case never:
                assert_never(never)

        return hook_type
