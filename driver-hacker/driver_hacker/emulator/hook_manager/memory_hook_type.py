from enum import Flag, auto
from typing import final

import unicorn  # type: ignore[import-untyped]


@final
class MemoryHookType(Flag):
    NONE = 0

    READ = auto()
    WRITE = auto()
    FETCH = auto()

    ACCESS = READ | WRITE
    ALL = READ | WRITE | FETCH

    def to_uc(self) -> int:
        hook_type = 0

        if self & MemoryHookType.READ:
            hook_type |= unicorn.UC_HOOK_MEM_READ

        if self & MemoryHookType.WRITE:
            hook_type |= unicorn.UC_HOOK_MEM_WRITE

        if self & MemoryHookType.FETCH:
            hook_type |= unicorn.UC_HOOK_MEM_FETCH

        return hook_type
