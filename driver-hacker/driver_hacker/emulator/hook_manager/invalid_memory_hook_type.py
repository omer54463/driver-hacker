from enum import Flag, auto
from typing import final

import unicorn  # type: ignore[import-untyped]


@final
class InvalidMemoryHookType(Flag):
    NONE = 0

    UNMAPPED_READ = auto()
    UNMAPPED_WRITE = auto()
    UNMAPPED_FETCH = auto()
    READ_PERMISSION_VIOLATION = auto()
    WRITE_PERMISSION_VIOLATION = auto()
    FETCH_PERMISSION_VIOLATION = auto()

    READ = UNMAPPED_READ | READ_PERMISSION_VIOLATION
    WRITE = UNMAPPED_WRITE | WRITE_PERMISSION_VIOLATION
    FETCH = UNMAPPED_FETCH | FETCH_PERMISSION_VIOLATION
    UNMAPPED = UNMAPPED_READ | UNMAPPED_WRITE | UNMAPPED_FETCH
    PERMISSION_VIOLATION = READ_PERMISSION_VIOLATION | WRITE_PERMISSION_VIOLATION | FETCH_PERMISSION_VIOLATION
    ACCESS = READ | WRITE
    ALL = UNMAPPED | PERMISSION_VIOLATION

    def to_uc(self) -> int:
        hook_type = 0

        if self & InvalidMemoryHookType.UNMAPPED_READ:
            hook_type |= unicorn.UC_HOOK_MEM_READ_UNMAPPED

        if self & InvalidMemoryHookType.UNMAPPED_WRITE:
            hook_type |= unicorn.UC_HOOK_MEM_WRITE_UNMAPPED

        if self & InvalidMemoryHookType.UNMAPPED_FETCH:
            hook_type |= unicorn.UC_HOOK_MEM_FETCH_UNMAPPED

        if self & InvalidMemoryHookType.READ_PERMISSION_VIOLATION:
            hook_type |= unicorn.UC_HOOK_MEM_READ_PROT

        if self & InvalidMemoryHookType.WRITE_PERMISSION_VIOLATION:
            hook_type |= unicorn.UC_HOOK_MEM_WRITE_PROT

        if self & InvalidMemoryHookType.FETCH_PERMISSION_VIOLATION:
            hook_type |= unicorn.UC_HOOK_MEM_FETCH_PROT

        return hook_type
