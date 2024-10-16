from enum import Flag, auto
from typing import Self, final

import unicorn


@final
class Permission(Flag):
    NONE = 0

    READ = auto()
    WRITE = auto()
    EXECUTE = auto()

    READ_WRITE = READ | WRITE
    READ_EXECUTE = READ | EXECUTE
    ALL = READ | WRITE | EXECUTE

    @classmethod
    def from_uc(cls, uc_permissions: int) -> Self:
        permissions = cls.NONE

        if uc_permissions & unicorn.UC_PROT_EXEC:
            permissions |= cls.EXECUTE

        if uc_permissions & unicorn.UC_PROT_WRITE:
            permissions |= cls.WRITE

        if uc_permissions & unicorn.UC_PROT_READ:
            permissions |= cls.READ

        return permissions

    def to_uc(self) -> int:
        permissions = 0

        if self & Permission.EXECUTE:
            permissions |= unicorn.UC_PROT_EXEC

        if self & Permission.WRITE:
            permissions |= unicorn.UC_PROT_WRITE

        if self & Permission.READ:
            permissions |= unicorn.UC_PROT_READ

        return permissions

    @classmethod
    def from_ida(cls, ida_permissions: int) -> Self:
        permissions = cls.NONE

        if ida_permissions & 1:
            permissions |= cls.EXECUTE

        if ida_permissions & 2:
            permissions |= cls.WRITE

        if ida_permissions & 4:
            permissions |= cls.READ

        return permissions

    def to_ida(self) -> int:
        permissions = 0

        if self & Permission.EXECUTE:
            permissions |= 1

        if self & Permission.WRITE:
            permissions |= 2

        if self & Permission.READ:
            permissions |= 4

        return permissions
