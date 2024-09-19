from enum import Flag, auto
from typing import Self, final

from unicorn import (  # type: ignore[import-untyped]
    UC_PROT_EXEC,
    UC_PROT_READ,
    UC_PROT_WRITE,
)


@final
class Permission(Flag):
    NONE = auto()
    READ = auto()
    WRITE = auto()
    EXECUTE = auto()

    READ_WRITE = READ | WRITE
    READ_EXECUTE = READ | EXECUTE
    ALL = READ | WRITE | EXECUTE

    @classmethod
    def from_uc(cls, uc_permissions: int) -> Self:
        permissions = cls.NONE

        if uc_permissions & UC_PROT_EXEC:
            permissions |= cls.EXECUTE

        if uc_permissions & UC_PROT_WRITE:
            permissions |= cls.WRITE

        if uc_permissions & UC_PROT_READ:
            permissions |= cls.READ

        return permissions

    def to_uc(self) -> int:
        permissions = 0

        if self & type(self).EXECUTE:
            permissions |= UC_PROT_EXEC

        if self & type(self).WRITE:
            permissions |= UC_PROT_WRITE

        if self & type(self).READ:
            permissions |= UC_PROT_READ

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

        if self & type(self).EXECUTE:
            permissions |= 1

        if self & type(self).WRITE:
            permissions |= 2

        if self & type(self).READ:
            permissions |= 4

        return permissions
