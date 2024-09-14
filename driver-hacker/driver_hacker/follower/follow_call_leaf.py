from __future__ import annotations

from typing import TYPE_CHECKING, final

if TYPE_CHECKING:
    from driver_hacker.resolver.function import Function


@final
class FollowCallLeaf:
    __address: int
    __target: Function

    __match_args__ = ("address", "target")

    def __init__(self, address: int, target: Function) -> None:
        self.__address = address
        self.__target = target

    @property
    def address(self) -> int:
        return self.__address

    @property
    def target(self) -> Function:
        return self.__target

    def __eq__(self, other: object) -> bool:
        if isinstance(other, type(self)):
            return self.__tuple() == other.__tuple()

        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.__tuple())

    def __repr__(self) -> str:
        parts = (f"{self.__address:#x}", f"{self.__target!r}")
        return f"{type(self).__name__}({', '.join(parts)})"

    def __tuple(self) -> tuple[int, Function]:
        return self.__address, self.__target
