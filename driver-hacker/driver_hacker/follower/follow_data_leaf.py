from __future__ import annotations

from typing import final


@final
class FollowDataLeaf:
    __address: int
    __target: int

    __match_args__ = ("address", "target")

    def __init__(self, address: int, target: int) -> None:
        self.__address = address
        self.__target = target

    @property
    def address(self) -> int:
        return self.__address

    @property
    def target(self) -> int:
        return self.__target

    def __eq__(self, other: object) -> bool:
        if isinstance(other, type(self)):
            return self.__tuple() == other.__tuple()

        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.__tuple())

    def __repr__(self) -> str:
        parts = (f"{self.__address:#x}", f"{self.__target:#x}")
        return f"{type(self).__name__}({', '.join(parts)})"

    def __tuple(self) -> tuple[int, int]:
        return self.__address, self.__target
