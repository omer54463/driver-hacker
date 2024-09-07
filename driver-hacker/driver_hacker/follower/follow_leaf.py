from __future__ import annotations

from typing import TYPE_CHECKING, Any, final

if TYPE_CHECKING:
    from driver_hacker.follower.follow_leaf_type import FollowLeafType


@final
class FollowLeaf:
    __address: int
    __type: FollowLeafType
    __value: Any

    __match_args__ = ("address", "type", "value")

    def __init__(self, address: int, type: FollowLeafType, value: Any = None) -> None:
        self.__address = address
        self.__type = type
        self.__value = value

    @property
    def address(self) -> int:
        return self.__address

    @property
    def type(self) -> FollowLeafType:
        return self.__type

    @property
    def value(self) -> Any:
        return self.__value

    def __eq__(self, other: object) -> bool:
        if isinstance(other, type(self)):
            return self.__tuple() == other.__tuple()

        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.__tuple())

    def __repr__(self) -> str:
        parts = (f"{self.__address:#x}", f"{self.__type}", f"{self.__value!r}")
        return f"{type(self).__name__}({', '.join(parts)})"

    def __tuple(self) -> tuple[int, FollowLeafType, Any]:
        return self.__address, self.__type, self.__value
