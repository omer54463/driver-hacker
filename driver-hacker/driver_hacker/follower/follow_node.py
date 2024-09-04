from __future__ import annotations

from typing import TYPE_CHECKING, Self, final

if TYPE_CHECKING:
    from collections.abc import Iterator
    from collections.abc import Set as AbstractSet

    from driver_hacker.follower.follow_direction import FollowDirection


@final
class FollowNode:
    __address: int
    __operand: int | str
    __direction: FollowDirection
    __sub_nodes: set[Self]

    def __init__(self, address: int, operand: int | str, direction: FollowDirection) -> None:
        self.__address = address
        self.__operand = operand
        self.__direction = direction
        self.__sub_nodes = set()

    @property
    def address(self) -> int:
        return self.__address

    @property
    def operand(self) -> int | str:
        return self.__operand

    @property
    def direction(self) -> FollowDirection:
        return self.__direction

    @property
    def sub_node_count(self) -> int:
        return len(self.__sub_nodes)

    @property
    def sub_nodes(self) -> AbstractSet[Self]:
        return self.__sub_nodes

    def new(self, address: int, operand: int | str, direction: FollowDirection) -> Self:
        self.__sub_nodes.add(node := type(self)(address, operand, direction))
        return node

    def add(self, node: Self) -> None:
        self.__sub_nodes.add(node)

    def __len__(self) -> int:
        return len(self.__sub_nodes)

    def __contains__(self, node: Self) -> bool:
        return node in self.__sub_nodes

    def __iter__(self) -> Iterator[Self]:
        return iter(self.__sub_nodes)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, FollowNode):
            return self.__key() == other.__key()

        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.__key())

    def __repr__(self) -> str:
        match self.__operand:
            case str():
                operand_part = f"{self.__operand!r}"

            case int():
                operand_part = f"{self.__operand:#x}"

        parts = (f"{self.__address:#x}", operand_part, f"{self.__direction}")
        return f"{type(self).__name__}({', '.join(parts)})"

    def __str__(self) -> str:
        return repr(self)

    def __match_args__(self) -> tuple[int, int | str, FollowDirection, AbstractSet[Self]]:
        return *self.__key(), self.sub_nodes

    def __key(self) -> tuple[int, int | str, FollowDirection]:
        return self.__address, self.__operand, self.__direction
