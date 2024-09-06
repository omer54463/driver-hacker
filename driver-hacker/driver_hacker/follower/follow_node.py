from __future__ import annotations

from typing import TYPE_CHECKING, Any, Self, final

from driver_hacker.follower.follow_leaf import FollowLeaf

if TYPE_CHECKING:
    from collections.abc import Iterator
    from collections.abc import Set as AbstractSet

    from driver_hacker.decoder.operand import Operand
    from driver_hacker.follower.follow_direction import FollowDirection
    from driver_hacker.follower.follow_leaf_type import FollowLeafType


@final
class FollowNode:
    __address: int
    __operand: Operand
    __direction: FollowDirection
    __sub_nodes: set[Self]
    __leafs: set[FollowLeaf]

    def __init__(self, address: int, operand: Operand, direction: FollowDirection) -> None:
        self.__address = address
        self.__operand = operand
        self.__direction = direction
        self.__sub_nodes = set()
        self.__leafs = set()

    @property
    def address(self) -> int:
        return self.__address

    @property
    def operand(self) -> Operand:
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

    @property
    def leaf_count(self) -> int:
        return len(self.__leafs)

    @property
    def leafs(self) -> AbstractSet[FollowLeaf]:
        return self.__leafs

    def new(self, address: int, operand: Operand, direction: FollowDirection) -> Self:
        self.__sub_nodes.add(node := type(self)(address, operand, direction))
        return node

    def new_leaf(self, address: int, type: FollowLeafType, value: Any) -> FollowLeaf:
        self.__leafs.add(leaf := FollowLeaf(address, type, value))
        return leaf

    def add(self, node_or_leaf: Self | FollowLeaf) -> None:
        match node_or_leaf:
            case FollowLeaf() as leaf:
                self.__leafs.add(leaf)

            case node:
                self.__sub_nodes.add(node)

    def __len__(self) -> int:
        return len(self.__sub_nodes)

    def __contains__(self, node: Self) -> bool:
        return node in self.__sub_nodes

    def __iter__(self) -> Iterator[Self]:
        return iter(self.__sub_nodes)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, type(self)):
            return self.__tuple() == other.__tuple()

        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.__tuple())

    def __repr__(self) -> str:
        parts = (
            f"{self.__address:#x}",
            f"{self.__operand!r}",
            f"{self.__direction}",
            f"{self.__sub_nodes!r}",
            f"{self.__leafs!r}",
        )
        return f"{type(self).__name__}({', '.join(parts)})"

    def __match_args__(
        self,
    ) -> tuple[int, Operand, FollowDirection, AbstractSet[Self], AbstractSet[FollowLeaf]]:
        return *self.__tuple(), self.sub_nodes, self.__leafs

    def __tuple(self) -> tuple[int, Operand, FollowDirection]:
        return self.__address, self.__operand, self.__direction
