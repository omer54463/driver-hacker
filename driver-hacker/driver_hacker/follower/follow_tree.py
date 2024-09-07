from collections.abc import Generator
from typing import final

from driver_hacker.follower.follow_leaf import FollowLeaf
from driver_hacker.follower.follow_node import FollowNode


@final
class FollowTree:
    __root: FollowNode

    def __init__(self, root: FollowNode) -> None:
        self.__root = root

    @property
    def root(self) -> FollowNode:
        return self.__root

    @property
    def leafs(self) -> Generator[FollowLeaf]:
        queue = [self.__root]

        while len(queue) > 0:
            node = queue.pop()
            yield from node.leafs
            queue.extend(node.sub_nodes)
