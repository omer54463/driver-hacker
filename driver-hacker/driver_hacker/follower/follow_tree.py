from typing import final

from driver_hacker.follower.follow_node import FollowNode


@final
class FollowTree:
    __root: FollowNode

    def __init__(self, root: FollowNode) -> None:
        self.__root = root

    @property
    def root(self) -> FollowNode:
        return self.__root
