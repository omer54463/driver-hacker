from typing import TypeAlias

from driver_hacker.follower.follow_call_leaf import FollowCallLeaf
from driver_hacker.follower.follow_data_leaf import FollowDataLeaf

FollowLeaf: TypeAlias = FollowCallLeaf | FollowDataLeaf
