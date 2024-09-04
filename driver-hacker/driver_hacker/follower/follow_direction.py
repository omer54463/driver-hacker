from __future__ import annotations

from enum import Enum, auto
from typing import final


@final
class FollowDirection(Enum):
    FORWARDS = auto()
    BACKWARDS = auto()

    def opposite(self) -> FollowDirection:
        match self:
            case FollowDirection.BACKWARDS:
                return FollowDirection.FORWARDS

            case FollowDirection.FORWARDS:
                return FollowDirection.BACKWARDS
