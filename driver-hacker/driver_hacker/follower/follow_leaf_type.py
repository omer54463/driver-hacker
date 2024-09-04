from enum import Enum, auto
from typing import final


@final
class FollowLeafType(Enum):
    FUNCTION_CALL = auto()
