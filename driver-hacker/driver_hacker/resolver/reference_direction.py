from enum import Enum, auto
from typing import final


@final
class ReferenceDirection(Enum):
    TO = auto()
    FROM = auto()
