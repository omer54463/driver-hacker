from enum import Enum, auto
from typing import final


@final
class EmulatorCallbackResult(Enum):
    CONTINUE = auto()
    RETURN = auto()
    STOP = auto()
