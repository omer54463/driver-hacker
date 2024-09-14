from enum import Flag, auto
from typing import final


@final
class ReferenceType(Flag):
    ORDINARY_FLOW = auto()
    CALL_FAR = auto()
    CALL_NEAR = auto()
    JUMP_FAR = auto()
    JUMP_NEAR = auto()
    OFFSET = auto()
    WRITE = auto()
    READ = auto()
    TEXTUAL = auto()

    CALL = CALL_FAR | CALL_NEAR
    JUMP = JUMP_FAR | JUMP_NEAR
    FLOW = CALL | JUMP
    ALL = ORDINARY_FLOW | CALL_FAR | CALL_NEAR | JUMP_FAR | JUMP_NEAR | OFFSET | WRITE | READ | TEXTUAL
