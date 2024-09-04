from typing import TypeAlias

from driver_hacker.decoder.data_operand import DataOperand
from driver_hacker.decoder.displacement_operand import DisplacementOperand
from driver_hacker.decoder.far_code_operand import FarCodeOperand
from driver_hacker.decoder.immediate_operand import ImmediateOperand
from driver_hacker.decoder.near_code_operand import NearCodeOperand
from driver_hacker.decoder.phrase_operand import PhraseOperand
from driver_hacker.decoder.register_operand import RegisterOperand

Operand: TypeAlias = (
    RegisterOperand
    | DataOperand
    | PhraseOperand
    | DisplacementOperand
    | ImmediateOperand
    | FarCodeOperand
    | NearCodeOperand
)
