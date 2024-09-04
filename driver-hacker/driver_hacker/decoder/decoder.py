from collections.abc import Sequence
from pathlib import Path
from re import compile
from typing import TYPE_CHECKING, cast

from yaml import safe_load

from driver_hacker.decoder.data_operand import DataOperand
from driver_hacker.decoder.displacement_operand import DisplacementOperand
from driver_hacker.decoder.far_code_operand import FarCodeOperand
from driver_hacker.decoder.immediate_operand import ImmediateOperand
from driver_hacker.decoder.instruction import Instruction
from driver_hacker.decoder.near_code_operand import NearCodeOperand
from driver_hacker.decoder.operand import Operand
from driver_hacker.decoder.phrase_operand import PhraseOperand
from driver_hacker.decoder.register_operand import RegisterOperand
from driver_hacker.ida.ida import Ida

if TYPE_CHECKING:
    import ida_ua  # type: ignore[import-not-found]


class Decoder:
    __ida: Ida

    __COLOR_PATTERN = compile(r"(\x01|\x02).")
    __REGISTER_NAMES: list[str] = safe_load((Path(__file__).parent / "registers.yaml").read_text())

    def __init__(self, ida: Ida) -> None:
        self.__ida = ida

    def decode_instruction(self, address: int) -> Instruction:
        return Instruction(
            self.__try_get_previous_instruction_address(address),
            address,
            self.__try_get_following_instruction_address(address),
            self.decode_mnemonic(address),
            self.decode_operands(address),
        )

    def decode_mnemonic(self, address: int) -> str:
        if (result := self.try_decode_mnemonic(address)) is not None:
            return result

        message = f"Failed to print the mnemonic of the instruction at `{address:#x}`"
        raise RuntimeError(message)

    def try_decode_mnemonic(self, address: int) -> str | None:
        mnemonic = self.__ida.ua.print_insn_mnem(address)

        if mnemonic is not None:
            return self.__remove_color(mnemonic)

        return None

    def decode_operands(self, address: int) -> Sequence[Operand]:
        operands: list[Operand] = []

        insn, _ = self.__decode_insn(address)
        for index, op in enumerate(insn.ops):
            match op.type:
                case self.__ida.ua.o_reg:
                    register = self.__print_op(address, index)

                    if not self.__is_register(register):
                        message = f"Expected a register, found `{register}`"
                        raise ValueError(message)

                    operands.append(RegisterOperand(register))

                case self.__ida.ua.o_mem:
                    operands.append(DataOperand(op.addr))

                case self.__ida.ua.o_phrase:
                    base_register, index_register, scale = self.__prase_phrase_op(address, index)
                    operands.append(PhraseOperand(base_register, index_register, scale))

                case self.__ida.ua.o_displ:
                    base_register, index_register, scale = self.__prase_phrase_op(address, index)
                    operands.append(
                        DisplacementOperand(base_register, index_register, scale, op.addr)
                    )

                case self.__ida.ua.o_imm:
                    operands.append(ImmediateOperand(op.addr))

                case self.__ida.ua.o_far:
                    operands.append(FarCodeOperand(op.addr))

                case self.__ida.ua.o_near:
                    operands.append(NearCodeOperand(op.addr))

        return operands

    def decode_operand(self, address: int, index: int) -> Operand:
        return self.decode_operands(address)[index]

    def try_decode_operand(self, address: int, index: int) -> Operand | None:
        operands = self.decode_operands(address)

        if index < len(operands):
            return operands[index]

        return None

    def __remove_color(self, text: str) -> str:
        return self.__COLOR_PATTERN.sub("", text)

    def __is_register(self, text: str) -> bool:
        return text in self.__REGISTER_NAMES

    def __try_get_previous_instruction_address(self, address: int) -> int | None:
        if (result := self.__try_decode_insn(address, previous=True)) is not None:
            _, previous_address = result
            return previous_address

        return None

    def __try_get_following_instruction_address(self, address: int) -> int | None:
        if (result := self.__try_decode_insn(address)) is not None:
            _, length = result
            return address + length

        return None

    def __decode_insn(
        self,
        address: int,
        *,
        previous: bool = False,
    ) -> tuple["ida_ua.insn_t", int]:
        if (result := self.__try_decode_insn(address, previous=previous)) is not None:
            return result

        message = f"Failed to decode instruction at `{address:#x}`"
        raise RuntimeError(message)

    def __try_decode_insn(
        self,
        address: int,
        *,
        previous: bool = False,
    ) -> tuple["ida_ua.insn_t", int] | None:
        instruction = self.__ida.ua.insn_t()
        function = self.__ida.ua.decode_prev_insn if previous else self.__ida.ua.decode_insn
        bad_value = self.__ida.api.BADADDR if previous else 0
        value = function(instruction, address)

        if value == bad_value:
            return None

        return instruction, value

    def __print_op(self, address: int, index: int) -> str:
        if (result := self.__try_print_op(address, index)) is not None:
            return self.__remove_color(result)

        message = f"Failed to print operand `{index}` of the instruction at `{address:#x}`"
        raise RuntimeError(message)

    def __try_print_op(self, address: int, index: int) -> str | None:
        text = self.__ida.ua.print_operand(address, index)

        if text is not None and len(text) > 0:
            return cast(str, text)

        return None

    def __prase_phrase_op(self, address: int, index: int) -> tuple[str | None, str | None, int]:
        base_register: str | None = None
        index_register: str | None = None
        scale = 1

        text = self.__print_op(address, index)
        content = text.removeprefix("[").removesuffix("]")

        for part in content.replace("-", "+-").split("+"):
            if self.__is_register(part):
                if base_register is None:
                    base_register = part
                    continue

                if index_register is None:
                    index_register = part
                    continue

                message = f"Too many registers in `{content}`"
                raise ValueError(message)

            if "*" in part:
                if index_register is not None:
                    message = f"Index register was found twice in `{content}`"
                    raise ValueError(message)

                index_register, scale_text = part.split("*")
                scale = int(scale_text)
                continue

            break

        return base_register, index_register, scale
