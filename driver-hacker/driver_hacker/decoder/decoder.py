from collections.abc import Sequence
from itertools import count
from pathlib import Path
from re import compile
from typing import cast

from yaml import safe_load

from driver_hacker.decoder.instruction import Instruction
from driver_hacker.ida.ida import Ida


class Decoder:
    __ida: Ida

    __COLOR_PATTERN = compile(r"(\x01|\x02).")
    __BRACKETS_PATTERN = compile(r"[^\[\]]*\[(.*)\]")
    __BRACKETS_CONTENT_PATTERN = compile(r"[+-][^+-]+")
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
        return cast(str, self.__ida.ua.print_insn_mnem(address))

    def decode_operands(self, address: int) -> Sequence[int | str]:
        operands = []

        for index in count():
            operand = self.try_decode_operand(address, index)
            if operand is None:
                break

            operands.append(operand)

        return operands

    def decode_operand(self, address: int, index: int) -> int | str:
        if (operand := self.try_decode_operand(address, index)) is not None:
            return operand

        message = f"The instruction at `{address:#x}` doesn't have a `{index}`-th operand"
        raise ValueError(message)

    def try_decode_operand(self, address: int, index: int) -> int | str | None:
        operand_type, operand_address = self.__get_operand_type_and_address(address, index)
        if operand_type in (self.__ida.ua.o_mem, self.__ida.ua.o_far, self.__ida.ua.o_near):
            return operand_address

        operand = self.__ida.ua.print_operand(address, index)
        if operand is None or len(operand) == 0:
            return None

        text = self.__COLOR_PATTERN.sub("", operand)

        if match := self.__BRACKETS_PATTERN.match(text):
            content = match.group(1)
            parts = self.__BRACKETS_CONTENT_PATTERN.findall(f"+{content}")
            if all(self.__is_register(part[1:]) for part in parts):
                return text

            register_parts = tuple(part for part in parts if self.__is_register(part[1:]))
            if len(register_parts) == 0:
                return operand_address

            displacement_part = f"+{operand_address:#x}"
            new_parts = (*register_parts, displacement_part)
            new_content = "".join(new_parts).removeprefix("+")
            return f"[{new_content}]"

        return text

    def __is_register(self, text: str) -> bool:
        return text in self.__REGISTER_NAMES

    def __get_operand_type_and_address(self, address: int, index: int) -> tuple[int, int]:
        instruction = self.__ida.ua.insn_t()
        self.__ida.ua.decode_insn(instruction, address)
        operand = instruction.ops[index]
        return cast(int, operand.type), cast(int, operand.addr)

    def __try_get_following_instruction_address(self, address: int) -> int | None:
        length = self.__ida.ua.decode_insn(self.__ida.ua.insn_t(), address)
        if length > 0:
            return cast(int, address + length)

        return None

    def __try_get_previous_instruction_address(self, address: int) -> int | None:
        previous_address = self.__ida.ua.decode_prev_insn(self.__ida.ua.insn_t(), address)

        if (previous_address) != self.__ida.api.BADADDR:
            return cast(int, previous_address)

        return None
