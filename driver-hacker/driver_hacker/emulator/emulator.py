import builtins
from math import ceil
from typing import TYPE_CHECKING, assert_never, final

import unicorn
from loguru import logger

from driver_hacker.emulator.image_manager.image_manager import ImageManager
from driver_hacker.emulator.memory_manager.memory_manager import MemoryManager
from driver_hacker.emulator.register_manager.register_manager import RegisterManager
from driver_hacker.emulator.struct_manager.struct_manager import StructManager

if TYPE_CHECKING:
    from ida_funcs import func_t  # type: ignore[import-not-found]


@final
class Emulator:
    __uc: unicorn.Uc
    __img: ImageManager
    __str: StructManager
    __reg: RegisterManager
    __mem: MemoryManager

    __DISASSEMBLY_SIZE = 7

    def __init__(
        self,
        uc: unicorn.Uc,
        img: ImageManager,
        str: StructManager,
        reg: RegisterManager,
        mem: MemoryManager,
    ) -> None:
        self.__uc = uc
        self.__img = img
        self.__str = str
        self.__reg = reg
        self.__mem = mem

    @property
    def uc(self) -> unicorn.Uc:
        return self.__uc

    @property
    def img(self) -> ImageManager:
        return self.__img

    @property
    def str(self) -> StructManager:
        return self.__str

    @property
    def reg(self) -> RegisterManager:
        return self.__reg

    @property
    def mem(self) -> MemoryManager:
        return self.__mem

    def disassembly(self, *, level: int | builtins.str = "TRACE") -> None:
        logger.log(level, "Disassembly:")

        current_address = self.reg.rip
        image = self.img.get_at(current_address)

        for _ in range(ceil(self.__DISASSEMBLY_SIZE / 2) - 1):
            previous_address: int = image.ua.decode_prev_insn(image.ua.insn_t(), current_address)
            if previous_address == image.api.BADADDR:
                break

            current_address = previous_address

        for _ in range(self.__DISASSEMBLY_SIZE):
            instruction_size: int = image.ua.decode_insn(image.ua.insn_t(), current_address)
            if instruction_size == 0:
                break

            mark = ">" if current_address == self.reg.rip else " "
            disassembly = image.lines.generate_disasm_line(current_address, image.lines.GENDSM_REMOVE_TAGS)
            logger.log(level, "{} {:#018x} {}", mark, current_address, disassembly)
            current_address += instruction_size

    def stack_trace(self, *, level: int | builtins.str = "TRACE") -> None:
        logger.log(level, "Stack trace:")

        current_stack_address = self.reg.rsp - self.mem.pointer_size
        current_address = self.reg.rip

        while current_address != 0:
            try:
                image = self.img.get_at(current_address)
            except ValueError:
                break

            function: func_t | None = image.funcs.get_func(current_address)
            if function is None:
                break

            mark = ">" if current_address == self.reg.rip else " "
            function_name: str = image.funcs.get_func_name(function.start_ea)
            entry = self.__format_stack_trace_entry(image.stem, function_name, function.start_ea, current_address)
            logger.log(level, "{} {:#018x} {}", mark, current_address, entry)

            current_stack_address += image.frame.get_frame_size(function)
            current_address = self.mem.read_pointer(current_stack_address)

    def resolve(self, image_name: builtins.str, symbol_identifier: builtins.str | int) -> int:
        image = self.img.get(image_name)

        match symbol_identifier:
            case str() as symbol_name:
                address: int = image.name.get_name_ea(image.api.BADADDR, symbol_name)
                if address == image.api.BADADDR:
                    for index in range(image.entry.get_entry_qty()):
                        export_ordinal: int = image.entry.get_entry_ordinal(index)
                        export_name: str = image.entry.get_entry_name(export_ordinal)
                        if export_name == symbol_name:
                            address = image.entry.get_entry(export_ordinal)

            case int() as export_ordinal:
                address = image.entry.get_entry(export_ordinal)

            case never:
                assert_never(never)

        if address == image.api.BADADDR:
            message = f"Symbol `{symbol_name}` of image `{image_name}` does not exist"
            raise ValueError(message)

        return address

    def start(self, address: int, *, single_step: bool = False) -> None:
        if single_step:
            while True:
                self.uc.emu_start(address, 0, count=1)
                address = self.reg.rip

        else:
            self.uc.emu_start(address, 0)

    @staticmethod
    def __format_stack_trace_entry(
        image_name: builtins.str,
        function_name: builtins.str,
        function_start_address: int,
        address: int,
    ) -> builtins.str:
        distance = address - function_start_address

        if distance < 0:
            return f"{image_name}!{function_name}-{-distance:#x}"

        if distance == 0:
            return f"{image_name}!{function_name}"

        return f"{image_name}!{function_name}+{distance:#x}"
