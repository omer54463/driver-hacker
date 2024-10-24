from math import ceil
from typing import TYPE_CHECKING, assert_never, final

import unicorn
from loguru import logger

from driver_hacker.emulator.image_manager.image_manager import ImageManager
from driver_hacker.emulator.memory_manager.memory_manager import MemoryManager
from driver_hacker.emulator.register_manager.register_manager import RegisterManager

if TYPE_CHECKING:
    from ida_funcs import func_t  # type: ignore[import-not-found]


@final
class Emulator:
    __uc: unicorn.Uc
    __image_manager: ImageManager
    __register_manager: RegisterManager
    __memory_manager: MemoryManager

    __DISASSEMBLY_SIZE = 7

    def __init__(
        self,
        uc: unicorn.Uc,
        image_manager: ImageManager,
        register_manager: RegisterManager,
        memory_manager: MemoryManager,
    ) -> None:
        self.__uc = uc
        self.__image_manager = image_manager
        self.__register_manager = register_manager
        self.__memory_manager = memory_manager

    @property
    def uc(self) -> unicorn.Uc:
        return self.__uc

    @property
    def image(self) -> ImageManager:
        return self.__image_manager

    @property
    def register(self) -> RegisterManager:
        return self.__register_manager

    @property
    def memory(self) -> MemoryManager:
        return self.__memory_manager

    def disassembly(self, *, level: int | str = "TRACE") -> None:
        logger.log(level, "Disassembly:")

        current_address = self.register.rip
        image = self.image.get_at(current_address)

        for _ in range(ceil(self.__DISASSEMBLY_SIZE / 2) - 1):
            previous_address: int = image.ua.decode_prev_insn(image.ua.insn_t(), current_address)
            if previous_address == image.api.BADADDR:
                break

            current_address = previous_address

        for _ in range(self.__DISASSEMBLY_SIZE):
            instruction_size: int = image.ua.decode_insn(image.ua.insn_t(), current_address)
            if instruction_size == 0:
                break

            mark = ">" if current_address == self.register.rip else " "
            disassembly = image.lines.generate_disasm_line(current_address, image.lines.GENDSM_REMOVE_TAGS)
            logger.log(level, "{} {:#018x} {}", mark, current_address, disassembly)
            current_address += instruction_size

    def stack_trace(self, *, level: int | str = "TRACE") -> None:
        logger.log(level, "Stack trace:")

        current_stack_address = self.register.rsp - self.memory.pointer_size
        current_address = self.register.rip

        while current_address != 0:
            try:
                image = self.image.get_at(current_address)
            except ValueError:
                break

            function: func_t | None = image.funcs.get_func(current_address)
            if function is None:
                break

            mark = ">" if current_address == self.register.rip else " "
            function_name: str = image.funcs.get_func_name(function.start_ea)
            entry = self.__format_stack_trace_entry(image.stem, function_name, function.start_ea, current_address)
            logger.log(level, "{} {:#018x} {}", mark, current_address, entry)

            current_stack_address += image.frame.get_frame_size(function)
            current_address = self.memory.read_pointer(current_stack_address)

    def resolve(self, image_name: str, symbol_identifier: str | int) -> int:
        image = self.image.get(image_name)

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
                address = self.register.rip

        else:
            self.uc.emu_start(address, 0)

    @staticmethod
    def __format_stack_trace_entry(
        image_name: str,
        function_name: str,
        function_start_address: int,
        address: int,
    ) -> str:
        distance = address - function_start_address

        if distance < 0:
            return f"{image_name}!{function_name}-{-distance:#x}"

        if distance == 0:
            return f"{image_name}!{function_name}"

        return f"{image_name}!{function_name}+{distance:#x}"
