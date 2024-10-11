from collections.abc import Callable
from contextlib import suppress
from math import ceil
from typing import TYPE_CHECKING, Self, assert_never, final

import unicorn  # type: ignore[import-untyped]
from loguru import logger

from driver_hacker.emulator.memory_manager.memory_manager import MemoryManager
from driver_hacker.emulator.memory_manager.permission import Permission
from driver_hacker.emulator.register_manager.register_manager import RegisterManager
from driver_hacker.image.image import Image

if TYPE_CHECKING:
    from ida_funcs import func_t  # type: ignore[import-not-found]
    from ida_segment import segment_t  # type: ignore[import-not-found]


@final
class Emulator:
    __uc: unicorn.Uc

    __register_manager: RegisterManager
    __memory_manager: MemoryManager

    __kuser_shared_data: bytes
    __stack_size: int

    __images: dict[str, Image]
    __overrides: dict[tuple[str, int | str], Callable[[Self], int | None]]
    __fallbacks: dict[tuple[str, int | str], Callable[[Self], int | None]]

    __DISASSEMBLY_SIZE = 7
    __KUSER_SHARED_DATA_ADDRESS = 0xFFFFF78000000000

    def __init__(self, kuser_shared_data: bytes, stack_size: int, memory_start: int, memory_end: int) -> None:
        self.__uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

        self.__register_manager = RegisterManager(self.__uc)
        self.__memory_manager = MemoryManager(self.__uc, memory_start, memory_end)

        self.__kuser_shared_data = kuser_shared_data
        self.__stack_size = stack_size

        self.__images = {}
        self.__overrides = {}
        self.__fallbacks = {}

    @property
    def uc(self) -> unicorn.Uc:
        return self.__uc

    @property
    def register(self) -> RegisterManager:
        return self.__register_manager

    @property
    def memory(self) -> MemoryManager:
        return self.__memory_manager

    @property
    def stack_size(self) -> int:
        return self.__stack_size

    def add_image(self, image: Image) -> None:
        self.__map_sections(image)
        self.__add_import_hook(image)
        self.__images[image.path.stem] = image

    def add_override(self, image_name: str, identifier: int | str, override: Callable[[Self], int | None]) -> None:
        self.__overrides[(image_name, identifier)] = override

    def add_fallback(self, image_name: str, identifier: int | str, fallback: Callable[[Self], int | None]) -> None:
        self.__fallbacks[(image_name, identifier)] = fallback

    def get_import(self, source_image_name: str, image_name: str, identifier: int | str) -> int:
        address: int | None = None

        def __callback(import_address: int, target_name: str | None, target_ordinal: int) -> bool:
            nonlocal address

            match identifier:
                case str() as name:
                    if target_name == name:
                        address = import_address
                        return False

                    return True

                case int() as ordinal:
                    if target_ordinal == ordinal:
                        address = import_address
                        return False

                    return True

                case never:
                    assert_never(never)

            image = self.__images[source_image_name]
            index = self.__get_import_index(image, image_name)
            image.nalt.enum_import_names(index, __callback)

            if address is None:
                message = f"Cannot find import `{identifier}` of image `{image_name}` in image `{source_image_name}`"
                raise ValueError(message)

            return address

        message = f"Image `{source_image_name}` does not import symbols from image `{image_name}`"
        raise ValueError(message)

    def get_export(self, image_name: str, identifier: int | str) -> int:
        if image_name not in self.__images:
            message = f"Image `{image_name}` is not mapped"
            raise ValueError(message)

        image = self.__images[image_name]

        match identifier:
            case str() as name:
                address: int = image.name.get_name_ea(image.api.BADADDR, name)

            case int() as ordinal:
                address = image.entry.get_entry(ordinal)

            case never:
                assert_never(never)

        if address == image.api.BADADDR:
            message = f"Cannot find export `{identifier}` of image `{image_name}`"
            raise ValueError(message)

        return address

    def disassembly(self, *, level: int | str = "INFO") -> None:
        logger.error("Disassembly:")

        address = self.register.get("rip")
        current_address = address
        image = self.__get_image(address)

        for _ in range(ceil(self.__DISASSEMBLY_SIZE / 2) - 1):
            previous_address: int = image.ua.decode_prev_insn(image.ua.insn_t(), current_address)
            if previous_address == image.api.BADADDR:
                break
            current_address = previous_address

        for _ in range(self.__DISASSEMBLY_SIZE):
            instruction_size: int = image.ua.decode_insn(image.ua.insn_t(), current_address)
            if instruction_size == 0:
                break

            mark = ">" if current_address == address else " "
            disassembly = image.lines.generate_disasm_line(current_address, image.lines.GENDSM_REMOVE_TAGS)
            logger.log(level, "{} {:#018x} {}", mark, current_address, disassembly)
            current_address += instruction_size

    def stack_trace(self, *, level: int | str = "INFO") -> None:
        logger.error("Stack trace:")

        current_stack_address = self.register.get("rsp") - self.memory.pointer_size
        address = self.register.get("rip")
        current_address = address
        image = self.__get_image(current_address)

        while True:
            function: func_t | None = image.funcs.get_func(current_address)
            if function is None:
                break

            mark = ">" if current_address == address else " "
            function_name: str = image.funcs.get_func_name(function.start_ea)
            entry = self.__format_stack_trace_entry(image.path.stem, function_name, function.start_ea, current_address)
            logger.log(level, "{} {:#018x} {}", mark, current_address, entry)

            current_stack_address += image.frame.get_frame_size(function)
            current_address = self.memory.read_pointer(current_stack_address)

            try:
                image = self.__get_image(current_address)

            except ValueError:
                break

    def start(self, address: int) -> None:
        stack = self.memory.allocate(self.stack_size * 2, Permission.READ_WRITE)
        self.register.set("rsp", stack + self.stack_size)

        self.memory.map(self.__KUSER_SHARED_DATA_ADDRESS, self.memory.page_size, Permission.READ)
        self.memory.write(self.__KUSER_SHARED_DATA_ADDRESS, self.__kuser_shared_data)

        self.uc.emu_start(address, 0)

    def __map_sections(self, image: Image) -> None:
        image_start: int = image.nalt.get_imagebase()
        image_end: int = max(image.segment.getnseg(index).end_ea for index in range(image.segment.get_segm_qty()))
        image_size = image_end - image_start

        address = self.memory.allocate(image_size)
        self.memory.unmap(address, image_size)
        image.segment.rebase_program(address - image_start, image.segment.MSF_FIXONCE)

        logger.info("Adding image `{}` at address {:#x}", image.path.stem, address)

        segment: segment_t = image.segment.get_first_seg()
        while segment is not None:
            segment_size = segment.end_ea - segment.start_ea

            self.memory.map(segment.start_ea, segment_size, Permission.from_ida(segment.perm))

            data: bytes = image.bytes.get_bytes(segment.start_ea, segment_size)
            self.memory.write(segment.start_ea, data)

            segment = image.segment.get_next_seg(segment.start_ea)

    def __add_import_hook(self, image: Image) -> None:
        for index in range(image.nalt.get_import_module_qty()):
            target_image_name: str = image.nalt.get_import_module_name(index)

            def __callback(import_address: int, target_name: str | None, target_ordinal: int) -> bool:
                target = (
                    (target_image_name, target_ordinal) if target_name is None else (target_image_name, target_name)
                )
                hook_address = self.memory.allocate(self.memory.page_size, Permission.READ_EXECUTE)
                self.uc.hook_add(
                    unicorn.UC_HOOK_CODE,
                    self.__import_hook,
                    target,
                    hook_address,
                    hook_address + self.memory.page_size - 1,
                )
                self.memory.write_pointer(import_address, hook_address)
                return True

            image.nalt.enum_import_names(index, __callback)

    def __import_hook(self, _uc: unicorn.Uc, _address: int, _size: int, target: tuple[str, int | str]) -> None:
        if target in self.__overrides:
            self.__run_callback(self.__overrides[target])
            return

        with suppress(ValueError):
            address = self.get_export(*target)
            self.register.set("rip", address)
            return

        if target in self.__fallbacks:
            self.__run_callback(self.__fallbacks[target])
            return

        image_name, identifier = target
        message = f"Cannot find implementation for import `{identifier}` of image `{image_name}`"
        raise RuntimeError(message)

    def __run_callback(self, callback: Callable[[Self], int | None]) -> None:
        value = callback(self)
        match value:
            case int(value):
                self.register.set("rax", value)
                rsp = self.register.get("rsp")
                self.register.set("rsp", rsp + self.memory.pointer_size)
                self.register.set("rip", self.memory.read_pointer(rsp))

            case None:
                self.uc.emu_stop()

            case never:
                assert_never(never)

    def __get_import_index(self, image: Image, image_name: str) -> int:
        for index in range(image.nalt.get_import_module_qty()):
            target_image_name: str = image.nalt.get_import_module_name(index)
            if target_image_name == image_name:
                return index

        message = f"Image `{image.path.stem}` does not import symbols from image `{image_name}`"
        raise ValueError(message)

    def __get_image(self, address: int) -> Image:
        for image in self.__images.values():
            if image.segment.getseg(address) is not None:
                return image

        message = f"Address {address:#x} is not a part of an image"
        raise ValueError(message)

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
