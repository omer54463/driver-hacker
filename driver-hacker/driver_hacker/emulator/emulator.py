from collections.abc import Mapping
from contextlib import suppress
from functools import partial
from math import ceil
from typing import TYPE_CHECKING, assert_never, final

import unicorn  # type: ignore[import-untyped]
from loguru import logger

from driver_hacker.emulator.emulator_callback import EmulatorCallback
from driver_hacker.emulator.emulator_callback_result import EmulatorCallbackResult
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
    __images: dict[str, Image]

    __DISASSEMBLY_SIZE = 7
    __KUSER_SHARED_DATA_ADDRESS = 0xFFFFF78000000000

    def __init__(
        self,
        stack_size: int,
        memory_start: int,
        memory_end: int,
        kuser_shared_data: bytes,
        images: Mapping[str, Image],
        import_fallbacks: Mapping[tuple[str, str | int], EmulatorCallback],
        default_import_fallback: EmulatorCallback | None,
        function_callbacks: Mapping[tuple[str, str | int], EmulatorCallback],
    ) -> None:
        self.__uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        self.__register_manager = RegisterManager(self.__uc)
        self.__memory_manager = MemoryManager(self.__uc, memory_start, memory_end)
        self.__images = dict(images)

        self.memory.map(self.__KUSER_SHARED_DATA_ADDRESS, self.memory.page_size, Permission.READ)
        self.memory.write(self.__KUSER_SHARED_DATA_ADDRESS, kuser_shared_data)

        for image_name in self.__images:
            self.__map_image_sections(image_name)

        for image_name in self.__images:
            self.__resolve_image_imports(image_name, import_fallbacks, default_import_fallback)

        for (image, function_identifier), callback in function_callbacks.items():
            self.__add_callback(image, function_identifier, callback)

        stack = self.memory.allocate(stack_size, Permission.READ_WRITE)
        self.register.rsp = stack + stack_size // 2

    @property
    def uc(self) -> unicorn.Uc:
        return self.__uc

    @property
    def register(self) -> RegisterManager:
        return self.__register_manager

    @property
    def memory(self) -> MemoryManager:
        return self.__memory_manager

    def disassembly(self, *, level: int | str = "TRACE") -> None:
        logger.log(level, "Disassembly:")

        current_address = self.register.rip
        image = self.__get_image_by_address(current_address)

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
            image = self.__get_image_by_address(current_address)
            function: func_t | None = image.funcs.get_func(current_address)
            if function is None:
                break

            mark = ">" if current_address == self.register.rip else " "
            function_name: str = image.funcs.get_func_name(function.start_ea)
            entry = self.__format_stack_trace_entry(image.stem, function_name, function.start_ea, current_address)
            logger.log(level, "{} {:#018x} {}", mark, current_address, entry)

            current_stack_address += image.frame.get_frame_size(function)
            current_address = self.memory.read_pointer(current_stack_address)

    def get(self, image_name: str) -> Image:
        try:
            return self.__images[image_name]

        except KeyError as key_error:
            message = f"Image `{image_name}` does not exist"
            raise ValueError(message) from key_error

    def resolve(self, image_name: str, symbol_identifier: str | int) -> int:
        image = self.get(image_name)

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

    def start(self, address: int) -> None:
        self.uc.emu_start(address, 0)

    def __map_image_sections(self, image_name: str) -> None:
        image = self.get(image_name)
        image_start: int = image.nalt.get_imagebase()
        image_end: int = max(image.segment.getnseg(index).end_ea for index in range(image.segment.get_segm_qty()))
        image_size = image_end - image_start

        address = self.memory.allocate(image_size)
        self.memory.unmap(address, image_size)
        image.segment.rebase_program(address - image_start, image.segment.MSF_FIXONCE)

        logger.info("Adding image `{}` at address {:#x}", image.stem, address)

        segment: segment_t = image.segment.get_first_seg()
        while segment is not None:
            segment_size = segment.end_ea - segment.start_ea

            self.memory.map(segment.start_ea, segment_size, Permission.from_ida(segment.perm))

            data: bytes = image.bytes.get_bytes(segment.start_ea, segment_size)
            self.memory.write(segment.start_ea, data)

            segment = image.segment.get_next_seg(segment.start_ea)

    def __resolve_image_imports(
        self,
        image_name: str,
        import_fallbacks: Mapping[tuple[str, str | int], EmulatorCallback],
        default_import_fallback: EmulatorCallback | None,
    ) -> None:
        image = self.get(image_name)
        for index in range(image.nalt.get_import_module_qty()):
            source_image_name: str = image.nalt.get_import_module_name(index)

            if source_image_name in self.__images:
                image.nalt.enum_import_names(
                    index,
                    partial(
                        self.__resolve_image_imports_callback,
                        image.stem,
                        source_image_name,
                        import_fallbacks,
                        default_import_fallback,
                    ),
                )
                continue

            logger.warning(
                "Image `{}` imports symbols from image `{}`, but such image doesn't exist",
                image.stem,
                source_image_name,
            )

    def __resolve_image_imports_callback(
        self,
        image_name: str,
        source_image_name: str,
        import_fallbacks: Mapping[tuple[str, str | int], EmulatorCallback],
        default_import_fallback: EmulatorCallback | None,
        address: int,
        name: str | None,
        ordinal: int,
    ) -> bool:
        source_address = None
        with suppress(ValueError):
            source_address = self.resolve(source_image_name, name or ordinal)

        if source_address is not None:
            self.memory.write_pointer(address, source_address)
            return True

        import_callback = import_fallbacks.get((source_image_name, name or ordinal), default_import_fallback)
        if import_callback is not None:
            hook_address = self.memory.allocate(self.memory.page_size, Permission.READ_EXECUTE)
            self.uc.hook_add(
                unicorn.UC_HOOK_CODE,
                lambda *_: self.__run_callback(import_callback),
                begin=hook_address,
                end=hook_address + 1,
            )
            self.memory.write_pointer(address, hook_address)
            return True

        logger.warning(
            "Image `{}` imports symbol {} from image `{}`, but such symbol doesn't exist",
            image_name,
            f"`{name}`" or f"#{ordinal}",
            source_image_name,
        )
        return True

    def __add_callback(self, image_name: str, function_identifier: str | int, callback: EmulatorCallback) -> None:
        address = self.resolve(image_name, function_identifier)
        self.uc.hook_add(
            unicorn.UC_HOOK_CODE,
            lambda *_: self.__run_callback(callback),
            begin=address,
            end=address + 1,
        )

    def __run_callback(self, callback: EmulatorCallback) -> None:
        match callback(self):
            case EmulatorCallbackResult.CONTINUE:
                pass

            case EmulatorCallbackResult.RETURN:
                self.register.rip = self.memory.read_pointer(self.register.rsp)
                self.register.rsp = self.register.rsp + self.memory.pointer_size

            case EmulatorCallbackResult.STOP:
                self.uc.emu_stop()

            case never:
                assert_never(never)

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

    def __get_image_by_address(self, address: int) -> Image:
        for image in self.__images.values():
            if image.segment.getseg(address) is not None:
                return image

        message = f"Address {address:#x} is not in any image"
        raise ValueError(message)
