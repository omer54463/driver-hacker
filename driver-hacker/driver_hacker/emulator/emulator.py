from collections.abc import Callable
from typing import TYPE_CHECKING, ParamSpec, Self, TypeVar, assert_never, final

import unicorn  # type: ignore[import-untyped]
from loguru import logger

from driver_hacker.emulator.memory_manager.memory_manager import MemoryManager
from driver_hacker.emulator.memory_manager.permission import Permission
from driver_hacker.emulator.register_manager.register_manager import RegisterManager
from driver_hacker.image.image import Image

if TYPE_CHECKING:
    from ida_funcs import func_t  # type: ignore[import-not-found]
    from ida_segment import segment_t  # type: ignore[import-not-found]

P = ParamSpec("P")
R = TypeVar("R")


@final
class Emulator:
    __uc: unicorn.Uc

    __register_manager: RegisterManager
    __memory_manager: MemoryManager

    __stack_size: int

    __images: dict[str, Image]
    __overrides: dict[tuple[str, int | str], Callable[[Self], int | None]]
    __fallbacks: dict[tuple[str, int | str], Callable[[Self], int | None]]

    def __init__(self, stack_size: int, memory_start: int, memory_end: int) -> None:
        self.__uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

        self.__register_manager = RegisterManager(self.__uc)
        self.__memory_manager = MemoryManager(self.__uc, memory_start, memory_end)

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

    def add_override(self, module_name: str, identifier: int | str, override: Callable[[Self], int | None]) -> None:
        self.__overrides[(module_name, identifier)] = override

    def add_fallback(self, module_name: str, identifier: int | str, fallback: Callable[[Self], int | None]) -> None:
        self.__fallbacks[(module_name, identifier)] = fallback

    def try_get_import(self, source_module_name: str, module_name: str, identifier: int | str) -> int | None:
        image = self.__images[source_module_name]

        for index in range(image.nalt.get_import_module_qty()):
            target_module_name: str = image.nalt.get_import_module_name(index)
            if target_module_name != module_name:
                continue

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

            image.nalt.enum_import_names(index, __callback)

            return address

        return None

    def get_import(self, source_module_name: str, module_name: str, identifier: int | str) -> int:
        match self.try_get_import(source_module_name, module_name, identifier):
            case int(address):
                return address

            case None:
                message = f"Cannot find import `{identifier}` of module `{module_name}`"
                raise ValueError(message)

            case never:
                assert_never(never)

    def try_get_export(self, module_name: str, identifier: int | str) -> int | None:
        if module_name not in self.__images:
            return None

        image = self.__images[module_name]

        match identifier:
            case str() as name:
                address: int = image.name.get_name_ea(image.api.BADADDR, name)

            case int() as ordinal:
                address = image.entry.get_entry(ordinal)

            case never:
                assert_never(never)

        if address == image.api.BADADDR:
            return None

        return address

    def get_export(self, module_name: str, identifier: int | str) -> int:
        match self.try_get_export(module_name, identifier):
            case int(address):
                return address

            case None:
                message = f"Cannot find export `{identifier}` of module `{module_name}`"
                raise ValueError(message)

            case never:
                assert_never(never)

    def try_get_name(self, address: int) -> str | None:
        for image_name, image in self.__images.items():
            function: func_t | None = image.funcs.get_func(address)
            if function is None:
                continue

            name: str = image.funcs.get_func_name(function.start_ea)
            distance = address - function.start_ea

            if distance < 0:
                return f"{image_name}!{name}-{-distance}"
            if distance == 0:
                return f"{image_name}!{name}"
            return f"{image_name}!{name}+{distance}"

        return None

    def get_name(self, address: int) -> str:
        match self.try_get_name(address):
            case str(name):
                return name

            case None:
                message = f"Cannot find name for address {address:#x}"
                raise ValueError(message)

            case never:
                assert_never(never)

    def stack_trace(self, level: int | str) -> None:
        value = self.register.get("rip")
        if isinstance(name := self.try_get_name(value), str):
            logger.log(level, "{:#018x} [{}]", value, name)

        start_address = self.register.get("rsp")
        address = start_address
        while self.memory.is_mapped(address) and address - start_address < self.stack_size:
            value = self.memory.read_pointer(address)
            if isinstance(name := self.try_get_name(value), str):
                logger.log(level, "{:#018x} [{}]", address, name)
            address += self.memory.pointer_size

    def start(self, address: int) -> None:
        stack = self.memory.allocate(self.stack_size * 2, Permission.READ_WRITE)
        self.register.set("rsp", stack + self.__stack_size)
        self.uc.emu_start(address, 0)

    def __map_sections(self, image: Image) -> None:
        image_start: int = image.nalt.get_imagebase()
        image_end: int = max(image.segment.getnseg(i).end_ea for i in range(image.segment.get_segm_qty()))
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
            target_module_name: str = image.nalt.get_import_module_name(index)

            def __callback(import_address: int, target_name: str | None, target_ordinal: int) -> bool:
                target = (
                    (target_module_name, target_ordinal) if target_name is None else (target_module_name, target_name)
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

        if (address := self.try_get_export(*target)) is not None:
            self.register.set("rip", address)
            return

        if target in self.__fallbacks:
            self.__run_callback(self.__fallbacks[target])
            return

        module_name, identifier = target
        message = f"Cannot find implementation for import `{identifier}` of module `{module_name}`"
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
