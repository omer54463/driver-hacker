from collections.abc import Mapping
from collections.abc import Set as AbstractSet
from contextlib import suppress
from functools import partial
from typing import TYPE_CHECKING, assert_never, final

import unicorn
from loguru import logger

from driver_hacker.emulator.emulator import Emulator
from driver_hacker.emulator.emulator_callback import EmulatorCallback
from driver_hacker.emulator.emulator_callback_result import EmulatorCallbackResult
from driver_hacker.emulator.image_manager.image_manager import ImageManager
from driver_hacker.emulator.memory_manager.memory_manager import MemoryManager
from driver_hacker.emulator.memory_manager.permission import Permission
from driver_hacker.emulator.register_manager.register_manager import RegisterManager
from driver_hacker.emulator.struct_manager.struct_manager import StructManager
from driver_hacker.image.image import Image

if TYPE_CHECKING:
    from ida_segment import segment_t  # type: ignore[import-not-found]


@final
class EmulatorFactory:
    __KUSER_SHARED_DATA_ADDRESS = 0xFFFFF78000000000
    __STACK_PAGE_COUNT = 0x10

    @classmethod
    def create(
        cls,
        images: AbstractSet[Image] | None = None,
        kuser_shared_data: bytes | None = None,
        import_fallbacks: Mapping[tuple[str, str | int], EmulatorCallback] | None = None,
        default_import_fallback: EmulatorCallback | None = None,
        function_callbacks: Mapping[tuple[str, str | int], EmulatorCallback] | None = None,
    ) -> Emulator:
        images = set() if images is None else images
        e = cls.__create_empty(images)

        if kuser_shared_data is not None:
            cls.__setup_kuser_shared_data(e, kuser_shared_data)

        cls.__map_images(e)

        import_fallbacks = {} if import_fallbacks is None else import_fallbacks
        cls.__resolve_imports(e, import_fallbacks, default_import_fallback)

        function_callbacks = {} if function_callbacks is None else function_callbacks
        cls.__add_callbacks(e, function_callbacks)

        cls.__setup_stack(e)

        return e

    @staticmethod
    def __create_empty(images: AbstractSet[Image]) -> Emulator:
        uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        uc.ctl_tlb_mode(unicorn.UC_TLB_VIRTUAL)

        img = ImageManager(images)
        str = StructManager(img)
        reg = RegisterManager(uc)
        mem = MemoryManager(uc)
        return Emulator(uc, img, str, reg, mem)

    @classmethod
    def __setup_kuser_shared_data(cls, e: Emulator, kuser_shared_data: bytes) -> None:
        e.mem.map(cls.__KUSER_SHARED_DATA_ADDRESS, e.mem.page_size, Permission.READ)
        e.mem.write(cls.__KUSER_SHARED_DATA_ADDRESS, kuser_shared_data)

    @classmethod
    def __map_images(cls, e: Emulator) -> None:
        for image in e.img:
            cls.__map_image(e, image)

    @staticmethod
    def __map_image(e: Emulator, image: Image) -> None:
        image_start: int = image.nalt.get_imagebase()
        image_end: int = max(image.segment.getnseg(index).end_ea for index in range(image.segment.get_segm_qty()))
        image_size = image_end - image_start

        address = e.mem.allocate(image_size)
        e.mem.unmap(address, image_size)
        image.segment.rebase_program(address - image_start, image.segment.MSF_FIXONCE)

        segment: segment_t = image.segment.get_first_seg()
        while segment is not None:
            segment_size = segment.end_ea - segment.start_ea

            e.mem.map(segment.start_ea, segment_size, Permission.from_ida(segment.perm))

            data: bytes = image.bytes.get_bytes(segment.start_ea, segment_size)
            e.mem.write(segment.start_ea, data)

            segment = image.segment.get_next_seg(segment.start_ea)

    @classmethod
    def __resolve_imports(
        cls,
        e: Emulator,
        import_fallbacks: Mapping[tuple[str, str | int], EmulatorCallback],
        default_import_fallback: EmulatorCallback | None,
    ) -> None:
        for image in e.img:
            cls.__resolve_image_imports(e, image, import_fallbacks, default_import_fallback)

    @classmethod
    def __resolve_image_imports(
        cls,
        e: Emulator,
        image: Image,
        import_fallbacks: Mapping[tuple[str, str | int], EmulatorCallback],
        default_import_fallback: EmulatorCallback | None,
    ) -> None:
        for index in range(image.nalt.get_import_module_qty()):
            source_image_name: str = image.nalt.get_import_module_name(index)

            try:
                source_image = e.img.get(source_image_name)

            except ValueError:
                logger.warning(
                    "Image `{}` imports symbols from image `{}`, but such image doesn't exist",
                    image.stem,
                    source_image_name,
                )
                continue

            image.nalt.enum_import_names(
                index,
                partial(
                    cls.__resolve_image_imports_callback,
                    e,
                    image,
                    source_image,
                    import_fallbacks,
                    default_import_fallback,
                ),
            )

    @classmethod
    def __resolve_image_imports_callback(
        cls,
        e: Emulator,
        image: Image,
        source_image: Image,
        import_fallbacks: Mapping[tuple[str, str | int], EmulatorCallback],
        default_import_fallback: EmulatorCallback | None,
        address: int,
        name: str | None,
        ordinal: int,
    ) -> bool:
        source_address = None
        with suppress(ValueError):
            source_address = e.img.resolve(source_image.stem, name or ordinal)

        if source_address is not None:
            e.mem.write_pointer(address, source_address)
            return True

        import_callback = import_fallbacks.get((source_image.stem, name or ordinal), default_import_fallback)
        if import_callback is not None:
            hook_address = e.mem.allocate(e.mem.page_size, Permission.READ_EXECUTE)
            e.uc.hook_add(
                unicorn.UC_HOOK_CODE,
                lambda *_: cls.__run_callback(e, import_callback),
                begin=hook_address,
                end=hook_address + 1,
            )
            e.mem.write_pointer(address, hook_address)
            return True

        logger.warning(
            "Image `{}` imports symbol {} from image `{}`, but such symbol doesn't exist",
            image.stem,
            f"`{name}`" or f"#{ordinal}",
            source_image.stem,
        )
        return True

    @classmethod
    def __add_callbacks(
        cls,
        e: Emulator,
        function_callbacks: Mapping[tuple[str, str | int], EmulatorCallback],
    ) -> None:
        for (image_name, function_identifier), callback in function_callbacks.items():
            cls.__add_callback(e, e.img.get(image_name), function_identifier, callback)

    @classmethod
    def __add_callback(
        cls,
        e: Emulator,
        image: Image,
        function_identifier: str | int,
        callback: EmulatorCallback,
    ) -> None:
        address = e.img.resolve(image.stem, function_identifier)
        e.uc.hook_add(
            unicorn.UC_HOOK_CODE,
            lambda *_: cls.__run_callback(e, callback),
            begin=address,
            end=address + 1,
        )

    @classmethod
    def __setup_stack(cls, e: Emulator) -> None:
        stack_size = cls.__STACK_PAGE_COUNT * e.mem.page_size
        stack = e.mem.allocate(stack_size, Permission.READ_WRITE)
        e.reg.rsp = stack + stack_size // 2

    @staticmethod
    def __run_callback(e: Emulator, callback: EmulatorCallback) -> None:
        match callback(e):
            case EmulatorCallbackResult.CONTINUE:
                pass

            case EmulatorCallbackResult.RETURN:
                e.reg.rip = e.mem.read_pointer(e.reg.rsp)
                e.reg.rsp = e.reg.rsp + e.mem.pointer_size

            case EmulatorCallbackResult.STOP:
                e.uc.emu_stop()

            case never:
                assert_never(never)
