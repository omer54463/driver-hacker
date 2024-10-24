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
        emulator = cls.__create_empty(images)

        if kuser_shared_data is not None:
            cls.__setup_kuser_shared_data(emulator, kuser_shared_data)

        cls.__map_images(emulator)

        import_fallbacks = {} if import_fallbacks is None else import_fallbacks
        cls.__resolve_imports(emulator, import_fallbacks, default_import_fallback)

        function_callbacks = {} if function_callbacks is None else function_callbacks
        cls.__add_callbacks(emulator, function_callbacks)

        cls.__setup_stack(emulator)
        cls.__setup_segmentation(emulator)

        return emulator

    @staticmethod
    def __create_empty(images: AbstractSet[Image]) -> Emulator:
        uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        uc.ctl_tlb_mode(unicorn.UC_TLB_VIRTUAL)

        image_manager = ImageManager(images)
        register_manager = RegisterManager(uc)
        memory_manager = MemoryManager(uc)
        return Emulator(uc, image_manager, register_manager, memory_manager)

    @classmethod
    def __setup_kuser_shared_data(cls, emulator: Emulator, kuser_shared_data: bytes) -> None:
        emulator.memory.map(cls.__KUSER_SHARED_DATA_ADDRESS, emulator.memory.page_size, Permission.READ)
        emulator.memory.write(cls.__KUSER_SHARED_DATA_ADDRESS, kuser_shared_data)

    @classmethod
    def __map_images(cls, emulator: Emulator) -> None:
        for image in emulator.image:
            cls.__map_image(emulator, image)

    @staticmethod
    def __map_image(emulator: Emulator, image: Image) -> None:
        image_start: int = image.nalt.get_imagebase()
        image_end: int = max(image.segment.getnseg(index).end_ea for index in range(image.segment.get_segm_qty()))
        image_size = image_end - image_start

        address = emulator.memory.allocate(image_size)
        emulator.memory.unmap(address, image_size)
        image.segment.rebase_program(address - image_start, image.segment.MSF_FIXONCE)

        segment: segment_t = image.segment.get_first_seg()
        while segment is not None:
            segment_size = segment.end_ea - segment.start_ea

            emulator.memory.map(segment.start_ea, segment_size, Permission.from_ida(segment.perm))

            data: bytes = image.bytes.get_bytes(segment.start_ea, segment_size)
            emulator.memory.write(segment.start_ea, data)

            segment = image.segment.get_next_seg(segment.start_ea)

    @classmethod
    def __resolve_imports(
        cls,
        emulator: Emulator,
        import_fallbacks: Mapping[tuple[str, str | int], EmulatorCallback],
        default_import_fallback: EmulatorCallback | None,
    ) -> None:
        for image in emulator.image:
            cls.__resolve_image_imports(emulator, image, import_fallbacks, default_import_fallback)

    @classmethod
    def __resolve_image_imports(
        cls,
        emulator: Emulator,
        image: Image,
        import_fallbacks: Mapping[tuple[str, str | int], EmulatorCallback],
        default_import_fallback: EmulatorCallback | None,
    ) -> None:
        for index in range(image.nalt.get_import_module_qty()):
            source_image_name: str = image.nalt.get_import_module_name(index)

            try:
                source_image = emulator.image.get(source_image_name)

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
                    emulator,
                    image,
                    source_image,
                    import_fallbacks,
                    default_import_fallback,
                ),
            )

    @classmethod
    def __resolve_image_imports_callback(
        cls,
        emulator: Emulator,
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
            source_address = emulator.image.resolve(source_image.stem, name or ordinal)

        if source_address is not None:
            emulator.memory.write_pointer(address, source_address)
            return True

        import_callback = import_fallbacks.get((source_image.stem, name or ordinal), default_import_fallback)
        if import_callback is not None:
            hook_address = emulator.memory.allocate(emulator.memory.page_size, Permission.READ_EXECUTE)
            emulator.uc.hook_add(
                unicorn.UC_HOOK_CODE,
                lambda *_: cls.__run_callback(emulator, import_callback),
                begin=hook_address,
                end=hook_address + 1,
            )
            emulator.memory.write_pointer(address, hook_address)
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
        emulator: Emulator,
        function_callbacks: Mapping[tuple[str, str | int], EmulatorCallback],
    ) -> None:
        for (image_name, function_identifier), callback in function_callbacks.items():
            cls.__add_callback(emulator, emulator.image.get(image_name), function_identifier, callback)

    @classmethod
    def __add_callback(
        cls,
        emulator: Emulator,
        image: Image,
        function_identifier: str | int,
        callback: EmulatorCallback,
    ) -> None:
        address = emulator.image.resolve(image.stem, function_identifier)
        emulator.uc.hook_add(
            unicorn.UC_HOOK_CODE,
            lambda *_: cls.__run_callback(emulator, callback),
            begin=address,
            end=address + 1,
        )

    @classmethod
    def __setup_stack(cls, emulator: Emulator) -> None:
        stack_size = cls.__STACK_PAGE_COUNT * emulator.memory.page_size
        stack = emulator.memory.allocate(stack_size, Permission.READ_WRITE)
        emulator.register.rsp = stack + stack_size // 2

    @staticmethod
    def __setup_segmentation(emulator: Emulator) -> None:
        pass

    @staticmethod
    def __run_callback(emulator: Emulator, callback: EmulatorCallback) -> None:
        match callback(emulator):
            case EmulatorCallbackResult.CONTINUE:
                pass

            case EmulatorCallbackResult.RETURN:
                emulator.register.rip = emulator.memory.read_pointer(emulator.register.rsp)
                emulator.register.rsp = emulator.register.rsp + emulator.memory.pointer_size

            case EmulatorCallbackResult.STOP:
                emulator.uc.emu_stop()

            case never:
                assert_never(never)
