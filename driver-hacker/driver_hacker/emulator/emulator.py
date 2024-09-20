from typing import TYPE_CHECKING

from loguru import logger
from unicorn import (  # type: ignore[import-untyped]
    UC_ARCH_X86,
    UC_MODE_64,
    Uc,
)

from driver_hacker.emulator.memory_manager.memory_manager import MemoryManager
from driver_hacker.emulator.memory_manager.permission import Permission
from driver_hacker.emulator.register_manager.register_manager import RegisterManager
from driver_hacker.image.image import Image

if TYPE_CHECKING:
    from ida_segment import segment_t  # type: ignore[import-not-found]


class Emulator:
    __uc: Uc
    __register_manager: RegisterManager
    __memory_manager: MemoryManager

    def __init__(self, memory_start: int, memory_end: int) -> None:
        self.__uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.__register_manager = RegisterManager(self.__uc)
        self.__memory_manager = MemoryManager(self.__uc, memory_start, memory_end)

    @property
    def uc(self) -> Uc:
        return self.__uc

    @property
    def register(self) -> RegisterManager:
        return self.__register_manager

    @property
    def memory(self) -> MemoryManager:
        return self.__memory_manager

    def add_image(self, image: Image) -> None:
        image_start: int = image.nalt.get_imagebase()
        image_end: int = max(image.segment.getnseg(i).end_ea for i in range(image.segment.get_segm_qty()))
        image_size = image_end - image_start

        address = self.__memory_manager.allocate(image_size)
        self.__memory_manager.unmap(address, image_size)
        image.segment.rebase_program(address - image_start, image.segment.MSF_FIXONCE)

        logger.info("Adding image `{}` at address {:#x}", image.name, address)

        segment: segment_t = image.segment.get_first_seg()
        while segment is not None:
            segment_size = segment.end_ea - segment.start_ea

            self.__memory_manager.map(segment.start_ea, segment_size, Permission.from_ida(segment.perm))

            data: bytes = image.bytes.get_bytes(segment.start_ea, segment_size)
            self.__uc.mem_write(segment.start_ea, data)

            segment = image.segment.get_next_seg(segment.start_ea)
