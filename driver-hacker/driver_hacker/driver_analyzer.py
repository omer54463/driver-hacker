from typing import TYPE_CHECKING

from unicorn import (  # type: ignore[import-untyped]
    UC_ARCH_X86,
    UC_MODE_64,
    Uc,
)

from driver_hacker.allocator.allocator import Allocator
from driver_hacker.allocator.permission import Permission
from driver_hacker.ida.ida import Ida

if TYPE_CHECKING:
    from ida_segment import segment_t  # type: ignore[import-not-found]


class DriverAnalyzer:
    __emulator: Uc
    __allocator: Allocator

    __KERNEL_START_ADDRESS = 0xFFFF000000000000
    __KERNEL_END_ADDRESS = 0xFFFFFFFFFFFFFFFF

    def __init__(self) -> None:
        self.__emulator = Uc(UC_ARCH_X86, UC_MODE_64)
        self.__allocator = Allocator(self.__emulator, self.__KERNEL_START_ADDRESS, self.__KERNEL_END_ADDRESS)

    def add(self, ida: Ida) -> None:
        start_address: int = ida.nalt.get_imagebase()
        end_address: int = max(ida.segment.getnseg(i).start_ea for i in range(ida.segment.get_segm_qty()))
        size = end_address - start_address

        address = self.__allocator.allocate(size)
        self.__allocator.free(address, size)
        ida.segment.rebase_program(address, ida.segment.MSF_FIXONCE)

        segment: segment_t = ida.segment.get_first_seg()
        while segment is not None:
            segment_size = segment.end_ea - segment.start_ea
            self.__emulator.mem_map(segment.start_ea, segment_size, Permission.from_ida(segment.perm).to_uc())
            data: bytes = ida.bytes.get_bytes(segment.start_ea, segment_size)
            self.__emulator.mem_write(segment.start_ea, data)
            segment = ida.segment.get_next_seg(segment.start_ea)
