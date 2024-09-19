from collections.abc import Generator

from unicorn import (  # type: ignore[import-untyped]
    Uc,
)

from driver_hacker.allocator.allocated_region import AllocatedRegion
from driver_hacker.allocator.free_region import FreeRegion
from driver_hacker.allocator.permission import Permission


class Allocator:
    __emulator: Uc
    __start_address: int
    __end_address: int

    def __init__(self, emulator: Uc, start_address: int, end_address: int) -> None:
        self.__emulator = emulator
        self.__start_address = start_address
        self.__end_address = end_address

    def allocate(self, size: int, permissions: Permission = Permission.ALL) -> int:
        for free_region in self.free_regions:
            if free_region.size >= size:
                self.__emulator.mem_map(free_region.start_address, size, permissions.to_uc())
                return free_region.start_address

        message = f"Failed to allocate {size:#x} bytes"
        raise RuntimeError(message)

    def allocate_at(self, address: int, size: int, permissions: Permission = Permission.ALL) -> int:
        for free_region in self.free_regions:
            if (
                free_region.start_address <= address < free_region.end_address
                and free_region.end_address - address >= size
            ):
                self.__emulator.mem_map(address, size, permissions.to_uc())
                return free_region.start_address

        message = f"Failed to allocate {size:#x} bytes at {address:#x}"
        raise RuntimeError(message)

    def free(self, address: int, size: int) -> None:
        self.__emulator.mem_unmap(address, size)

    @property
    def free_regions(self) -> Generator[FreeRegion]:
        current_address = self.__start_address
        for allocated_region in self.allocated_regions:
            if allocated_region.start_address > current_address:
                yield FreeRegion(current_address, allocated_region.start_address)

            current_address = max(current_address, allocated_region.end_address)

        if current_address < self.__end_address:
            yield FreeRegion(current_address, self.__end_address)

    @property
    def allocated_regions(self) -> Generator[AllocatedRegion]:
        for first_address, last_address, permissions in self.__emulator.mem_regions():
            if (
                self.__start_address <= first_address < self.__end_address
                or self.__start_address <= last_address < self.__end_address
            ):
                yield AllocatedRegion(
                    max(first_address, self.__start_address),
                    min(last_address + 1, self.__end_address),
                    Permission.from_uc(permissions),
                )
