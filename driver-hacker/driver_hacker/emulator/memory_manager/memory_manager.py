from collections.abc import Generator
from math import ceil, floor
from typing import Literal, final

import unicorn
from loguru import logger

from driver_hacker.emulator.memory_manager.allocated_blocks import AllocatedBlock
from driver_hacker.emulator.memory_manager.free_block import FreeBlock
from driver_hacker.emulator.memory_manager.permission import Permission


@final
class MemoryManager:
    __uc: unicorn.Uc

    __START_ADDRESS_ZERO_COUNT = 47

    def __init__(self, uc: unicorn.Uc) -> None:
        self.__uc = uc

    @property
    def start(self) -> int:
        one_count = 1

        while (start := (1 << one_count - 1) << self.__START_ADDRESS_ZERO_COUNT).bit_length() < self.pointer_size * 8:
            one_count += 1

        return start

    @property
    def end(self) -> int:
        return (1 << (self.pointer_size * 8)) - 1

    @property
    def page_size(self) -> int:
        page_size: int = self.__uc.ctl_get_page_size()
        return page_size

    @property
    def pointer_size(self) -> int:
        if (architecture := self.__uc.ctl_get_arch()) != unicorn.UC_ARCH_X86:
            message = f"Unsupported architecture `{architecture}`"
            raise NotImplementedError(message)

        mode: int = self.__uc.ctl_get_mode()

        if mode & unicorn.UC_MODE_64:
            return 8

        if mode & unicorn.UC_MODE_32:
            return 4

        if mode & unicorn.UC_MODE_16:
            return 2

        message = f"Failed to process mode {mode:#x}"
        raise RuntimeError(message)

    @property
    def endian(self) -> Literal["big", "little"]:
        return "big" if self.__uc.ctl_get_mode() & unicorn.UC_MODE_BIG_ENDIAN else "little"

    @property
    def free_blocks(self) -> Generator[FreeBlock]:
        current = self.start
        for block in self.allocated_blocks:
            if block.start > current:
                yield FreeBlock(current, block.start)

            current = max(current, block.end)

        if current < self.end:
            yield FreeBlock(current, self.end)

    @property
    def allocated_blocks(self) -> Generator[AllocatedBlock]:
        for first, last, permissions in self.__uc.mem_regions():
            if self.start <= first < self.end or self.start <= last < self.end:
                yield AllocatedBlock(max(first, self.start), min(last + 1, self.end), Permission.from_uc(permissions))

    def map(self, start: int, size: int, permissions: Permission = Permission.ALL) -> None:
        logger.trace("map(start={:#x}, size={:#x}, permissions={})", start, size, permissions)

        aligned_start, aligned_end, aligned_size = self.__process_start_and_size(start, size)

        for block in self.allocated_blocks:
            if (overlap_block := self.__overlap(block, aligned_start, aligned_end)) is not None:
                if overlap_block.permissions == permissions:
                    self.unmap(overlap_block.start, overlap_block.size)

                else:
                    message = f"Cannot map {size:#x} bytes at address {start:#x} without modifying permissions"
                    raise RuntimeError(message)

        self.__uc.mem_map(aligned_start, aligned_size, permissions.to_uc())

    def allocate(self, size: int, permissions: Permission = Permission.ALL) -> int:
        logger.trace("allocate(size={:#x}, permissions={})", size, permissions)

        for block in self.free_blocks:
            if block.size >= size:
                self.map(block.start, size, permissions)

                logger.trace("allocate(...) -> {:#x}", block.start)
                return block.start

        message = f"Failed to find a free block of at least {size:#x} bytes"
        raise RuntimeError(message)

    def unmap(self, start: int, size: int) -> None:
        logger.trace("free(start={:#x}, size={:#x})", start, size)

        aligned_start, _, aligned_size = self.__process_start_and_size(start, size)
        self.__uc.mem_unmap(aligned_start, aligned_size)

    def is_mapped(self, address: int) -> bool:
        return any(block.start <= address < block.end for block in self.allocated_blocks)

    def is_unmapped(self, address: int) -> bool:
        return any(block.start <= address < block.end for block in self.free_blocks)

    def write(self, address: int, data: bytes) -> None:
        self.__uc.mem_write(address, data)

    def write_byte(self, address: int, value: int) -> None:
        self.write(address, value.to_bytes(1, self.endian))

    def write_word(self, address: int, value: int) -> None:
        self.write(address, value.to_bytes(2, self.endian))

    def write_dword(self, address: int, value: int) -> None:
        self.write(address, value.to_bytes(4, self.endian))

    def write_qword(self, address: int, value: int) -> None:
        self.write(address, value.to_bytes(8, self.endian))

    def write_pointer(self, address: int, value: int) -> None:
        self.write(address, value.to_bytes(self.pointer_size, self.endian))

    def write_string(self, address: int, value: str) -> None:
        for byte in value.encode("ascii"):
            self.write_byte(address, byte)
            address += 1

    def write_wstring(self, address: int, value: str) -> None:
        for byte in value.encode("utf-16-le"):
            self.write_byte(address, byte)
            address += 1

    def read(self, address: int, size: int) -> bytes:
        return bytes(self.__uc.mem_read(address, size))

    def read_byte(self, address: int) -> int:
        return int.from_bytes(self.read(address, 1), self.endian)

    def read_word(self, address: int) -> int:
        return int.from_bytes(self.read(address, 2), self.endian)

    def read_dword(self, address: int) -> int:
        return int.from_bytes(self.read(address, 4), self.endian)

    def read_qword(self, address: int) -> int:
        return int.from_bytes(self.read(address, 8), self.endian)

    def read_pointer(self, address: int) -> int:
        return int.from_bytes(self.read(address, self.pointer_size), self.endian)

    def read_string(self, address: int) -> str:
        data = b""

        while (character := self.read(address, 1)) != b"\0":
            data += character
            address += 1

        return data.decode("ascii")

    def read_wstring(self, address: int) -> str:
        data = b""

        while (character := self.read(address, 2)) != b"\0\0":
            data += character
            address += 2

        return data.decode("utf-16-le")

    def __process_start_and_size(self, start: int, size: int) -> tuple[int, int, int]:
        aligned_start = self.__align_down(start)
        aligned_size = self.__align_up(size + start - aligned_start)
        aligned_end = aligned_start + aligned_size
        if (
            aligned_start < self.start
            or aligned_start >= self.end
            or aligned_end < self.start
            or aligned_end >= self.end
        ):
            message = f"Invalid start {start:#x} or size {size:#x}"
            raise RuntimeError(message)

        return aligned_start, aligned_end, aligned_size

    @staticmethod
    def __overlap(block: AllocatedBlock, start: int, end: int) -> AllocatedBlock | None:
        overlap_start = max(block.start, start)
        overlap_end = min(block.end, end)

        if overlap_start >= overlap_end:
            return None

        return AllocatedBlock(overlap_start, overlap_end, block.permissions)

    def __align_down(self, value: int) -> int:
        return floor(value / self.page_size) * self.page_size

    def __align_up(self, value: int) -> int:
        return ceil(value / self.page_size) * self.page_size
