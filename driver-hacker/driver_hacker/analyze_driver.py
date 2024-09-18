from collections.abc import Iterable
from math import ceil, floor
from typing import TYPE_CHECKING

from loguru import logger
from unicorn import (  # type: ignore[import-untyped]
    UC_ARCH_X86,
    UC_MODE_64,
    UC_PROT_EXEC,
    UC_PROT_READ,
    UC_PROT_WRITE,
    Uc,
)
from unicorn.x86_const import UC_X86_REG_RIP  # type: ignore[import-untyped]

from driver_hacker.ida.ida import Ida

if TYPE_CHECKING:
    from ida_segment import segment_t  # type: ignore[import-not-found]

__PAGE_SIZE = 0x1000
__POINTER_SIZE = 8


def analyze_driver(ntoskrnl: Ida, driver: Ida) -> None:
    emulator = Uc(UC_ARCH_X86, UC_MODE_64)

    __map_segments(emulator, ntoskrnl)
    __map_segments(emulator, driver)
    __resolve_imports(emulator, ntoskrnl)
    __resolve_imports(emulator, driver, (ntoskrnl,))

    start = 0x00000001C00571E8
    end = 0x00000001C00572FC

    current = start
    while current != end:
        emulator.emu_start(current, end, count=1)
        current = emulator.reg_read(UC_X86_REG_RIP)
        logger.info("{}", hex(current))


def __map_segments(emulator: Uc, ida: Ida) -> None:
    logger.info("Mapping `{}` segments", ida.name)

    segment: segment_t = ida.segment.get_first_seg()
    while segment is not None:
        __map_segment(emulator, ida, segment)
        segment = ida.segment.get_next_seg(segment.start_ea)


def __resolve_imports(emulator: Uc, driver: Ida, libraries: Iterable[Ida] | None = None) -> None:
    if libraries is None:
        libraries = {}

    library_mapping = {library.name: library for library in libraries}

    imports = __get_imports(driver)
    for library_name, library_imports in imports.items():
        if library_name in library_mapping:
            library = library_mapping[library_name]
            exports = __get_exports(library)

            for import_address, import_name, import_ordinal in library_imports:
                if import_name in exports:
                    export_address = exports[import_name]

                elif import_ordinal in exports:
                    export_address = exports[import_ordinal]

                else:
                    message = f"Import `{library_name}:{import_name or import_ordinal}` could not be resolved"
                    raise RuntimeError(message)

                emulator.mem_write(import_address, export_address.to_bytes(__POINTER_SIZE, "little"))


def __get_imports(driver: Ida) -> dict[str, list[tuple[int, str | None, int | None]]]:
    imports: dict[str, list[tuple[int, str | None, int | None]]] = {}

    for index in range(driver.nalt.get_import_module_qty()):
        library_imports: list[tuple[int, str | None, int | None]] = []

        def __resolve_imports_callback(address: int, name: str | None, ordinal: int | None) -> bool:
            library_imports.append((address, name, ordinal))
            return True

        driver.nalt.enum_import_names(index, __resolve_imports_callback)

        library_name: str = driver.nalt.get_import_module_name(index)
        imports[library_name] = library_imports

    return imports


def __get_exports(driver: Ida) -> dict[int | str, int]:
    exports: dict[int | str, int] = {}

    for index in range(driver.entry.get_entry_qty()):
        ordinal: int = driver.entry.get_entry_ordinal(index)
        address: int = driver.entry.get_entry(ordinal)
        name: str | None = driver.entry.get_entry_name(ordinal)

        if ordinal != 0:
            exports[ordinal] = address

        if name is not None:
            exports[name] = address

    return exports


def __map_segment(emulator: Uc, ida: Ida, segment: "segment_t") -> None:
    segment_start = __align_down(segment.start_ea, __PAGE_SIZE)
    segment_end = __align_up(segment.end_ea, __PAGE_SIZE)
    segment_permissions = segment.perm

    region_start = segment_start
    region_end = segment_end - 1
    region_permissions = 0
    if segment_permissions & ida.segment.SEGPERM_EXEC:
        region_permissions |= UC_PROT_EXEC
    if segment_permissions & ida.segment.SEGPERM_WRITE:
        region_permissions |= UC_PROT_WRITE
    if segment_permissions & ida.segment.SEGPERM_READ:
        region_permissions |= UC_PROT_READ

    for other_region_start, other_region_end, other_region_permissions in emulator.mem_regions():
        if other_region_start <= segment_start <= other_region_end:
            if region_permissions == other_region_permissions:
                emulator.mem_unmap(other_region_start, other_region_end - other_region_start + 1)
                region_start = other_region_start

            else:
                message = f"Contradicting permissions around {segment_start:#x}"
                raise RuntimeError(message)

        if other_region_start < segment_end <= other_region_end + 1:
            if region_permissions == other_region_permissions:
                emulator.mem_unmap(other_region_start, other_region_end - other_region_start + 1)
                region_end = other_region_end

            else:
                message = f"Contradicting permissions around {segment_end:#x}"
                raise RuntimeError(message)

    emulator.mem_map(region_start, region_end - region_start + 1, region_permissions)
    data: bytes = ida.bytes.get_bytes(segment.start_ea, segment.end_ea - segment.start_ea)
    emulator.mem_write(segment.start_ea, data)


def __align_down(value: int, factor: int) -> int:
    return floor(value / factor) * factor


def __align_up(value: int, factor: int) -> int:
    return ceil(value / factor) * factor
