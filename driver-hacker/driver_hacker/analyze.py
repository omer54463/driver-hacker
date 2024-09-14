from typing import TYPE_CHECKING, final

from loguru import logger
from unicorn import UC_ARCH_X86, UC_MODE_64, Uc  # type: ignore[import-untyped]

from driver_hacker.ida.ida import Ida

if TYPE_CHECKING:
    from ida_segment import segment_t  # type: ignore[import-not-found]


@final
class _Section:
    __start: int
    __end: int

    def __init__(self, start: int, end: int) -> None:
        self.__start = start
        self.__end = end

    @property
    def start(self) -> int:
        return self.__start

    @property
    def end(self) -> int:
        return self.__end

    @property
    def size(self) -> int:
        return self.__end - self.__start


def analyze(ntoskrnl: Ida, target: Ida) -> None:
    emulator = Uc(UC_ARCH_X86, UC_MODE_64)

    __map_sections(emulator, ntoskrnl)
    __map_sections(emulator, target)


def __map_sections(emulator: Uc, driver: Ida) -> dict[str, _Section]:
    logger.info("Mapping `{}` sections", driver.name)

    sections: dict[str, _Section] = {}

    seg: segment_t = driver.segment.get_first_seg()
    while seg is not None:
        name: str = driver.segment.get_segm_name(seg)

        if name in sections:
            if sections[name].end != seg.start_ea:
                message = f"Non-adjacent segments with name `{name}` were found"
                raise RuntimeError(message)

            sections[name] = _Section(sections[name].start, seg.end_ea)

        else:
            sections[name] = _Section(seg.start_ea, seg.end_ea)

        seg = driver.segment.get_next_seg(seg.start_ea)

    for section in sections.values():
        emulator.mem_map(section.start, section.size)
        data: bytes = driver.bytes.get_bytes(section.start, section.size)
        emulator.mem_write(section.start, data)

    return sections
