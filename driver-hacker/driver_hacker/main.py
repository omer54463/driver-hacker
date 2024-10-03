from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
from re import Pattern, compile
from sys import stderr
from typing import final

from loguru import logger

from driver_hacker.emulator.emulator import Emulator
from driver_hacker.emulator.memory_manager.permission import Permission
from driver_hacker.get_drivers import get_drivers
from driver_hacker.image.ida_cache import ImageCache
from driver_hacker.image.image import Image

__STACK_SIZE = 0x10000
__MEMORY_START = 0xFFFF000000000000
__MEMORY_END = 0xFFFFFFFFFFFFFFFF


@final
@dataclass(frozen=True)
class Arguments:
    pattern: Pattern[str]
    cache: Path
    verbose: bool


def parse_arguments() -> Arguments:
    argument_parser = ArgumentParser()
    argument_parser.add_argument(
        "-p",
        "--pattern",
        type=compile,
        default=compile(""),
        help="REGEX pattern to match driver names against",
    )
    argument_parser.add_argument(
        "-c",
        "--cache",
        type=Path,
        default=Path.cwd() / "cache",
        help="IDA database cache directory",
    )
    argument_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    return Arguments(**vars(argument_parser.parse_args()))


def rtl_init_unicode_string_ex(emulator: Emulator) -> int:
    source_string_address = emulator.register.get("rdx")
    source_string = emulator.memory.read_wstring(source_string_address)
    source_string_byte_count = len(source_string.encode("utf-16-le"))

    destination_string_address = emulator.register.get("rcx")
    emulator.memory.write_word(destination_string_address, source_string_byte_count)
    emulator.memory.write_word(destination_string_address + 2, source_string_byte_count)
    emulator.memory.write_pointer(destination_string_address + 8, source_string_address)
    return 0


@logger.catch
def analyze(image: Image) -> None:
    emulator = Emulator(__MEMORY_START, __MEMORY_END)
    emulator.add_image(image)

    emulator.add_fallback("ntoskrnl", "RtlQueryFeatureConfigurationChangeStamp", lambda _: 0)
    emulator.add_fallback("ntoskrnl", "RtlQueryFeatureConfiguration", lambda _: 0)
    emulator.add_fallback("ntoskrnl", "EtwRegister", lambda _: 0)
    emulator.add_fallback("ntoskrnl", "EtwSetInformation", lambda _: 0)
    emulator.add_fallback("ntoskrnl", "RtlInitUnicodeStringEx", rtl_init_unicode_string_ex)

    stack = emulator.memory.allocate(__STACK_SIZE * 2, Permission.READ_WRITE) + __STACK_SIZE
    emulator.register.set("rsp", stack)

    driver_entry = emulator.get_export(image.path.stem, "DriverEntry")
    try:
        emulator.uc.emu_start(driver_entry, 0)
    except Exception:
        emulator.print_stack()
        raise


def main(arguments: Arguments) -> None:
    logger.remove()
    logger.add(stderr, level="TRACE" if arguments.verbose else "INFO")

    image_cache = ImageCache(arguments.cache)
    drivers = get_drivers()

    for driver, driver_path in drivers.items():
        if not arguments.pattern.match(driver):
            continue

        analyze(image_cache.get(driver_path))
