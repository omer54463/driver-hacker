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

__STACK_SIZE = 0x1000
__MEMORY_START = 0xFFFF000000000000
__MEMORY_END = 0xFFFFFFFFFFFFFFFF

__KUSER_SHARED_DATA_ADDRESS = 0xFFFFF78000000000


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

    destination_string_address = emulator.register.get("rcx")
    emulator.memory.write_word(destination_string_address, len(source_string) * 2)
    emulator.memory.write_word(destination_string_address + 2, len(source_string) * 2)
    emulator.memory.write_pointer(destination_string_address + 8, source_string_address)
    return 0


def rtl_init_ansi_string(emulator: Emulator) -> int:
    source_string_address = emulator.register.get("rdx")
    source_string = emulator.memory.read_string(source_string_address)

    destination_string_address = emulator.register.get("rcx")
    emulator.memory.write_word(destination_string_address, len(source_string))
    emulator.memory.write_word(destination_string_address + 2, len(source_string))
    emulator.memory.write_pointer(destination_string_address + 8, source_string_address)
    return 0


def ex_allocate_pool_2(emulator: Emulator) -> int:
    number_of_bytes = emulator.register.get("rdx")
    return emulator.memory.allocate(number_of_bytes, Permission.READ_WRITE)


def ex_allocate_pool_with_tag(emulator: Emulator) -> int:
    number_of_bytes = emulator.register.get("rdx")
    return emulator.memory.allocate(number_of_bytes, Permission.READ_WRITE)


def strcpy_s(emulator: Emulator) -> int:
    source = emulator.register.get("r8")
    string = emulator.memory.read_string(source)
    destination = emulator.register.get("rcx")
    emulator.memory.write_string(destination, string)
    return 0


def io_create_device(emulator: Emulator) -> int:
    device_name_address = emulator.register.get("r8")
    device_name_buffer = emulator.memory.read_pointer(device_name_address + 8)
    device_name = emulator.memory.read_wstring(device_name_buffer)
    logger.success("Device: {}", device_name)
    return 0


def io_create_symbolic_link(emulator: Emulator) -> int:
    symbolic_link_name_address = emulator.register.get("rcx")
    symbolic_link_name_buffer = emulator.memory.read_pointer(symbolic_link_name_address + 8)
    symbolic_link_name = emulator.memory.read_wstring(symbolic_link_name_buffer)

    device_name_address = emulator.register.get("rdx")
    device_name_buffer = emulator.memory.read_pointer(device_name_address + 8)
    device_name = emulator.memory.read_wstring(device_name_buffer)

    logger.success("Symbolic Link: {} -> {}", symbolic_link_name, device_name)
    return 0


def analyze(image: Image) -> None:
    emulator = Emulator(__STACK_SIZE, __MEMORY_START, __MEMORY_END)
    emulator.add_image(image)

    emulator.add_fallback("ntoskrnl", "RtlQueryFeatureConfigurationChangeStamp", lambda _: 0)
    emulator.add_fallback("ntoskrnl", "RtlQueryFeatureConfiguration", lambda _: 0)
    emulator.add_fallback("ntoskrnl", "EtwRegister", lambda _: 0)
    emulator.add_fallback("ntoskrnl", "EtwSetInformation", lambda _: 0)
    emulator.add_fallback("ntoskrnl", "ExInitializeResourceLite", lambda _: 0)

    emulator.add_fallback("ntoskrnl", "RtlInitUnicodeStringEx", rtl_init_unicode_string_ex)
    emulator.add_fallback("ntoskrnl", "RtlInitAnsiString", rtl_init_ansi_string)
    emulator.add_fallback("ntoskrnl", "ExAllocatePool2", ex_allocate_pool_2)
    emulator.add_fallback("ntoskrnl", "ExAllocatePoolWithTag", ex_allocate_pool_with_tag)

    emulator.add_fallback("ntoskrnl", "strcpy_s", strcpy_s)

    emulator.add_fallback("ntoskrnl", "IoCreateDevice", io_create_device)
    emulator.add_fallback("ntoskrnl", "IoCreateSymbolicLink", io_create_symbolic_link)

    emulator.memory.map(__KUSER_SHARED_DATA_ADDRESS, emulator.memory.page_size, Permission.READ)

    driver_object = emulator.memory.allocate(emulator.memory.page_size, Permission.READ_WRITE)
    emulator.register.set("rcx", driver_object)

    try:
        emulator.start(emulator.get_export(image.path.stem, "DriverEntry"))

    except Exception as exception:
        logger.error(exception)
        emulator.stack_trace("ERROR")


def main(arguments: Arguments) -> None:
    logger.remove()
    logger.add(stderr, level="TRACE" if arguments.verbose else "INFO")

    image_cache = ImageCache(arguments.cache)
    drivers = get_drivers()

    for driver, driver_path in drivers.items():
        if arguments.pattern.match(driver):
            analyze(image_cache.get(driver_path))
