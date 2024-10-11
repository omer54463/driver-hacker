from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
from re import Pattern, compile
from sys import stderr
from typing import TYPE_CHECKING, final

import unicorn  # type: ignore[import-untyped]
from loguru import logger

from driver_hacker import native
from driver_hacker.emulator.emulator import Emulator
from driver_hacker.emulator.memory_manager.permission import Permission
from driver_hacker.image.image import Image
from driver_hacker.image.image_cache import ImageCache

if TYPE_CHECKING:
    from loguru import Record

__STACK_SIZE = 0x2000
__MEMORY_START = 0xFFFF000000000000
__MEMORY_END = 0xFFFFFFFFFFFFFFFF


@final
@dataclass(frozen=True)
class _Arguments:
    pattern: Pattern[str]
    cache: Path
    verbose: bool


def __parse_arguments() -> _Arguments:
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
    return _Arguments(**vars(argument_parser.parse_args()))


def __format_function(record: "Record") -> str:
    if record["name"] is None:
        message = "Record is missing the `name` field"
        raise ValueError(message)

    return (
        f"<green>{record['time']:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        f"<level>{record['level']:<8}</level> | "
        f"<cyan>{record['name'].split('.')[0]}</cyan> - "
        f"<level>{record['message']}</level>"
        "\n{exception}"
    )


def __setup_logger(*, verbose: bool = False) -> None:
    logger.remove()
    logger.add(stderr, level="TRACE" if verbose else "INFO", format=__format_function)


def __ex_allocate_pool(emulator: Emulator) -> int:
    number_of_bytes = emulator.register.get("rdx")
    return emulator.memory.allocate(number_of_bytes, Permission.READ_WRITE)


def __io_create_device(emulator: Emulator) -> int:
    device_name_address = emulator.register.get("r8")
    device_name_buffer = emulator.memory.read_pointer(device_name_address + 8)
    device_name = emulator.memory.read_wstring(device_name_buffer)

    logger.success("Device: {}", device_name)
    return 0


def __io_create_symbolic_link(emulator: Emulator) -> int:
    symbolic_link_name_address = emulator.register.get("rcx")
    symbolic_link_name_buffer = emulator.memory.read_pointer(symbolic_link_name_address + 8)
    symbolic_link_name = emulator.memory.read_wstring(symbolic_link_name_buffer)

    device_name_address = emulator.register.get("rdx")
    device_name_buffer = emulator.memory.read_pointer(device_name_address + 8)
    device_name = emulator.memory.read_wstring(device_name_buffer)

    logger.success("Symbolic Link: {} -> {}", symbolic_link_name, device_name)
    return 0


def __analyze(kuser_shared_data: bytes, ntoskrnl: Image, driver: Image) -> None:
    emulator = Emulator(kuser_shared_data, __STACK_SIZE, __MEMORY_START, __MEMORY_END)

    emulator.add_image(ntoskrnl)
    emulator.add_image(driver)

    emulator.add_override("ntoskrnl", "EtwRegister", lambda _: 0)
    emulator.add_override("ntoskrnl", "ExInitializeResourceLite", lambda _: 0)

    emulator.add_override("ntoskrnl", "ExAllocatePool2", __ex_allocate_pool)
    emulator.add_override("ntoskrnl", "ExAllocatePoolWithTag", __ex_allocate_pool)

    emulator.add_override("ntoskrnl", "IoCreateDevice", __io_create_device)
    emulator.add_override("ntoskrnl", "IoCreateSymbolicLink", __io_create_symbolic_link)

    driver_object = emulator.memory.allocate(emulator.memory.page_size, Permission.READ_WRITE)
    emulator.register.set("rcx", driver_object)

    try:
        emulator.start(emulator.get_export(driver.path.stem, "DriverEntry"))

    except unicorn.UcError as error:
        logger.error("Error: {}", error)
        emulator.disassembly("ERROR")
        emulator.stack_trace("ERROR")


@logger.catch
def main() -> None:
    arguments = __parse_arguments()
    __setup_logger(verbose=arguments.verbose)

    kuser_shared_data = native.get_kuser_shared_data()
    drivers = native.get_drivers()

    image_cache = ImageCache(arguments.cache)
    ntoskrnl = image_cache.get(drivers["ntoskrnl"])
    for driver, driver_path in drivers.items():
        if driver != "ntoskrnl" and arguments.pattern.match(driver):
            __analyze(kuser_shared_data, ntoskrnl, image_cache.get(driver_path))
