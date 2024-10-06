from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
from re import Pattern, compile
from sys import stderr
from typing import TYPE_CHECKING, final

from loguru import logger

from driver_hacker.emulator.emulator import Emulator
from driver_hacker.emulator.memory_manager.permission import Permission
from driver_hacker.get_drivers import get_drivers
from driver_hacker.image.ida_cache import ImageCache
from driver_hacker.image.image import Image

if TYPE_CHECKING:
    from loguru import Record

__STACK_SIZE = 0x2000
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


def ex_allocate_pool(emulator: Emulator) -> int:
    number_of_bytes = emulator.register.get("rdx")
    return emulator.memory.allocate(number_of_bytes, Permission.READ_WRITE)


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


def analyze(ntoskrnl: Image, driver: Image) -> None:
    emulator = Emulator(__STACK_SIZE, __MEMORY_START, __MEMORY_END)

    emulator.add_image(ntoskrnl)
    emulator.add_image(driver)

    emulator.add_override("ntoskrnl", "EtwRegister", lambda _: 0)
    emulator.add_override("ntoskrnl", "ExInitializeResourceLite", lambda _: 0)

    emulator.add_override("ntoskrnl", "ExAllocatePool2", ex_allocate_pool)
    emulator.add_override("ntoskrnl", "ExAllocatePoolWithTag", ex_allocate_pool)

    emulator.add_override("ntoskrnl", "IoCreateDevice", io_create_device)
    emulator.add_override("ntoskrnl", "IoCreateSymbolicLink", io_create_symbolic_link)

    emulator.memory.map(__KUSER_SHARED_DATA_ADDRESS, emulator.memory.page_size, Permission.READ)

    driver_object = emulator.memory.allocate(emulator.memory.page_size, Permission.READ_WRITE)
    emulator.register.set("rcx", driver_object)

    try:
        emulator.start(emulator.get_export(driver.path.stem, "DriverEntry"))

    except Exception as exception:
        logger.error("Error: {}", exception)
        emulator.disassembly("ERROR")
        emulator.stack_trace("ERROR")


def format_function(record: "Record") -> str:
    return (
        f"<green>{record['time']:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        f"<level>{record['level']:<8}</level> | "
        f"<cyan>{__package__}</cyan> - "
        f"<level>{record['message']}</level>"
        "\n"
    ).format(record)


def main(arguments: Arguments) -> None:
    logger.remove()
    logger.add(
        stderr,
        level="TRACE" if arguments.verbose else "INFO",
        format=format_function,
    )

    image_cache = ImageCache(arguments.cache)
    drivers = get_drivers()

    ntoskrnl = image_cache.get(drivers["ntoskrnl"])

    for driver, driver_path in drivers.items():
        if driver != "ntoskrnl" and arguments.pattern.match(driver):
            analyze(ntoskrnl, image_cache.get(driver_path))
