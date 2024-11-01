from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
from re import Pattern, compile
from sys import stderr
from typing import TYPE_CHECKING, final

import unicorn
from loguru import logger

from driver_hacker import native
from driver_hacker.emulator.emulator import Emulator
from driver_hacker.emulator.emulator_builder import EmulatorBuilder
from driver_hacker.emulator.emulator_callback_result import EmulatorCallbackResult
from driver_hacker.emulator.memory_manager.permission import Permission
from driver_hacker.image.image import Image
from driver_hacker.image.image_cache import ImageCache

if TYPE_CHECKING:
    from loguru import Record


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
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level:<8}</level> | "
        f"<cyan>{record['name'].split('.')[0]}</cyan> - "
        "<level>{message}</level>"
        "\n{exception}"
    )


def __setup_logger(*, verbose: bool = False) -> None:
    logger.remove()
    logger.add(stderr, level="TRACE" if verbose else "INFO", format=__format_function)


def __return_zero(emulator: Emulator) -> EmulatorCallbackResult:
    emulator.register.rax = 0
    return EmulatorCallbackResult.RETURN


def __allocate(emulator: Emulator) -> EmulatorCallbackResult:
    emulator.register.rax = emulator.memory.allocate(emulator.register.rdx, Permission.READ_WRITE)
    return EmulatorCallbackResult.RETURN


def __io_create_device(emulator: Emulator) -> EmulatorCallbackResult:
    device_name_address = emulator.register.r8
    device_name_buffer = emulator.memory.read_pointer(device_name_address + 8)
    device_name = emulator.memory.read_wstring(device_name_buffer)

    logger.success("Device: {}", device_name)

    emulator.register.rax = 0
    return EmulatorCallbackResult.RETURN


def __io_create_symbolic_link(emulator: Emulator) -> EmulatorCallbackResult:
    symbolic_link_name_address = emulator.register.rcx
    symbolic_link_name_buffer = emulator.memory.read_pointer(symbolic_link_name_address + 8)
    symbolic_link_name = emulator.memory.read_wstring(symbolic_link_name_buffer)

    device_name_address = emulator.register.rdx
    device_name_buffer = emulator.memory.read_pointer(device_name_address + 8)
    device_name = emulator.memory.read_wstring(device_name_buffer)

    logger.success("Symbolic Link: {} -> {}", symbolic_link_name, device_name)

    emulator.register.rax = 0
    return EmulatorCallbackResult.RETURN


def __analyze(kuser_shared_data: bytes, ntoskrnl: Image, driver: Image) -> None:
    emulator = (
        EmulatorBuilder()
        .set_kuser_shared_data(kuser_shared_data)
        .add_image(ntoskrnl)
        .add_image(driver)
        .add_function_callback("ntoskrnl", "EtwRegister", __return_zero)
        .add_function_callback("ntoskrnl", "ExInitializeResourceLite", __return_zero)
        .add_function_callback("ntoskrnl", "IoRegisterShutdownNotification", __return_zero)
        .add_function_callback("ntoskrnl", "ExAllocatePoolWithTag", __allocate)
        .add_function_callback("ntoskrnl", "ExAllocatePool2", __allocate)
        .add_function_callback("ntoskrnl", "IoCreateDevice", __io_create_device)
        .add_function_callback("ntoskrnl", "IoCreateSymbolicLink", __io_create_symbolic_link)
        .build()
    )

    driver_object = emulator.memory.allocate(emulator.memory.page_size, Permission.READ_WRITE)
    emulator.register.rcx = driver_object

    kthread_size = emulator.memory.page_size * 0x10
    kthread_address = emulator.memory.allocate(kthread_size)
    kpcr_size = emulator.memory.page_size * 0x10
    kpcr_address = emulator.memory.allocate(kpcr_size)
    kprcb_address = kpcr_address + 0x180
    emulator.memory.write_pointer(kpcr_address + 0x20, kprcb_address)
    emulator.memory.write_pointer(kprcb_address + 0x8, kthread_address)
    emulator.register.gs_base = kpcr_address

    try:
        driver_entry = emulator.resolve(driver.stem, "DriverEntry")
        emulator.start(driver_entry, single_step=True)

    except unicorn.UcError as uc_error:
        logger.error("Unicorn error: {}", uc_error)
        emulator.disassembly(level="ERROR")
        emulator.stack_trace(level="ERROR")


@logger.catch
def main() -> None:
    arguments = __parse_arguments()
    __setup_logger(verbose=arguments.verbose)

    kuser_shared_data = native.get_kuser_shared_data()
    drivers = native.get_drivers()

    image_cache = ImageCache(arguments.cache)
    with image_cache.get(drivers["ntoskrnl"]) as ntoskrnl:
        for driver_name, driver_path in drivers.items():
            if driver_name == "ntoskrnl" or not arguments.pattern.match(driver_name):
                continue

            with image_cache.get(driver_path) as driver:
                __analyze(kuser_shared_data, ntoskrnl, driver)
