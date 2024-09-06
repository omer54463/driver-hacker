import ctypes
import ctypes.wintypes
from collections.abc import Generator, Sequence
from enum import IntEnum
from os import getenv
from pathlib import Path
from re import IGNORECASE, compile
from typing import final

__SYSTEM_MODULE_INFORMATION = 11

__FULL_PATH_NAME_ENCODING = "ansi"

__GLOBAL_NAMESPACE_PREFIX = "\\??\\"

__SYSTEM_ROOT_ENVIRONMENT_VARIABLE = "systemroot"
__SYSTEM_ROOT_PREFIX = Path("\\systemroot")

__GHOST_DUMP_DRIVE_NAME_PATTERN = compile(r"^dump_.*\.sys$", IGNORECASE)


@final
class _NtStatus(IntEnum):
    SUCCESS = 0x00000000
    INFO_LENGTH_MISMATCH = 0xC0000004


@final
class _RtlProcessModules(ctypes.Structure):
    number_of_modules: int
    padding: int

    _pack_ = 1
    _fields_ = (
        ("number_of_modules", ctypes.wintypes.ULONG),
        ("padding", ctypes.wintypes.ULONG),
    )


@final
class _RtlProcessModuleInformation(ctypes.Structure):
    section: int
    mapped_base: int
    image_base: int
    image_size: int
    flags: int
    load_order_index: int
    init_order_index: int
    load_count: int
    offset_to_file_name: int
    full_path_name: bytes

    FULL_PATH_NAME_LENGTH = 256

    _pack_ = 1
    _fields_ = (
        ("section", ctypes.wintypes.HANDLE),
        ("mapped_base", ctypes.wintypes.LPVOID),
        ("image_base", ctypes.wintypes.LPVOID),
        ("image_size", ctypes.wintypes.ULONG),
        ("flags", ctypes.wintypes.ULONG),
        ("load_order_index", ctypes.wintypes.USHORT),
        ("init_order_index", ctypes.wintypes.USHORT),
        ("load_count", ctypes.wintypes.USHORT),
        ("offset_to_file_name", ctypes.wintypes.USHORT),
        ("full_path_name", ctypes.wintypes.CHAR * FULL_PATH_NAME_LENGTH),
    )


def __get_system_module_information_buffer() -> ctypes.Array[ctypes.wintypes.CHAR]:
    nt_query_system_information = ctypes.WinDLL("ntdll").NtQuerySystemInformation
    nt_query_system_information.argtypes = (
        ctypes.wintypes.ULONG,
        ctypes.wintypes.LPVOID,
        ctypes.wintypes.ULONG,
        ctypes.wintypes.PULONG,
    )
    nt_query_system_information.restype = ctypes.wintypes.ULONG

    buffer_size = ctypes.wintypes.ULONG(0)
    buffer = ctypes.create_string_buffer(buffer_size.value)

    while True:
        status = nt_query_system_information(
            __SYSTEM_MODULE_INFORMATION,
            buffer,
            buffer_size,
            ctypes.byref(buffer_size),
        )

        match status:
            case _NtStatus.SUCCESS:
                break

            case _NtStatus.INFO_LENGTH_MISMATCH:
                buffer = ctypes.create_string_buffer(buffer_size.value)

            case status:
                raise ctypes.WinError(status)

    return buffer


def __parse_system_module_information_buffer(
    buffer: ctypes.Array[ctypes.wintypes.CHAR],
) -> Sequence[_RtlProcessModuleInformation]:
    modules = _RtlProcessModules.from_buffer(buffer)
    array_type = _RtlProcessModuleInformation * modules.number_of_modules
    return tuple(array_type.from_buffer(buffer, ctypes.sizeof(_RtlProcessModules)))


def __get_system_root() -> Path:
    if (system_root := getenv(__SYSTEM_ROOT_ENVIRONMENT_VARIABLE)) is not None:
        return Path(system_root)

    message = f"`{__SYSTEM_ROOT_ENVIRONMENT_VARIABLE}` environment variable does not exist"
    raise RuntimeError(message)


def __decode_full_path_name(system_root: Path, data: bytes) -> Path | None:
    string = data.decode(__FULL_PATH_NAME_ENCODING).lower()

    if string.startswith(__GLOBAL_NAMESPACE_PREFIX):
        string = string.removeprefix(__GLOBAL_NAMESPACE_PREFIX)

    path = Path(string)

    if path.is_relative_to(__SYSTEM_ROOT_PREFIX):
        path = system_root / path.relative_to(__SYSTEM_ROOT_PREFIX)

    if not path.exists():
        if __GHOST_DUMP_DRIVE_NAME_PATTERN.match(path.name):
            return None

        message = f"Module `{path}` cannot be found"
        raise FileNotFoundError(message)

    return path


def get_system_modules() -> Generator[Path]:
    buffer = __get_system_module_information_buffer()
    system_root = __get_system_root()

    for module in __parse_system_module_information_buffer(buffer):
        if (path := __decode_full_path_name(system_root, module.full_path_name)) is not None:
            yield path
