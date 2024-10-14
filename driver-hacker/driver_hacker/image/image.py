from functools import cache
from pathlib import Path
from shutil import which
from subprocess import DEVNULL, Popen
from time import sleep
from types import MappingProxyType, TracebackType
from typing import Any, Literal, Self, final

import rpyc  # type: ignore[import-untyped]
from loguru import logger


@final
class Image:
    __binary: Path | None
    __database: Path
    __port: int
    __process: Popen[bytes]
    __connection: rpyc.Connection

    __DEFAULT_PORT = 9000
    __DATABASE_SUFFIX = ".i64"
    __SERVER = Path(__file__).parent / "image_server.py"
    __IDAT = Path("C:\\Program Files\\IDA Professional 9.0\\idat64.exe")

    __MODULE_NAMES = MappingProxyType(
        {
            "utils": "idautils",
            "i64": "ida_64",
            "allins": "ida_allins",
            "auto": "ida_auto",
            "bitrange": "ida_bitrange",
            "bytes": "ida_bytes",
            "dbg": "ida_dbg",
            "dirtree": "ida_dirtree",
            "diskio": "ida_diskio",
            "entry": "ida_entry",
            "expr": "ida_expr",
            "fixup": "ida_fixup",
            "fpro": "ida_fpro",
            "frame": "ida_frame",
            "funcs": "ida_funcs",
            "gdl": "ida_gdl",
            "graph": "ida_graph",
            "hexrays": "ida_hexrays",
            "ida": "ida_ida",
            "api": "ida_idaapi",
            "idc": "ida_idc",
            "idd": "ida_idd",
            "idp": "ida_idp",
            "ieee": "ida_ieee",
            "kernwin": "ida_kernwin",
            "lines": "ida_lines",
            "loader": "ida_loader",
            "merge": "ida_merge",
            "mergemod": "ida_mergemod",
            "moves": "ida_moves",
            "nalt": "ida_nalt",
            "name": "ida_name",
            "netnode": "ida_netnode",
            "offset": "ida_offset",
            "pro": "ida_pro",
            "problems": "ida_problems",
            "range": "ida_range",
            "regfinder": "ida_regfinder",
            "registry": "ida_registry",
            "search": "ida_search",
            "segment": "ida_segment",
            "segregs": "ida_segregs",
            "srclang": "ida_srclang",
            "strlist": "ida_strlist",
            "tryblks": "ida_tryblks",
            "typeinf": "ida_typeinf",
            "ua": "ida_ua",
            "xref": "ida_xref",
        }
    )

    def __init__(self, path: Path, port: int = __DEFAULT_PORT) -> None:
        logger.info(f"Launching IDA on `{path.stem}` with via port {port}")

        if path.suffix == self.__DATABASE_SUFFIX:
            self.__binary = None
            self.__database = path

        else:
            self.__binary = path
            self.__database = path.with_suffix(self.__DATABASE_SUFFIX)

        self.__port = port

        self.__process = self.__create_process()

        try:
            self.__connection = self.__create_connection()

        except:
            self.__process.terminate()
            self.__process.wait()
            raise

    @property
    def path(self) -> Path:
        if self.__binary is not None:
            return self.__binary

        return self.__database

    @property
    def binary(self) -> Path:
        if self.__binary is not None:
            return self.__binary

        message = "Binary was not provided"
        raise RuntimeError(message)

    @property
    def database(self) -> Path:
        return self.__database

    @property
    def port(self) -> int:
        return self.__port

    @property
    def process(self) -> Popen[bytes]:
        return self.__process

    @property
    def connection(self) -> rpyc.Connection:
        return self.__connection

    def close(self) -> None:
        self.__connection.close()
        self.__process.wait()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.__connection.modules, self.__MODULE_NAMES[name])

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        type: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        self.close()
        return False

    def __create_process(self) -> Popen[bytes]:
        escaped_idat = self.__escape(self.__get_idat())
        escaped_database = self.__escape(self.__database)
        escaped_server = self.__escape(self.__SERVER)
        escaped_server_path_and_port = self.__escape(f"{escaped_server} {self.__port}")
        escaped_binary = None if self.__binary is None else self.__escape(self.__binary)

        command = (escaped_idat, "-A", f"-S{escaped_server_path_and_port}", "-P+") + (
            (escaped_database,)
            if escaped_binary is None or self.__database.exists()
            else (f"-O{escaped_database}", escaped_binary)
        )

        return Popen(" ".join(command), stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL)

    def __create_connection(self) -> rpyc.Connection:
        while True:
            try:
                return rpyc.classic.connect("localhost", self.__port)

            except ConnectionRefusedError:
                sleep(0.1)

    @staticmethod
    def __escape(value: str | Path) -> str:
        string = str(value)

        if " " in string:
            string = string.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{string}"'

        return string

    @classmethod
    @cache
    def __get_idat(cls) -> Path:
        if (which_result := which(cls.__IDAT.name)) is not None:
            return Path(which_result)

        if cls.__IDAT.exists():
            return cls.__IDAT

        message = f"`{cls.__IDAT.name}` could not be found"
        raise FileNotFoundError(message)
