from collections.abc import Iterator
from functools import partial
from hashlib import md5
from itertools import count
from pathlib import Path

from driver_hacker.ida.ida import Ida


class IdaCache:
    __working_directory: Path
    __port_generator: Iterator[int]

    __FIRST_PORT = 9000
    __CHUNK_SIZE = 1 << 20

    def __init__(self, working_directory: Path) -> None:
        self.__working_directory = working_directory
        self.__port_generator = count(self.__FIRST_PORT)

    @property
    def working_directory(self) -> Path:
        return self.__working_directory

    def get(self, binary: Path) -> Ida:
        directory = self.__working_directory / self.__directory_name(binary)
        new_binary = directory / binary.name

        if not directory.exists():
            directory.mkdir(parents=True)
            new_binary.write_bytes(binary.read_bytes())

        return Ida(new_binary, next(self.__port_generator))

    @classmethod
    def __directory_name(cls, binary: Path) -> str:
        hasher = md5()

        with binary.open("rb") as file:
            read_chunk = partial(file.read, cls.__CHUNK_SIZE)

            for chunk in iter(read_chunk, b""):
                hasher.update(chunk)

        return f"{binary.name}-{hasher.hexdigest()}"
