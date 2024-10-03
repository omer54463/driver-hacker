from typing import final


@final
class FreeBlock:
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

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.__start:#x}, {self.__end:#x})"
