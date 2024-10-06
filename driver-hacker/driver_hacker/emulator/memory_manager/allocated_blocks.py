from typing import final

from driver_hacker.emulator.memory_manager.permission import Permission


@final
class AllocatedBlock:
    __start: int
    __end: int
    __permissions: Permission

    def __init__(self, start: int, end: int, permissions: Permission) -> None:
        self.__start = start
        self.__end = end
        self.__permissions = permissions

    @property
    def start(self) -> int:
        return self.__start

    @property
    def end(self) -> int:
        return self.__end

    @property
    def size(self) -> int:
        return self.__end - self.__start

    @property
    def permissions(self) -> Permission:
        return self.__permissions

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.__start:#x}, {self.__end:#x}, {self.__permissions})"
