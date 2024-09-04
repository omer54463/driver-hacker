from typing import final


@final
class Function:
    __address: int
    __name: str
    __argument_count: int | None

    def __init__(self, address: int, name: str, argument_count: int | None) -> None:
        self.__address = address
        self.__name = name
        self.__argument_count = argument_count

    @property
    def address(self) -> int:
        return self.__address

    @property
    def name(self) -> str:
        return self.__name

    @property
    def argument_count(self) -> int | None:
        return self.__argument_count

    def __repr__(self) -> str:
        parts = (
            f"{self.__address:#x}",
            f"{self.__name!r}",
            f"{None!r}" if self.__argument_count is None else f"{self.__argument_count:#x}",
        )
        return f"{type(self).__name__}({', '.join(parts)})"

    def __str__(self) -> str:
        return repr(self)

    def __match_args__(self) -> tuple[int, str, int | None]:
        return (self.__address, self.__name, self.__argument_count)
