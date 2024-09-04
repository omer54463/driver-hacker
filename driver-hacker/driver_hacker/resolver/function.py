from collections.abc import Iterable, Iterator, Sequence


class Function:
    __address: int
    __name: str
    __arguments: tuple[str, ...]

    def __init__(self, address: int, name: str, arguments: Iterable[str]) -> None:
        self.__address = address
        self.__name = name
        self.__arguments = tuple(arguments)

    @property
    def address(self) -> int:
        return self.__address

    @property
    def name(self) -> str:
        return self.__name

    @property
    def argument_count(self) -> int:
        return len(self.__arguments)

    @property
    def arguments(self) -> Sequence[str]:
        return self.__arguments

    def get_argument(self, index: int) -> str:
        return self.__arguments[index]

    def __len__(self) -> int:
        return len(self.__arguments)

    def __contains__(self, argument: str) -> bool:
        return argument in self.__arguments

    def __iter__(self) -> Iterator[str]:
        return iter(self.__arguments)

    def __repr__(self) -> str:
        parts = (f"{self.__address:#x}", f"{self.__name!r}", f"{self.__arguments!r}")
        return f"{type(self).__name__}({', '.join(parts)})"

    def __str__(self) -> str:
        return repr(self)

    def __match_args__(self) -> tuple[int, str, Sequence[str]]:
        return (self.__address, self.__name, self.__arguments)
