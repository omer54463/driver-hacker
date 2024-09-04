from collections.abc import Iterable, Iterator, Sequence
from typing import final, overload


@final
class Instruction:
    __previous_address: int | None
    __address: int
    __following_address: int | None
    __mnemonic: str
    __operands: tuple[int | str, ...]

    def __init__(
        self,
        previous_address: int | None,
        address: int,
        following_address: int | None,
        mnemonic: str,
        operands: Iterable[int | str],
    ) -> None:
        self.__previous_address = previous_address
        self.__address = address
        self.__following_address = following_address
        self.__mnemonic = mnemonic
        self.__operands = tuple(operands)

    @property
    def previous_address(self) -> int | None:
        return self.__previous_address

    @property
    def address(self) -> int:
        return self.__address

    @property
    def following_address(self) -> int | None:
        return self.__following_address

    @property
    def mnemonic(self) -> str:
        return self.__mnemonic

    @property
    def operand_count(self) -> int:
        return len(self.__operands)

    @property
    def operands(self) -> Sequence[int | str]:
        return self.__operands

    @overload
    def get_operand(self, index: int) -> int | str: ...

    @overload
    def get_operand(self, index: int, operand_type: type[int]) -> int: ...

    @overload
    def get_operand(self, index: int, operand_type: type[str]) -> str: ...

    def get_operand(
        self, index: int, operand_type: type[str] | type[int] | None = None
    ) -> int | str:
        operand = self.__operands[index]

        if operand_type is None or isinstance(operand, operand_type):
            return operand

        message = f"Expected operand type `{type}`, got `{type(operand)}`"
        raise TypeError(message)

    def __len__(self) -> int:
        return len(self.__operands)

    def __contains__(self, operand: int | str) -> bool:
        return operand in self.__operands

    def __iter__(self) -> Iterator[int | str]:
        return iter(self.__operands)

    def __repr__(self) -> str:
        operand_parts = []

        for operand in self.__operands:
            match operand:
                case str():
                    operand_parts.append(f"{operand!r}")

                case int():
                    operand_parts.append(f"{operand:#x}")

        operands_part = f"[{', '.join(operand_parts)}]"

        parts = (
            f"{None!r}" if self.__previous_address is None else f"{self.__previous_address:#x}",
            f"{self.__address:#x}",
            f"{None!r}" if self.__following_address is None else f"{self.__following_address:#x}",
            f"{self.__mnemonic!r}",
            operands_part,
        )
        return f"{type(self).__name__}({', '.join(parts)})"

    def __str__(self) -> str:
        return repr(self)

    def __match_args__(self) -> tuple[int | str, ...]:
        return (self.__mnemonic, *self.__operands)
