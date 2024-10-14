from typing import final

import unicorn  # type: ignore[import-untyped]


@final
class FloatingPointRegisterWrapper:
    __uc: unicorn.Uc
    __id: int

    def __init__(self, uc: unicorn.Uc, id: int) -> None:
        self.__uc = uc
        self.__id = id

    @property
    def mantissa(self) -> int:
        return self.__get_value()[0]

    @mantissa.setter
    def mantissa(self, mantissa: int) -> None:
        self.__set_value((mantissa, self.exponent))

    @property
    def exponent(self) -> int:
        return self.__get_value()[1]

    @exponent.setter
    def exponent(self, exponent: int) -> None:
        self.__set_value((self.mantissa, exponent))

    def __get_value(self) -> tuple[int, int]:
        value: tuple[int, int] = self.__uc.reg_read(self.__id)
        return value

    def __set_value(self, value: tuple[int, int]) -> None:
        self.__uc.reg_write(self.__id, value)
