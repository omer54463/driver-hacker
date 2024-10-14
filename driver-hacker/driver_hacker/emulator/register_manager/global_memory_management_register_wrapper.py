from typing import final

import unicorn  # type: ignore[import-untyped]


@final
class GlobalMemoryManagementRegisterWrapper:
    __uc: unicorn.Uc
    __id: int

    def __init__(self, uc: unicorn.Uc, id: int) -> None:
        self.__uc = uc
        self.__id = id

    @property
    def base(self) -> int:
        return self.__get_value()[0]

    @base.setter
    def base(self, base: int) -> None:
        self.__set_value((base, self.limit))

    @property
    def limit(self) -> int:
        return self.__get_value()[1]

    @limit.setter
    def limit(self, limit: int) -> None:
        self.__set_value((self.base, limit))

    def __get_value(self) -> tuple[int, int]:
        value: tuple[int, int, int, int] = self.__uc.reg_read(self.__id)
        return value[1:3]

    def __set_value(self, value: tuple[int, int]) -> None:
        self.__uc.reg_write(self.__id, (0, *value, 0))
