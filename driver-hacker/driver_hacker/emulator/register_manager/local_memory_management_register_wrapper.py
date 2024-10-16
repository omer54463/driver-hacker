from typing import final

import unicorn


@final
class LocalMemoryManagementRegisterWrapper:
    __uc: unicorn.Uc
    __id: int

    def __init__(self, uc: unicorn.Uc, id: int) -> None:
        self.__uc = uc
        self.__id = id

    @property
    def selector(self) -> int:
        return self.__get_value()[0]

    @selector.setter
    def selector(self, selector: int) -> None:
        self.__set_value((selector, self.base, self.limit, self.flags))

    @property
    def base(self) -> int:
        return self.__get_value()[1]

    @base.setter
    def base(self, base: int) -> None:
        self.__set_value((self.selector, base, self.limit, self.flags))

    @property
    def limit(self) -> int:
        return self.__get_value()[1]

    @limit.setter
    def limit(self, limit: int) -> None:
        self.__set_value((self.selector, self.base, limit, self.flags))

    @property
    def flags(self) -> int:
        return self.__get_value()[1]

    @flags.setter
    def flags(self, flags: int) -> None:
        self.__set_value((self.selector, self.base, self.limit, flags))

    def __get_value(self) -> tuple[int, int, int, int]:
        value: tuple[int, int, int, int] = self.__uc.reg_read(self.__id)
        return value

    def __set_value(self, value: tuple[int, int, int, int]) -> None:
        self.__uc.reg_write(self.__id, value)
