import unicorn  # type: ignore[import-untyped]
from loguru import logger


class RegisterManager:
    __uc: unicorn.Uc

    def __init__(self, uc: unicorn.Uc) -> None:
        self.__uc = uc

    def get(self, name: str) -> int:
        logger.trace("get(name={!r})", name)

        value = self.__uc.reg_read(self.__register(name))

        if not isinstance(value, int):
            message = f"Unexpected register value type `{type(value).__name__}`"
            raise TypeError(message)

        logger.trace("get(...) -> {:#x}", value)
        return value

    def set(self, name: str, value: int) -> None:
        logger.trace("set(name={!r}, value={:#x})", name, value)

        self.__uc.reg_write(self.__register(name), value)

    def __register(self, name: str) -> int:
        register = getattr(unicorn.x86_const, f"UC_X86_REG_{name.upper()}", None)

        if register is None:
            message = f"Invalid register name `{name}`"
            raise ValueError(message)

        if not isinstance(register, int):
            message = f"Unexpected register type `{type(register).__name__}`"
            raise TypeError(message)

        return register
