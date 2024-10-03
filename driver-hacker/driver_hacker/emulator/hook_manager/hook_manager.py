from collections.abc import Callable
from functools import wraps
from typing import Any, ParamSpec, TypeVar, final

import unicorn  # type: ignore[import-untyped]
from loguru import logger

from driver_hacker.emulator.hook_manager.hook import Hook
from driver_hacker.emulator.hook_manager.hook_type import HookType

P = ParamSpec("P")
R = TypeVar("R")


@final
class HookManager:
    __uc: unicorn.Uc

    __DEFAULT_START = 1
    __DEFAULT_END = 0

    def __init__(self, uc: unicorn.Uc) -> None:
        self.__uc = uc

    def add(
        self,
        hook_type: HookType,
        callback: Callable[..., R],
        user_data: Any | None = None,
        start: int = __DEFAULT_START,
        end: int = __DEFAULT_END,
    ) -> Hook:
        logger.trace(
            "add(hook_type={}, callback={}, user_data={}, start={:#x}, end={:#x})",
            hook_type,
            callback,
            user_data,
            start,
            end,
        )

        @wraps(callback)
        def __callback(_: unicorn.Uc, /, *args: P.args, **kwargs: P.kwargs) -> R:
            return callback(*args, **kwargs)

        hook = Hook(self.__uc.hook_add(hook_type.to_uc(), __callback, user_data, begin=start, end=end))
        logger.trace("add(...) -> {:#x}", hook)
        return hook

    def remove(self, hook: Hook) -> None:
        self.__uc.hook_del(hook)
