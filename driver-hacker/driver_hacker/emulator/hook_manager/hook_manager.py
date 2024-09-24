from collections.abc import Callable
from functools import wraps
from typing import Any, ParamSpec, TypeVar

import unicorn  # type: ignore[import-untyped]

from driver_hacker.emulator.hook_manager.hook import Hook
from driver_hacker.emulator.hook_manager.hook_type import HookType
from driver_hacker.emulator.hook_manager.invalid_memory_hook_type import InvalidMemoryHookType
from driver_hacker.emulator.hook_manager.memory_hook_type import MemoryHookType

C = TypeVar("C")
P = ParamSpec("P")
R = TypeVar("R")


class HookManager:
    __uc: unicorn.Uc

    __DEFAULT_START = 1
    __DEFAULT_END = 0

    def __init__(self, uc: unicorn.Uc) -> None:
        self.__uc = uc

    def add(
        self,
        hook_type: HookType | MemoryHookType | InvalidMemoryHookType,
        callback: Callable[..., R],
        user_data: Any | None = None,
        start: int = __DEFAULT_START,
        end: int = __DEFAULT_END,
    ) -> Hook:
        @wraps(callback)
        def __callback(_: unicorn.Uc, /, *args: P.args, **kwargs: P.kwargs) -> R:
            return callback(*args, **kwargs)

        return Hook(self.__uc.hook_add(hook_type.to_uc(), __callback, user_data, begin=start, end=end))

    def remove(self, hook: Hook) -> None:
        self.__uc.hook_del(hook)
