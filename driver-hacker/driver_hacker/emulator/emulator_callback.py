from collections.abc import Callable
from typing import TYPE_CHECKING, TypeAlias

from driver_hacker.emulator.emulator_callback_result import EmulatorCallbackResult

if TYPE_CHECKING:
    from driver_hacker.emulator.emulator import Emulator

EmulatorCallback: TypeAlias = Callable[["Emulator"], EmulatorCallbackResult]
