from typing import Self, final

from driver_hacker.emulator.emulator import Emulator
from driver_hacker.emulator.emulator_callback import EmulatorCallback
from driver_hacker.image.image import Image


@final
class EmulatorBuilder:
    __stack_size: int
    __memory_start: int
    __memory_end: int
    __kuser_shared_data: bytes

    __images: list[Image]
    __import_fallbacks: dict[tuple[Image, str | int], EmulatorCallback]
    __default_import_fallback: EmulatorCallback | None
    __function_callbacks: dict[tuple[Image, str | int], EmulatorCallback]

    DEFAULT_STACK_SIZE = 0x2000
    DEFAULT_MEMORY_START = 0xFFFF000000000000
    DEFAULT_MEMORY_END = 0xFFFFFFFFFFFFFFFF
    DEFUALT_KUSER_SHARED_DATA = bytes(0x1000)

    def __init__(self) -> None:
        self.__stack_size = self.DEFAULT_STACK_SIZE
        self.__memory_start = self.DEFAULT_MEMORY_START
        self.__memory_end = self.DEFAULT_MEMORY_END
        self.__kuser_shared_data = self.DEFUALT_KUSER_SHARED_DATA

        self.__images = []
        self.__import_fallbacks = {}
        self.__default_import_fallback = None
        self.__function_callbacks = {}

    def set_stack_size(self, size: int) -> Self:
        self.__stack_size = size
        return self

    def set_memory_range(self, start: int, end: int) -> Self:
        self.__memory_start = start
        self.__memory_end = end
        return self

    def set_kuser_shared_data(self, kuser_shared_data: bytes) -> Self:
        self.__kuser_shared_data = kuser_shared_data
        return self

    def add_image(self, image: Image) -> Self:
        self.__images.append(image)
        return self

    def add_import_fallback(self, image: Image, identifier: str | int, import_fallback: EmulatorCallback) -> Self:
        self.__import_fallbacks[(image, identifier)] = import_fallback
        return self

    def set_default_import_fallback(self, default_import_fallback: EmulatorCallback) -> Self:
        self.__default_import_fallback = default_import_fallback
        return self

    def add_function_callback(
        self,
        image: Image,
        function_identifier: str | int,
        function_callback: EmulatorCallback,
    ) -> Self:
        self.__function_callbacks[(image, function_identifier)] = function_callback
        return self

    def build(self) -> Emulator:
        return Emulator(
            self.__stack_size,
            self.__memory_start,
            self.__memory_end,
            self.__kuser_shared_data,
            self.__images,
            self.__import_fallbacks,
            self.__default_import_fallback,
            self.__function_callbacks,
        )
