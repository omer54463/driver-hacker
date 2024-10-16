from typing import Self, final

from driver_hacker.emulator.emulator import Emulator
from driver_hacker.emulator.emulator_callback import EmulatorCallback
from driver_hacker.emulator.emulator_factory import EmulatorFactory
from driver_hacker.image.image import Image


@final
class EmulatorBuilder:
    __kuser_shared_data: bytes | None

    __images: set[Image]
    __import_fallbacks: dict[tuple[str, str | int], EmulatorCallback]
    __default_import_fallback: EmulatorCallback | None
    __function_callbacks: dict[tuple[str, str | int], EmulatorCallback]

    def __init__(self) -> None:
        self.__kuser_shared_data = None

        self.__images = set()
        self.__import_fallbacks = {}
        self.__default_import_fallback = None
        self.__function_callbacks = {}

    def set_kuser_shared_data(self, kuser_shared_data: bytes) -> Self:
        self.__kuser_shared_data = kuser_shared_data
        return self

    def add_image(self, image: Image) -> Self:
        self.__images.add(image)
        return self

    def add_import_fallback(self, image_name: str, identifier: str | int, import_fallback: EmulatorCallback) -> Self:
        self.__import_fallbacks[(image_name, identifier)] = import_fallback
        return self

    def set_default_import_fallback(self, default_import_fallback: EmulatorCallback) -> Self:
        self.__default_import_fallback = default_import_fallback
        return self

    def add_function_callback(
        self,
        image_name: str,
        function_identifier: str | int,
        function_callback: EmulatorCallback,
    ) -> Self:
        self.__function_callbacks[(image_name, function_identifier)] = function_callback
        return self

    def build(self) -> Emulator:
        return EmulatorFactory().create(
            self.__images,
            self.__kuser_shared_data,
            self.__import_fallbacks,
            self.__default_import_fallback,
            self.__function_callbacks,
        )
