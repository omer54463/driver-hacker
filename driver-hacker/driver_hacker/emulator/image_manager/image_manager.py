from collections.abc import Set as AbstractSet
from typing import assert_never, final

from driver_hacker.image.image import Image


@final
class ImageManager:
    __images: dict[str, Image]

    def __init__(self, images: AbstractSet[Image]) -> None:
        self.__images = {image.stem: image for image in images}

    def get(self, image_name: str) -> Image:
        try:
            return self.__images[image_name]

        except KeyError as key_error:
            message = f"Image `{image_name}` does not exist"
            raise ValueError(message) from key_error

    def get_at(self, image_address: int) -> Image:
        for image in self.__images.values():
            if image.segment.getseg(image_address) is not None:
                return image

        message = f"Address {image_address:#x} is not in any image"
        raise ValueError(message)

    def resolve(self, image_name: str, symbol_identifier: str | int) -> int:
        image = self.get(image_name)

        match symbol_identifier:
            case str() as symbol_name:
                address: int = image.name.get_name_ea(image.api.BADADDR, symbol_name)
                if address == image.api.BADADDR:
                    for index in range(image.entry.get_entry_qty()):
                        export_ordinal: int = image.entry.get_entry_ordinal(index)
                        export_name: str = image.entry.get_entry_name(export_ordinal)
                        if export_name == symbol_name:
                            address = image.entry.get_entry(export_ordinal)

            case int() as export_ordinal:
                address = image.entry.get_entry(export_ordinal)

            case never:
                assert_never(never)

        if address == image.api.BADADDR:
            message = f"Symbol `{symbol_name}` of image `{image_name}` does not exist"
            raise ValueError(message)

        return address
