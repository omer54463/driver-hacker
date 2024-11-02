from typing import TYPE_CHECKING, final

from driver_hacker.emulator.image_manager.image_manager import ImageManager

if TYPE_CHECKING:
    from ida_typeinf import tinfo_t, udm_t  # type: ignore[import-not-found]


@final
class StructManager:
    __img: ImageManager

    def __init__(self, img: ImageManager) -> None:
        self.__img = img

    def size(self, value: str) -> int:
        type_info, _ = self.__resolve_value(value)
        member_size: int = type_info.get_size()
        return member_size

    def offset(self, value: str) -> int:
        _, offset = self.__resolve_value(value)
        return offset

    def __resolve_value(self, value: str) -> tuple["tinfo_t", int]:
        image_name, value = value.split("!")
        struct_name, *member_names = value.split(".")

        type_info = self.__get_type_info(image_name, struct_name)
        member_info = None
        offset = 0
        for member_name in member_names:
            member_info = self.__get_member_info(image_name, type_info, member_name)
            type_info = member_info.type
            offset += member_info.offset // 8

        return type_info, offset

    def __get_member_info(self, image_name: str, type_info: "tinfo_t", member_name: str) -> "udm_t":
        image = self.__img.get(image_name)

        member_info: udm_t = image.typeinf.udm_t()
        member_info.name = member_name
        if type_info.find_udm(member_info, image.typeinf.STRMEM_NAME) == image.api.BADADDR:
            message = f"Failed to find member `{member_name}`"
            raise ValueError(message)

        return member_info

    def __get_type_info(self, image_name: str, type_name: str) -> "tinfo_t":
        image = self.__img.get(image_name)

        type_id: int = image.typeinf.get_named_type_tid(type_name)
        if type_id == image.api.BADADDR:
            message = f"Failed to find type `{type_name}`"
            raise ValueError(message)

        type_info: tinfo_t = image.typeinf.tinfo_t()
        if not type_info.get_type_by_tid(type_id):
            message = f"Failed to get type information for type `{type_name}`"
            raise RuntimeError(message)

        return type_info
