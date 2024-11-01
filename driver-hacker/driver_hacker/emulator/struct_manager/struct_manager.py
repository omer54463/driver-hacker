from typing import TYPE_CHECKING, final

from driver_hacker.emulator.image_manager.image_manager import ImageManager

if TYPE_CHECKING:
    from ida_typeinf import tinfo_t, udm_t  # type: ignore[import-not-found]


@final
class StructManager:
    __img: ImageManager

    def __init__(self, img: ImageManager) -> None:
        self.__img = img

    def size(self, image_name: str, struct_name: str) -> int:
        type_info = self.__get_type_info(image_name, struct_name)

        if not type_info.is_struct():
            message = f"Type `{struct_name}` is not a struct"
            raise ValueError(message)

        size: int = type_info.get_size()
        return size

    def offset(self, image_name: str, struct_name: str, member_name: str) -> int:
        type_info = self.__get_type_info(image_name, struct_name)

        if not type_info.is_struct():
            message = f"Type `{struct_name}` is not a struct"
            raise ValueError(message)

        return self.__get_member_offset(image_name, type_info, member_name)

    def __get_member_offset(self, image_name: str, type_info: "tinfo_t", member_name: str) -> int:
        image = self.__img.get(image_name)

        member: udm_t = image.typeinf.udm_t()
        member.name = member_name
        if type_info.find_udm(member, image.typeinf.STRMEM_NAME) == image.api.BADADDR:
            message = f"Failed to find member `{member_name}`"
            raise ValueError(message)

        offset: int = member.offset // 8
        return offset

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
