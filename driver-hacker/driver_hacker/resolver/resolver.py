from collections.abc import Iterable, MutableMapping, Sequence
from enum import Enum, Flag, auto
from functools import partial
from typing import assert_never, cast, final

from driver_hacker.ida.ida import Ida


@final
class ReferenceDirection(Enum):
    TO = auto()
    FROM = auto()


@final
class ReferenceType(Flag):
    ORDINARY_FLOW = auto()
    CALL_FAR = auto()
    CALL_NEAR = auto()
    JUMP_FAR = auto()
    JUMP_NEAR = auto()
    OFFSET = auto()
    WRITE = auto()
    READ = auto()
    TEXTUAL = auto()

    CALL = CALL_FAR | CALL_NEAR
    JUMP = JUMP_FAR | JUMP_NEAR
    FLOW = CALL | JUMP
    ALL = (
        ORDINARY_FLOW
        | CALL_FAR
        | CALL_NEAR
        | JUMP_FAR
        | JUMP_NEAR
        | OFFSET
        | WRITE
        | READ
        | TEXTUAL
    )


class Resolver:
    __ida: Ida
    __imports: dict[str, int]

    def __init__(self, ida: Ida) -> None:
        self.__ida = ida
        self.__imports = self.__get_imports()

    def resolve_name(self, address: int) -> str:
        if (operand := self.try_resolve_name(address)) is not None:
            return operand

        message = f"Could not resolve the name of the function at `{address:#x}`"
        raise ValueError(message)

    def try_resolve_name(self, address: int) -> str | None:
        return cast(str, self.__ida.name.get_name(address))

    def resolve_imports(self, names: Iterable[str]) -> Sequence[int]:
        return [self.__imports[name] for name in names]

    def resolve_import(self, name: str) -> int:
        try:
            return self.__imports[name]

        except KeyError as key_error:
            message = f"Import `{name}` was not found"
            raise ValueError(message) from key_error

    def resolve_references(
        self,
        address: int,
        direction: ReferenceDirection,
        types: ReferenceType,
    ) -> Sequence[int]:
        match direction:
            case ReferenceDirection.TO:
                function = self.__ida.utils.XrefsTo

            case ReferenceDirection.FROM:
                function = self.__ida.utils.XrefsFrom

            case never:
                assert_never(never)

        xref_types: set[int] = set()
        for type in types:
            match type:
                case ReferenceType.ORDINARY_FLOW:
                    xref_types.add(self.__ida.xref.fl_F)

                case ReferenceType.CALL_FAR:
                    xref_types.add(self.__ida.xref.fl_CF)

                case ReferenceType.CALL_NEAR:
                    xref_types.add(self.__ida.xref.fl_CN)

                case ReferenceType.JUMP_FAR:
                    xref_types.add(self.__ida.xref.fl_JF)

                case ReferenceType.JUMP_NEAR:
                    xref_types.add(self.__ida.xref.fl_JN)

                case ReferenceType.OFFSET:
                    xref_types.add(self.__ida.xref.dr_O)

                case ReferenceType.WRITE:
                    xref_types.add(self.__ida.xref.dr_W)

                case ReferenceType.READ:
                    xref_types.add(self.__ida.xref.dr_R)

                case ReferenceType.TEXTUAL:
                    xref_types.add(self.__ida.xref.dr_T)

                case value:
                    message = f"Unexpected reference type `{value}`"
                    raise ValueError(message)

        return [xref.frm for xref in function(address) if xref.type in xref_types]

    def resolve_references_to(self, address: int, types: ReferenceType) -> Sequence[int]:
        return self.resolve_references(address, ReferenceDirection.TO, types)

    def resolve_references_from(self, address: int, types: ReferenceType) -> Sequence[int]:
        return self.resolve_references(address, ReferenceDirection.FROM, types)

    @staticmethod
    def __enum_import_names_callback(
        result: MutableMapping[str, int],
        current_address: int,
        current_name: str | None,
        _current_ordinal: int,
    ) -> bool:
        if current_name is not None:
            result[current_name] = current_address

        return True

    def __get_imports(self) -> dict[str, int]:
        result: dict[str, int] = {}

        for index in range(self.__ida.nalt.get_import_module_qty()):
            self.__ida.nalt.enum_import_names(
                index,
                partial(self.__enum_import_names_callback, result),
            )

        return result
