from collections.abc import Iterable, MutableMapping, Sequence
from functools import partial
from pathlib import Path
from typing import assert_never, cast, final

from yaml import safe_load

from driver_hacker.ida.ida import Ida
from driver_hacker.resolver.function import Function
from driver_hacker.resolver.reference_direction import ReferenceDirection
from driver_hacker.resolver.reference_type import ReferenceType


@final
class Resolver:
    __ida: Ida
    __imports: dict[str, int]

    __FUNCTION_ARGUMENT_COUNTS: dict[str, int] = safe_load(
        (Path(__file__).parent / "function_argument_counts.yaml").read_text()
    )
    __FUNCTION_IMPORT_PREFIX = "__imp_"

    def __init__(self, ida: Ida) -> None:
        self.__ida = ida
        self.__imports = self.__get_imports()

    def resolve_name(self, address: int) -> str:
        if (name := self.try_resolve_name(address)) is not None:
            return name

        message = f"Could not resolve the name of the symbol at `{address:#x}`"
        raise ValueError(message)

    def try_resolve_name(self, address: int) -> str | None:
        return cast(str, self.__ida.name.get_name(address))

    def resolve_function(self, address: int) -> Function:
        if (function := self.try_resolve_function(address)) is not None:
            return function

        message = f"Could not resolve the function at `{address:#x}`"
        raise ValueError(message)

    def try_resolve_function(self, address: int) -> Function | None:
        function_name = self.try_resolve_name(address)

        if function_name is None:
            return None

        argument_count = self.__FUNCTION_ARGUMENT_COUNTS.get(
            function_name.removeprefix(self.__FUNCTION_IMPORT_PREFIX)
        )

        return Function(address, function_name, argument_count)

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
