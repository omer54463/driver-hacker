from collections.abc import Iterable

from unicorn import (  # type: ignore[import-untyped]
    Uc,
)

from driver_hacker.ida.ida import Ida

__POINTER_SIZE = 8


def __resolve_imports(emulator: Uc, driver: Ida, libraries: Iterable[Ida] | None = None) -> None:
    if libraries is None:
        libraries = {}

    library_mapping = {library.name: library for library in libraries}

    imports = __get_imports(driver)
    for library_name, library_imports in imports.items():
        if library_name in library_mapping:
            library = library_mapping[library_name]
            exports = __get_exports(library)

            for import_address, import_name, import_ordinal in library_imports:
                if import_name in exports:
                    export_address = exports[import_name]

                elif import_ordinal in exports:
                    export_address = exports[import_ordinal]

                else:
                    message = f"Import `{library_name}:{import_name or import_ordinal}` could not be resolved"
                    raise RuntimeError(message)

                emulator.mem_write(import_address, export_address.to_bytes(__POINTER_SIZE, "little"))


def __get_imports(driver: Ida) -> dict[str, list[tuple[int, str | None, int | None]]]:
    imports: dict[str, list[tuple[int, str | None, int | None]]] = {}

    for index in range(driver.nalt.get_import_module_qty()):
        library_imports: list[tuple[int, str | None, int | None]] = []

        def __resolve_imports_callback(address: int, name: str | None, ordinal: int | None) -> bool:
            library_imports.append((address, name, ordinal))
            return True

        driver.nalt.enum_import_names(index, __resolve_imports_callback)

        library_name: str = driver.nalt.get_import_module_name(index)
        imports[library_name] = library_imports

    return imports


def __get_exports(driver: Ida) -> dict[int | str, int]:
    exports: dict[int | str, int] = {}

    for index in range(driver.entry.get_entry_qty()):
        ordinal: int = driver.entry.get_entry_ordinal(index)
        address: int = driver.entry.get_entry(ordinal)
        name: str | None = driver.entry.get_entry_name(ordinal)

        if ordinal != 0:
            exports[ordinal] = address

        if name is not None:
            exports[name] = address

    return exports
