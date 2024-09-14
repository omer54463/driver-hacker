from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
from re import Pattern, compile
from typing import final

from driver_hacker.analyze import analyze
from driver_hacker.get_drivers import get_drivers
from driver_hacker.ida.ida_cache import IdaCache

PAGE_SIZE = 0x1000


@final
@dataclass(frozen=True)
class Arguments:
    pattern: Pattern[str]
    working_directory: Path


def parse_arguments() -> Arguments:
    argument_parser = ArgumentParser()
    argument_parser.add_argument(
        "-p",
        "--pattern",
        type=compile,
        default=compile(""),
        help="REGEX pattern to match driver names against",
    )
    argument_parser.add_argument(
        "-w",
        "--working-directory",
        type=Path,
        default=Path.cwd() / "working-directory",
        help="IDA database cache root directory",
    )
    return Arguments(**vars(argument_parser.parse_args()))


def main(arguments: Arguments) -> None:
    ida_cache = IdaCache(arguments.working_directory)
    drivers = get_drivers()

    ntoskrnl = ida_cache.get(drivers["ntoskrnl"])

    for driver, driver_path in drivers.items():
        if driver == "ntoskrnl" or not arguments.pattern.match(driver):
            continue

        analyze(ntoskrnl, ida_cache.get(driver_path))


if __name__ == "__main__":
    main(parse_arguments())
