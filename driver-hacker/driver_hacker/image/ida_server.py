from argparse import ArgumentParser
from dataclasses import dataclass
from typing import ParamSpec, TypeVar, final

import ida_auto  # type: ignore[import-not-found]
import ida_pro  # type: ignore[import-not-found]
import idc  # type: ignore[import-not-found]
import rpyc  # type: ignore[import-untyped]

ParameterTypes = ParamSpec("ParameterTypes")
ReturnType = TypeVar("ReturnType")


@final
@dataclass(frozen=True)
class Arguments:
    port: int


def parse_arguments() -> Arguments:
    argument_parser = ArgumentParser()
    argument_parser.add_argument("port", type=int)
    return Arguments(**vars(argument_parser.parse_args(idc.ARGV[1:])))


def main(arguments: Arguments) -> None:
    ida_auto.auto_wait()
    rpyc.OneShotServer(rpyc.SlaveService, port=arguments.port).start()
    ida_pro.qexit()


if __name__ == "__main__":
    main(parse_arguments())
