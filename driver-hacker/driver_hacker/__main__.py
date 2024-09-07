from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
from re import Pattern, compile
from typing import final

from loguru import logger

from driver_hacker.decoder.register_operand import RegisterOperand
from driver_hacker.follower.follow_leaf import FollowLeaf
from driver_hacker.follower.follow_leaf_type import FollowLeafType
from driver_hacker.follower.follow_node import FollowNode
from driver_hacker.follower.follower import Follower
from driver_hacker.get_system_modules import get_system_modules
from driver_hacker.ida.ida import Ida
from driver_hacker.ida.ida_cache import IdaCache
from driver_hacker.resolver.function import Function
from driver_hacker.resolver.reference_type import ReferenceType
from driver_hacker.resolver.resolver import Resolver

MAX_SIZE = 1 << 20


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


def display_follow_nodes(node: FollowNode, level: int = 0) -> None:
    logger.info("{} - {}", " " * level * 2, node)

    for sub_node in node:
        display_follow_nodes(sub_node, level + 1)

    for leaf in node.leafs:
        logger.info("{} - {}", " " * (level + 1) * 2, leaf)


def analyze(ida: Ida) -> None:
    resolver = Resolver(ida)
    io_create_device = resolver.resolve_import("IoCreateDevice")
    logger.info("IoCreateDevice: {:#x}", io_create_device)

    follower = Follower(ida)
    for reference_address in resolver.resolve_references_to(io_create_device, ReferenceType.FLOW):
        logger.info("IoCreateDevice reference: {:#x}", reference_address)
        tree = follower.follow_backwards(reference_address, RegisterOperand("r8"))

        for leaf in tree.leafs:
            match leaf:
                case FollowLeaf(
                    leaf_address,
                    FollowLeafType.FUNCTION_CALL,
                    Function(
                        _,
                        "__imp_RtlInitUnicodeString"
                        | "__imp_RtlInitUnicodeStringEx"
                        | "RtlInitUnicodeString"
                        | "RtlInitUnicodeStringEx",
                        _,
                    ),
                ):
                    tree = follower.follow_backwards(leaf_address, RegisterOperand("rdx"))
                    display_follow_nodes(tree.root)


def main(arguments: Arguments) -> None:
    ida_cache = IdaCache(arguments.working_directory)

    for module in get_system_modules():
        if not arguments.pattern.match(module.name):
            continue

        logger.info("Module: {}", module)
        if (module_size := module.stat().st_size) > MAX_SIZE:
            logger.warning(
                "Skipping module because it's too large ({:} bytes > {:} bytes)",
                module_size,
                MAX_SIZE,
            )
            continue

        logger.info("Connecting to IDA...")
        with ida_cache.get(module) as ida:
            try:
                logger.info("Analyzing module...")
                analyze(ida)

            except Exception as exception:
                logger.exception(exception)


if __name__ == "__main__":
    main(parse_arguments())
