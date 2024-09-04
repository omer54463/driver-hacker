from collections.abc import Generator, Sequence
from typing import TYPE_CHECKING, cast

from driver_hacker.decoder.decoder import Decoder
from driver_hacker.decoder.instruction import Instruction
from driver_hacker.follower.follow_direction import FollowDirection
from driver_hacker.follower.follow_node import FollowNode
from driver_hacker.follower.follow_tree import FollowTree
from driver_hacker.ida.ida import Ida
from driver_hacker.resolver.resolver import Resolver

if TYPE_CHECKING:
    import ida_gdl  # type: ignore[import-not-found]


class Follower:
    __ida: Ida

    __MOV_MNEMONICS = ("mov", "movdqu", "movups", "lea")

    def __init__(self, ida: Ida) -> None:
        self.__ida = ida
        self.__resolver = Resolver(ida)
        self.__decoder = Decoder(ida)

    def follow(self, address: int, operand: str, direction: FollowDirection) -> FollowTree:
        tree = FollowTree(FollowNode(address, operand, direction))

        queue = [(tree.root, self.__get_block(tree.root.address))]
        visited = set()

        while len(queue) > 0:
            node, block = queue.pop()
            visited.add((node, block.start_ea))
            new_nodes, node_exhausted = self.__follow_node(node, block)

            if not node_exhausted:
                queue.extend(
                    (node, next_block)
                    for next_block in self.__get_next_blocks(block, node.direction)
                    if (node, next_block.start_ea) not in visited
                )

            queue.extend(
                (new_node, block)
                for new_node in new_nodes
                if new_node.direction != FollowDirection.STOP
            )

        return tree

    def follow_backwards(self, address: int, operand: str) -> FollowTree:
        return self.follow(address, operand, FollowDirection.BACKWARDS)

    def follow_forwards(self, address: int, operand: str) -> FollowTree:
        return self.follow(address, operand, FollowDirection.FORWARDS)

    def __get_block(self, address: int) -> "ida_gdl.BasicBlock":
        function = self.__ida.funcs.get_func(address)
        flow_chart = self.__ida.gdl.FlowChart(function)

        for block in flow_chart:
            if block.start_ea <= address <= block.end_ea:
                return block

        message = f"Block was not found for address `{address:#x}`"
        raise ValueError(message)

    def __follow_node(
        self,
        node: FollowNode,
        block: "ida_gdl.BasicBlock",
    ) -> tuple[Sequence[FollowNode], bool]:
        address = (
            node.address
            if block.start_ea <= node.address <= block.end_ea
            else self.__default_address(block, node.direction)
        )

        instruction: Instruction | None = self.__decoder.decode_instruction(address)
        new_nodes: list[FollowNode] = []
        while instruction := self.__next_instruction(instruction, block, node.direction):
            new_node, is_primary = self.__process_instruction(instruction, node)

            if new_node is None:
                continue

            new_nodes.append(new_node)

            if is_primary:
                return new_nodes, True

        return new_nodes, False

    def __get_next_blocks(
        self,
        block: "ida_gdl.BasicBlock",
        direction: FollowDirection,
    ) -> Generator["ida_gdl.BasicBlock"]:
        match direction:
            case FollowDirection.BACKWARDS:
                return cast(Generator["ida_gdl.BasicBlock"], block.preds())

            case FollowDirection.FORWARDS:
                return cast(Generator["ida_gdl.BasicBlock"], block.succs())

            case direction:
                message = f"Unexpected direction `{direction}`"
                raise RuntimeError(message)

    def __default_address(self, block: "ida_gdl.BasicBlock", direction: FollowDirection) -> int:
        match direction:
            case FollowDirection.BACKWARDS:
                return cast(int, block.end_ea)

            case FollowDirection.FORWARDS:
                return cast(int, block.start_ea)

            case direction:
                message = f"Unexpected direction `{direction}`"
                raise RuntimeError(message)

    def __next_instruction(
        self,
        instruction: Instruction | None,
        block: "ida_gdl.BasicBlock",
        direction: FollowDirection,
    ) -> Instruction | None:
        if instruction is None:
            return None

        match direction:
            case FollowDirection.BACKWARDS:
                if (
                    instruction.previous_address is not None
                    and instruction.previous_address >= block.start_ea
                ):
                    return self.__decoder.decode_instruction(instruction.previous_address)

                return None

            case FollowDirection.FORWARDS:
                if (
                    instruction.following_address is not None
                    and instruction.following_address < block.end_ea
                ):
                    return self.__decoder.decode_instruction(instruction.following_address)

                return None

            case direction:
                message = f"Unexpected direction `{direction}`"
                raise RuntimeError(message)

    def __process_instruction(
        self,
        instruction: Instruction,
        node: FollowNode,
    ) -> tuple[FollowNode | None, bool]:
        match node.direction:
            case FollowDirection.BACKWARDS:
                return self.__process_instruction_backwards(instruction, node)

            case FollowDirection.FORWARDS:
                return self.__process_instruction_forwards(instruction, node)

            case direction:
                message = f"Unexpected direction `{direction}`"
                raise RuntimeError(message)

    def __process_instruction_backwards(
        self,
        instruction: Instruction,
        node: FollowNode,
    ) -> tuple[FollowNode | None, bool]:
        if instruction.mnemonic in self.__MOV_MNEMONICS:
            if node.operand == instruction.get_operand(0):
                new_node = node.new(instruction.address, instruction.get_operand(1), node.direction)
                return new_node, True

            if instruction.mnemonic == "lea" and node.operand == instruction.get_operand(1):
                new_node = node.new(
                    instruction.address,
                    instruction.get_operand(0),
                    node.direction.opposite(),
                )
                return new_node, False

        return None, False

    def __process_instruction_forwards(
        self,
        instruction: Instruction,
        node: FollowNode,
    ) -> tuple[FollowNode | None, bool]:
        if instruction.mnemonic in self.__MOV_MNEMONICS and node.operand == instruction.get_operand(
            1
        ):
            return node.new(instruction.address, instruction.get_operand(0), node.direction), True

        if instruction.mnemonic == ("call"):
            function_address = instruction.get_operand(0, int)
            function = self.__resolver.resolve_function(function_address)

            if node.operand in function.arguments:
                return node.new(instruction.address, function.name, FollowDirection.STOP), True

        return None, False
