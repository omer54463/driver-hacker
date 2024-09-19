class FreeRegion:
    __start_address: int
    __end_address: int

    def __init__(self, start_address: int, end_address: int) -> None:
        self.__start_address = start_address
        self.__end_address = end_address

    @property
    def start_address(self) -> int:
        return self.__start_address

    @property
    def end_address(self) -> int:
        return self.__end_address

    @property
    def size(self) -> int:
        return self.__end_address - self.__start_address
