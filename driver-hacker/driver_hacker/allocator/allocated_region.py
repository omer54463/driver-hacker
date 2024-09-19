from driver_hacker.allocator.permission import Permission


class AllocatedRegion:
    __start_address: int
    __end_address: int
    __permissions: Permission

    def __init__(self, start_address: int, end_address: int, permissions: Permission) -> None:
        self.__start_address = start_address
        self.__end_address = end_address
        self.__permissions = permissions

    @property
    def start_address(self) -> int:
        return self.__start_address

    @property
    def end_address(self) -> int:
        return self.__end_address

    @property
    def size(self) -> int:
        return self.__end_address - self.__start_address

    @property
    def permissions(self) -> Permission:
        return self.__permissions
