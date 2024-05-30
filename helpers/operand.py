
from enum import Enum
from helpers.log import logger

class OperandKind(Enum):
    SOURCE = "source"
    DESTINATION = "destination"


class Operand:
    def __init__(self, kind, value):
        self.kind = kind
        self.value = value


class StackVariableOperand(Operand):
    def __init__(self, kind, address, value, name):
        super().__init__(kind, value)
        self.address = address
        self.name = name

        if value is None:
            logger.error(f"Stack variable value is None, address={hex(address)}, name={name}")
            # raise ValueError(f"Stack variable value is None, address={hex(address)}, name={name}")


class RegisterOperand(Operand):
    def __init__(self, kind, address, value, name):
        super().__init__(kind, value)
        self.address = address
        self.name = name