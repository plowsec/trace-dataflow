from enum import Enum

import networkx as nx
from helpers import parse
from helpers import lift
from helpers.operand import OperandKind, StackVariableOperand, RegisterOperand, NodeKind
from helpers.log import logger
import pyvex
from typing import Dict, Any, Tuple
import matplotlib.pyplot as plt



class StatementNode:
    def __init__(self, stmt, index, root=False):
        self.stmt = stmt
        self.root = root
        self.index = index
        self.dependents = []  # Statements that depend on this statement
        self.dependencies = []  # Statements that this statement depends on
        self.is_reg = False
        self.reg_name = None
        self.reg_value = None
        self.is_const = False
        self.const_value = None
        self.is_ptr = False
        self.ptr_addr = None
        self.ptr_value = None

    def add_dependent(self, node):
        self.dependents.append(node)

    def add_dependency(self, node):
        self.dependencies.append(node)

    def __repr__(self):
        return f"StatementNode(index={self.index}, stmt={self.stmt}, dependents={self.dependents}, dependencies={self.dependencies})"

class Node:
    def __init__(self, name: str, loc: int, value: int, rip: int, instruction: str, timestamp: int, node_kind: Enum, origin=None):
        self.name = name  # e.g., 'rax'
        self.value = value  # e.g., the value stored in 'rax'
        self.rip = rip  # The instruction pointer where the value was set
        self.instruction = instruction  # Ensure it's hashable
        self.timestamp = timestamp  # A sequence number
        self.origin = origin  # The origin of the data
        self.loc = loc
        self.node_kind = node_kind

    def __str__(self):
        loc = hex(self.loc) if isinstance(self.loc, int) else str(self.loc)
        if loc == "None":
            # loc is a register

            if isinstance(self.value, int):
                return f"(v={hex(self.value)})@{self.name}[{self.timestamp}]\n{self.instruction}"
            if isinstance(self.value, tuple):
                return f"({hex(self.value[0]),self.value[1]})@{self.name}[{self.timestamp}]\n{self.instruction}"
            return f"({self.value})@{self.name}[{self.timestamp}]\n{self.instruction}"

        else:
            if isinstance(self.value, int):
                return f"{self.name}(v={hex(self.value)})@{loc}[{self.timestamp}]\n{self.instruction}"
            if isinstance(self.value, tuple):
                return f"{self.name}({hex(self.value[0]),self.value[1]})@{loc}[{self.timestamp}]\n{self.instruction}"
            return f"{self.name}({self.value})@{loc}[{self.timestamp}]\n{self.instruction}"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        if isinstance(other, Node):
            return (self.name == other.name and self.value == other.value and
                    self.rip == other.rip and self.instruction == other.instruction and
                    self.timestamp == other.timestamp and self.node_kind == other.node_kind and self.loc == other.loc)
        return False

    def __hash__(self):
        return hash((self.name, self.value, self.rip, self.instruction, self.timestamp, self.node_kind, self.loc))


class DataFlowAnalyzer:
    def __init__(self, source_buffer, source_size, global_state, taint_map):
        self.source_buffer = source_buffer
        self.source_size = source_size
        self.taint_map = taint_map
        self.global_state = global_state
        self.stack_variables = {}
        self.digraph = nx.DiGraph()  # Initialize the directed graph
        self.timestamp = 0  # Initialize a timestamp or sequence number
        self.register_history = {}  # Dictionary to map register names to their history of nodes
        self.memory_history = {}  # Dictionary to map memory addresses to their history of nodes
        self.alias_history = {}  # Dictionary to map memory aliases to their history of nodes
        self.alias_to_mem = {}
        self.mem_to_alias = {}
        #node = self.create_node("source", source_buffer, source_buffer, 0, "source buffer", 0)  # Add the source buffer as a node

        node = self.create_node("source", source_buffer, source_buffer, 0, "", NodeKind.MEMORY)  # Add the source buffer as a node
        self.add_node_to_graph(node)  # Add the source buffer node to the graph
        self.alias_to_mem["source"] = source_buffer  # Add the source buffer as an alias
        self.mem_to_alias[source_buffer] = "source"  # Add the source buffer as an alias
        self.accessed_registers = set()  # Initialize a set to store the accessed registers
        self.statements = []  # List to store the statement nodes
        self.tmp_to_stmt = {}  # Map from temporary variables to statement nodes
        self.current_rip = 0  # Initialize the current instruction pointer
        self.current_instruction = ""  # Initialize the current instruction


    def create_statement_node(self, stmt, index, root=False):
        node = StatementNode(stmt, index, root)
        self.statements.append(node)
        return node

    def get_dependencies(self, start_index):
        visited = set()
        dependencies = []

        def dfs(node):
            if node.index in visited:
                return
            visited.add(node.index)
            dependencies.append(node)
            for dep_node in node.dependencies:
                dfs(dep_node)

        if start_index < len(self.statements):
            start_node = self.statements[start_index]
            dfs(start_node)
        return dependencies

    def get_dependencies_from_node_stmt(self, node: StatementNode):
        visited = set()
        dependencies = []

        def dfs(node):
            if node.index in visited:
                return
            visited.add(node.index)
            dependencies.append(node)
            for dep_node in node.dependencies:
                dfs(dep_node)

        dfs(node)
        return dependencies



    def get_dependents(self, start_index):
        visited = set()
        dependents = []

        def dfs(node):
            if node.index in visited:
                return
            visited.add(node.index)
            dependents.append(node)
            for dep_node in node.dependents:
                dfs(dep_node)

        if start_index < len(self.statements):
            start_node = self.statements[start_index]
            dfs(start_node)
        return dependents

    def create_node(self, name, loc, value, rip, instruction: str, node_kind, origin=None):
        logger.debug(f"Creating node: name={name}, loc={hex(loc) if isinstance(loc, int) else str(loc)}, value={hex(value) if isinstance(value, int) else str(value)}, rip={hex(rip) if isinstance(rip, int) else str(rip)}, instruction={instruction}, node_kind={node_kind}, origin={origin}")

        self.timestamp += 1
        node = Node(name, loc, value, rip, instruction, self.timestamp, node_kind, origin)
        return node

    def add_node_to_graph(self, node: Node):

        # check if digraph already has a node with the same name and location and value
        for n in self.digraph.nodes:
            if node.name == n.name and node.loc == n.loc and node.value == n.value:
                logger.warning(f"Node already exists: {node} vs {n}")
                return node

        # Add the node to the graph
        self.digraph.add_node(node)
        # Update the node history based on the source kind
        if node.node_kind == NodeKind.REGISTER:
            if node.name not in self.register_history:
                self.register_history[node.name] = []
            self.register_history[node.name].append(node)
        elif node.node_kind == NodeKind.MEMORY:
            if node.loc not in self.memory_history:
                self.memory_history[node.loc] = []
            self.memory_history[node.loc].append(node)
        elif node.node_kind == NodeKind.STACK and node.name.startswith("0x"):
            if node.loc not in self.memory_history:
                self.memory_history[node.loc] = []
            self.memory_history[node.loc].append(node)
        elif node.node_kind == NodeKind.STACK:
            if node.name not in self.alias_history and node.loc not in self.mem_to_alias:
                self.alias_history[node.name] = [node]
                if node.name not in self.alias_to_mem:
                    self.alias_to_mem[node.name] = node.loc
                    self.mem_to_alias[node.loc] = node.name
            elif node.loc in self.mem_to_alias:
                logger.debug(f"Node alread exists in mem_to_alias: {node.loc} -> {self.mem_to_alias[node.loc]}")
                if node.name not in self.alias_to_mem:
                    self.alias_to_mem[node.name] = node.loc
                alias = self.mem_to_alias[node.loc]
                if alias not in self.alias_history:
                    self.alias_history[alias] = [node]
                else:
                    self.alias_history[alias].append(node)
            else:
                self.alias_history[node.name].append(node)

        return node


    def add_edge_to_graph(self, src_node, dst_node, operation):
        # Add an edge from src_node to dst_node with the operation as an attribute
        self.digraph.add_edge(src_node, dst_node, operation=operation)

    def lookup_previous_node(self, source_name, source_loc, source_kind, current_rip, origin=None):
        # Lookup the most recent node for the variable before the current RIP

        history = None
        if source_kind == NodeKind.REGISTER:
            history = self.register_history.get(source_name, [])
        elif source_kind == NodeKind.MEMORY:
            history = self.memory_history.get(source_name)
            if not history:
                history = self.memory_history.get(self.alias_to_mem.get(source_name), [])
                if not history:
                    history = self.memory_history.get(source_loc, [])
                    if not history:
                        alias = self.mem_to_alias.get(source_loc)
                        if alias:
                            history = self.alias_history.get(alias, [])

        elif source_kind == NodeKind.STACK:
            history = self.alias_history.get(source_name, [])
            if history is None:
                history = self.memory_history.get(self.alias_to_mem.get(source_name), [])
                if history is None:
                    history = self.memory_history.get(source_loc, [])

        if history:
            for node in reversed(history):
                if node.timestamp <= self.timestamp:
                    return node

        """
        elif source_name.startswith("source"):
            return self.node_history["source"][0]
        elif origin and origin in self.node_history:
            return self.lookup_previous_node(origin, current_rip)
        elif origin and origin.startswith("source"):
            return self.node_history["source"][0]
        """

        return None

    def add_link(self, target_name, target_addr, source_name, source_loc, target_kind, source_kind, current_value, rip, instruction: str, origin=None):

        logger.debug(f"add_link: target_name={target_name}, target_addr={hex(target_addr) if isinstance(target_addr, int) else str(target_addr)}, source_name={source_name}, source_loc={hex(source_loc) if isinstance(source_loc, int) else str(source_loc)}, target_kind={target_kind}, source_kind={source_kind}, current_value={hex(current_value) if isinstance(current_value, int) else str(current_value)}, rip={hex(rip) if isinstance(rip, int) else str(rip)}, instruction={instruction}, origin={origin}")
        # self.add_link(target_name, source_name, source_loc, current_value, rip, instr.split()[1:], origin)
        if isinstance(source_name, int):
            source_name = hex(source_name)

        # Create a new node for the current instruction
        new_node = self.create_node(target_name, target_addr, current_value, rip, instruction, target_kind, origin)
        # Lookup the previous node for the variable
        prev_node = self.lookup_previous_node(source_name, source_loc, source_kind, rip, origin)
        # Add the new node to the graph
        new_node = self.add_node_to_graph(new_node)

        if prev_node:
            # Add an edge from the previous node to the new node
            self.add_edge_to_graph(prev_node, new_node, instruction)
        else:
            logger.error(f"Previous node not found for {source_name} at RIP {hex(rip)}")
            node = self.create_node(source_name, source_loc, current_value, rip, instruction, source_kind, origin)
            self.add_node_to_graph(node)


    # Function to print the taint flow in the desired format
    @staticmethod
    def print_taint_flow(taint_flows):
        indent_level = 0
        last_rip = None

        for flow in taint_flows:
            rip = flow['rip']
            src = flow['src']
            src_value = flow['src_value']
            dest = flow['dest']
            dest_type = flow['dest_type']
            instr = flow['instr']

            if dest_type == 'reg':
                dest_str = dest
            else:
                dest_str = f"{hex(dest)} (memory)" if dest is not None else "None"

            if isinstance(src, int):
                src_str = f"{hex(src)} (memory)"
            else:
                src_str = src

            if rip != last_rip:
                indent_level = 0
                if last_rip is not None:
                    print()  # Add a blank line between different RIPs
                print(f"{hex(rip)}:", end=' ')
                last_rip = rip

            indent = '  ' * indent_level
            hex_src_value = hex(src_value) if isinstance(src_value, int) else src_value
            print(f"{indent}{src_str} --[{hex_src_value}]--> {dest_str}")
            print(f"{indent}  {instr}")

            indent_level += 1

    def update_taint_map(self, dest, value, origin):
        dest_name = hex(dest) if isinstance(dest, int) else dest
        value_name = hex(value) if isinstance(value, int) else value
        logger.debug(f"Updating taint map: {dest_name} -> ({value_name}, {origin})")
        self.taint_map[dest] = (value, origin)

    # Function to get the origin of a tainted value
    def get_origin(self, value):
        if value in self.taint_map:
            if isinstance(self.taint_map[value], tuple):
                return self.taint_map[value][1]
            else:
                return "unknown"

        return None

    # Function to get the value of a temporary variable
    @staticmethod
    def get_tmp_value(tmp, tmp_values):
        return tmp_values.get(tmp, None)


    def update_stmt_dependencies(self, stmt, index):

        node = self.create_statement_node(stmt, index)
        if isinstance(stmt.data, pyvex.expr.RdTmp):
            src_tmp = stmt.data.tmp
            if src_tmp in self.tmp_to_stmt:
                src_node = self.tmp_to_stmt[src_tmp]
                node.add_dependency(src_node)
                src_node.add_dependent(node)
            self.tmp_to_stmt[stmt.tmp] = node
        elif isinstance(stmt.data, pyvex.expr.Binop):
            for arg in stmt.data.args:
                if isinstance(arg, pyvex.expr.RdTmp):
                    src_tmp = arg.tmp
                    if src_tmp in self.tmp_to_stmt:
                        src_node = self.tmp_to_stmt[src_tmp]
                        node.add_dependency(src_node)
                        src_node.add_dependent(node)
            self.tmp_to_stmt[stmt.tmp] = node

    # Function to perform intra-instruction taint analysis
    def handle_wr_tmp(self, stmt, tmp_values, tmp_taint, operand_map, node: StatementNode):

        """Handle WrTmp statements."""
        if isinstance(stmt.data, pyvex.expr.RdTmp):
            self.handle_wr_tmp_rdtmp(stmt, tmp_values, tmp_taint, operand_map, node)
        elif isinstance(stmt.data, pyvex.expr.Unop):
            self.handle_wr_tmp_unop(stmt, tmp_values, tmp_taint, operand_map, node)
        elif isinstance(stmt.data, pyvex.expr.Load):
            self.handle_wr_tmp_load(stmt, tmp_values, tmp_taint, operand_map, node)
        elif isinstance(stmt.data, pyvex.expr.Get):
            self.handle_wr_tmp_get(stmt, tmp_values, tmp_taint, operand_map, node)
        elif isinstance(stmt.data, pyvex.expr.Const):
            self.handle_wr_tmp_const(stmt, tmp_values, tmp_taint, node)
        elif isinstance(stmt.data, pyvex.expr.Binop):
            self.handle_wr_tmp_binop(stmt, tmp_values, tmp_taint, operand_map, node)
        else:
            logger.error(f"WrTmp statement with data type {type(stmt.data)} not implemented")

    def handle_wr_tmp_rdtmp(self, stmt, tmp_values, tmp_taint, operand_map, node: StatementNode):
        """Handle WrTmp statements with RdTmp data."""
        src_tmp = stmt.data.tmp
        tmp_values[stmt.tmp] = tmp_values.get(src_tmp)
        tmp_taint[stmt.tmp] = tmp_taint.get(src_tmp)
        logger.debug(
            f"RdTmp: src_tmp={src_tmp}, tmp_values[{stmt.tmp}]={hex(tmp_values[stmt.tmp])}, tmp_taint[{stmt.tmp}]={tmp_taint[stmt.tmp]}")

        if src_tmp in self.tmp_to_stmt:
            src_node = self.tmp_to_stmt[src_tmp]
            node.add_dependency(src_node)
            src_node.add_dependent(node)
        self.tmp_to_stmt[stmt.tmp] = node


    def handle_wr_tmp_unop(self, stmt, tmp_values, tmp_taint, operand_map, node: StatementNode):

        """Handle WrTmp statements with Unop data."""
        if isinstance(stmt.data.args[0], pyvex.expr.RdTmp):
            src_tmp = stmt.data.args[0].tmp
            if tmp_values.get(src_tmp) is None:
                logger.error(f"Unop: Source temp value is None, stmt={stmt}")
            tmp_values[stmt.tmp] = tmp_values.get(src_tmp)
            tmp_taint[stmt.tmp] = tmp_taint.get(src_tmp)
            logger.debug(
                f"Unop: src_tmp={src_tmp}, tmp_values[{stmt.tmp}]={hex(tmp_values[stmt.tmp])}, tmp_taint[{stmt.tmp}]={tmp_taint[stmt.tmp]}")
            if src_tmp in operand_map:
                operand_map[stmt.tmp] = operand_map[src_tmp]

            if src_tmp in self.tmp_to_stmt:
                src_node = self.tmp_to_stmt[src_tmp]
                node.add_dependency(src_node)
                src_node.add_dependent(node)
            self.tmp_to_stmt[stmt.tmp] = node

    def handle_wr_tmp_load(self, stmt, tmp_values, tmp_taint, operand_map, stmt_node: StatementNode):

        """Handle WrTmp statements with Load data."""
        if isinstance(stmt.data.addr, pyvex.expr.Const):
            addr = stmt.data.addr.con.value
            tmp_values[stmt.tmp] = self.stack_variables.get(addr).value if addr in self.stack_variables else 0
            tmp_taint[stmt.tmp] = self.taint_map.get(addr)
            logger.debug(
                f"Load: addr={hex(addr)}, tmp_values[{stmt.tmp}]={hex(tmp_values[stmt.tmp])}, tmp_taint[{stmt.tmp}]={tmp_taint[stmt.tmp]}")
            if addr in self.stack_variables:
                operand_map[stmt.tmp] = self.stack_variables.get(addr)
            else:
                logger.debug(f"Creating stack variable for address: {hex(addr)}")
                self.stack_variables[addr] = StackVariableOperand(OperandKind.SOURCE, addr, 0, "unknown")
                node = self.create_node(hex(addr), addr, 0, 0, "", NodeKind.MEMORY)  # TODO stack
                self.add_node_to_graph(node)
                operand_map[stmt.tmp] = self.stack_variables.get(addr)

            stmt_node.root = True
            stmt_node.is_ptr = True
            stmt_node.ptr_addr = addr
            stmt_node.ptr_value = tmp_values[stmt.tmp]
            self.tmp_to_stmt[stmt.tmp] = stmt_node

        else:

            logger.debug(f"Load: Address is not a constant, stmt={stmt}")
            if isinstance(stmt.data.addr, pyvex.expr.RdTmp):
                addr_tmp = stmt.data.addr.tmp
                if addr_tmp in self.tmp_to_stmt:
                    addr_node = self.tmp_to_stmt[addr_tmp]
                    stmt_node.add_dependency(addr_node)
                    addr_node.add_dependent(stmt_node)
            self.tmp_to_stmt[stmt.tmp] = stmt_node

            addr_tmp = stmt.data.addr.tmp
            addr = tmp_values.get(addr_tmp)

            if addr is None:
                logger.error(f"Load: Address temp value is None, stmt={stmt}")
                raise ValueError(f"Load: Address temp value is None, stmt={stmt}")

            if addr in self.stack_variables:
                operand_map[stmt.tmp] = self.stack_variables.get(addr)
            else:
                logger.debug(f"Creating stack variable for address: {hex(addr)}")
                value = self.global_state['memory'].get(addr)
                if value is None:
                    logger.warning(f"Memory value at address {hex(addr)} is None")
                self.stack_variables[addr] = StackVariableOperand(OperandKind.SOURCE, addr, value, "unknown")
                operand_map[stmt.tmp] = self.stack_variables.get(addr)
                node = self.create_node(hex(addr), addr, value, 0, "", NodeKind.MEMORY)  # TODO stack
                self.add_node_to_graph(node)

            new_tmp_value = self.stack_variables.get(addr).value if addr in self.stack_variables else None

            if new_tmp_value is None:
                logger.error(f"Load: New temp value is None, stmt={stmt}")
                dbg_addr_in_stack = addr in self.stack_variables
                dbg_stack_variables = self.stack_variables.get(addr)
                dbg_stack_var_value = self.stack_variables.get(addr).value
                raise ValueError(f"Load: New temp value is None, stmt={stmt}")

            tmp_values[stmt.tmp] = new_tmp_value
            tmp_taint[stmt.tmp] = self.taint_map.get(addr)
            logger.debug(
                f"Load: addr_tmp={addr_tmp}, addr={hex(addr)}, tmp_values[{stmt.tmp}]={hex(tmp_values[stmt.tmp])}, tmp_taint[{stmt.tmp}]={tmp_taint[stmt.tmp]}")
            stmt_node.root = True
            stmt_node.is_ptr = True
            stmt_node.ptr_addr = addr
            stmt_node.ptr_value = tmp_values[stmt.tmp]
            self.tmp_to_stmt[stmt.tmp] = stmt_node

    def handle_wr_tmp_get(self, stmt, tmp_values, tmp_taint, operand_map, node):
        """Handle WrTmp statements with Get data."""
        reg_name = lift.get_register_name(stmt.data.offset)
        new_tmp_value = self.global_state['registers'].get(reg_name)



        if new_tmp_value is None and (reg_name == 'd' or reg_name.startswith('xmm')):
            new_tmp_value = lift.arch.get_default_reg_value('d')
            logger.warning(f"Using default value for register 'd': {hex(new_tmp_value)}")
            self.global_state['registers'][reg_name] = new_tmp_value

        if new_tmp_value is None:
            logger.error(f"Get: New temp value is None, stmt={stmt}")
            raise ValueError(f"Get: New temp value is None, stmt={stmt}")

        tmp_values[stmt.tmp] = new_tmp_value
        tmp_tainted_value = self.taint_map.get(reg_name)
        if tmp_tainted_value is not None:
            if isinstance(tmp_tainted_value, tuple):
                tmp_taint[stmt.tmp] = tmp_tainted_value[0]
            else:
                tmp_taint[stmt.tmp] = tmp_tainted_value
        else:
            current_value = self.global_state['registers'].get(reg_name)
            if current_value is not None:
                tmp_taint[stmt.tmp] = current_value
            else:
                logger.warning(f"Taint value for register {reg_name} is None")
        logger.debug(
            f"Get: reg_name={reg_name}, tmp_values[{stmt.tmp}]={tmp_values[stmt.tmp]}, tmp_taint[{stmt.tmp}]={tmp_taint[stmt.tmp]}")
        if reg_name == "rsp":
            operand_map[stmt.tmp] = StackVariableOperand(OperandKind.SOURCE, tmp_values[stmt.tmp], tmp_taint[stmt.tmp],
                                                         "unknown")
            #node = self.create_node(hex(tmp_values[stmt.tmp]), tmp_values[stmt.tmp], tmp_taint[stmt.tmp], 0, "",
            #                        NodeKind.STACK) # TODO
            #self.add_node_to_graph(node)
        else:
            operand_map[stmt.tmp] = RegisterOperand(OperandKind.SOURCE, tmp_taint[stmt.tmp], tmp_taint[stmt.tmp],
                                                    reg_name)
            #node = self.create_node(reg_name, tmp_taint[stmt.tmp], tmp_taint[stmt.tmp], 0, "", NodeKind.REGISTER)
            #self.add_node_to_graph(node)

        node.root = True
        node.is_reg = True
        node.reg_name = reg_name
        node.reg_value = tmp_taint[stmt.tmp]
        self.tmp_to_stmt[stmt.tmp] = node

    def handle_wr_tmp_const(self, stmt, tmp_values, tmp_taint, node):
        """Handle WrTmp statements with Const data."""
        tmp_values[stmt.tmp] = stmt.data.con.value
        tmp_taint[stmt.tmp] = None
        logger.debug(
            f"Const: tmp_values[{stmt.tmp}]={tmp_values[stmt.tmp]}, tmp_taint[{stmt.tmp}]={hex(tmp_taint[stmt.tmp])}")
        node.root = True
        node.is_const = True
        node.const_value = tmp_values[stmt.tmp]
        self.tmp_to_stmt[stmt.tmp] = node
    def handle_wr_tmp_binop(self, stmt, tmp_values, tmp_taint, operand_map, node):

        for arg in stmt.data.args:
            if isinstance(arg, pyvex.expr.RdTmp):
                src_tmp = arg.tmp
                if src_tmp in self.tmp_to_stmt:
                    src_node = self.tmp_to_stmt[src_tmp]
                    node.add_dependency(src_node)
                    src_node.add_dependent(node)

        self.tmp_to_stmt[stmt.tmp] = node
        """Handle WrTmp statements with Binop data."""
        arg0 = self.get_tmp_value(stmt.data.args[0].tmp, tmp_values) if isinstance(stmt.data.args[0],
                                                                                   pyvex.expr.RdTmp) else \
            stmt.data.args[0].con.value if isinstance(stmt.data.args[0], pyvex.expr.Const) else None
        arg1 = stmt.data.args[1].con.value if isinstance(stmt.data.args[1], pyvex.expr.Const) else self.get_tmp_value(
            stmt.data.args[1].tmp, tmp_values)
        if isinstance(stmt.data.args[0], pyvex.expr.RdTmp) and isinstance(stmt.data.args[1], pyvex.expr.RdTmp):
            self.handle_binop_both_rdtmp(stmt, tmp_values, operand_map, arg0, arg1)
        elif isinstance(stmt.data.args[0], pyvex.expr.RdTmp):
            self.handle_binop_first_rdtmp(stmt, tmp_values, operand_map, arg0, arg1)
        elif isinstance(stmt.data.args[1], pyvex.expr.RdTmp):
            self.handle_binop_second_rdtmp(stmt, tmp_values, operand_map, arg0, arg1)
        self.handle_binop_operations(stmt, tmp_values, arg0, arg1)

    def handle_binop_both_rdtmp(self, stmt, tmp_values, operand_map, arg0, arg1):
        """Handle Binop with both RdTmp arguments."""
        operand1 = operand_map.get(stmt.data.args[0].tmp)
        operand2 = operand_map.get(stmt.data.args[1].tmp)
        rd_tmp1 = stmt.data.args[0].tmp
        rd_tmp2 = stmt.data.args[1].tmp
        if rd_tmp1 in tmp_values and rd_tmp2 in tmp_values:
            if stmt.data.op.startswith('Iop_Add'):
                tmp_values[stmt.tmp] = tmp_values[rd_tmp1] + tmp_values[rd_tmp2]
                operand_map[stmt.tmp] = RegisterOperand(OperandKind.SOURCE, tmp_values[stmt.tmp],
                                                        tmp_values[rd_tmp1] + tmp_values[rd_tmp2], "unknown")
            else:
                logger.error(f"Binop with both RdTmp: Not handled, stmt={stmt}")
        else:
            logger.error(f"Binop: One of the arguments is None, arg0={arg0}, arg1={arg1}")

    def handle_binop_first_rdtmp(self, stmt, tmp_values, operand_map, arg0, arg1):
        """Handle Binop with the first argument as RdTmp."""
        operand = operand_map.get(stmt.data.args[0].tmp)
        if operand is None:
            logger.warning(f"Binop: Operand is None, stmt={stmt}")
            return
        if isinstance(operand, StackVariableOperand):
            offset = stmt.data.args[1].con.value if isinstance(stmt.data.args[1], pyvex.expr.Const) else None
            if offset is not None:
                name = f"rsp+{hex(offset)}"
                address = operand.address + offset
                operand_map[stmt.tmp] = StackVariableOperand(OperandKind.SOURCE, address, operand.value, name)
                logger.debug(f"Stack variable offset: {name}, address={hex(address)}, pyvex_name={stmt.tmp}")
                #node = self.create_node(name, address, operand.value, 0, "", NodeKind.STACK)  # TODO stack
                #self.add_node_to_graph(node)
            else:
                logger.error(f"Binop: Stack variable offset is None, stmt={stmt}")
        else:
            offset = stmt.data.args[1].con.value if isinstance(stmt.data.args[1], pyvex.expr.Const) else None
            if offset is not None:
                name = f"{operand.name}+{hex(offset)}"
                address = tmp_values.get(stmt.data.args[0].tmp) + offset
                operand_map[stmt.tmp] = RegisterOperand(OperandKind.SOURCE, address,
                                                        tmp_values.get(stmt.data.args[0].tmp),
                                                        name)
                logger.debug(f"Register + offset: {name}, address={hex(address)}, pyvex_name={stmt.tmp}")
                node = self.create_node(name, address, tmp_values.get(stmt.data.args[0].tmp), 0, "", NodeKind.REGISTER)
                self.add_node_to_graph(node)

    def handle_binop_second_rdtmp(self, stmt, tmp_values, operand_map, arg0, arg1):
        """Handle Binop with the second argument as RdTmp."""
        operand = operand_map.get(stmt.data.args[1].tmp)
        if isinstance(operand, StackVariableOperand):
            offset = stmt.data.args[0].con.value if isinstance(stmt.data.args[0], pyvex.expr.Const) else None
            if offset is not None:
                name = f"rsp+0x{hex(offset)}"
                address = operand.address + offset
                operand_map[stmt.tmp] = StackVariableOperand(OperandKind.SOURCE, address, operand.value, name)
                logger.debug(f"Stack variable offset: {name}, address={hex(address)}, pyvex_name={stmt.tmp}")
                node = self.create_node(name, address, operand.value, 0, "", NodeKind.STACK)  # TODO stack
                self.add_node_to_graph(node)
            else:
                logger.error(f"Binop: Stack variable offset is None, stmt={stmt}")

    def handle_binop_operations(self, stmt, tmp_values, arg0, arg1):
        """Handle Binop operations."""
        if stmt.data.op.startswith('Iop_Add') or stmt.data.op.startswith('Iop_And') or stmt.data.op.startswith(
                'Iop_Sub') or stmt.data.op.startswith('Iop_Xor') or stmt.data.op.startswith(
            'Iop_Shl') or stmt.data.op.startswith('Iop_Or') or stmt.data.op.startswith('Iop_Mul') or stmt.data.op.startswith('Iop_Shr'):
            if arg0 is not None and arg1 is not None:
                size_in_bits = stmt.data.tag_int * 8
                mask = (1 << size_in_bits) - 1
                if stmt.data.op.startswith('Iop_Add'):
                    result = (arg0 + arg1) & mask
                    tmp_values[stmt.tmp] = result
                    logger.debug(
                        f"Binop Add: tmp_values[{stmt.tmp}]={hex(arg0)}+{hex(arg1)} = {hex(tmp_values[stmt.tmp])}")
                elif stmt.data.op.startswith('Iop_And'):
                    result = (arg0 & arg1) & mask
                    tmp_values[stmt.tmp] = result
                    logger.debug(f"Binop And: tmp_values[{stmt.tmp}]={hex(tmp_values[stmt.tmp])}")
                elif stmt.data.op.startswith('Iop_Sub'):
                    result = (arg0 - arg1) & mask
                    tmp_values[stmt.tmp] = result
                    logger.debug(f"Binop Sub: tmp_values[{stmt.tmp}]={hex(tmp_values[stmt.tmp])}")
                elif stmt.data.op.startswith('Iop_Xor'):
                    result = (arg0 ^ arg1) & mask
                    tmp_values[stmt.tmp] = result
                    logger.debug(f"Binop Xor: tmp_values[{stmt.tmp}]={hex(tmp_values[stmt.tmp])}")
                elif stmt.data.op.startswith('Iop_Shl'):
                    result = (arg0 << arg1) & mask
                    tmp_values[stmt.tmp] = result
                    logger.debug(f"Binop Shl: tmp_values[{stmt.tmp}]={hex(tmp_values[stmt.tmp])}")
                elif stmt.data.op.startswith('Iop_Or'):
                    result = (arg0 | arg1) & mask
                    tmp_values[stmt.tmp] = result
                    logger.debug(f"Binop Or: tmp_values[{stmt.tmp}]={hex(tmp_values[stmt.tmp])}")
                elif stmt.data.op.startswith('Iop_Mul'):
                    result = (arg0 * arg1) & mask
                    tmp_values[stmt.tmp] = result
                    logger.debug(f"Binop Mul: tmp_values[{stmt.tmp}]={hex(tmp_values[stmt.tmp])}")
                elif stmt.data.op.startswith('Iop_Shr'):
                    result = (arg0 >> arg1) & mask
                    tmp_values[stmt.tmp] = result
                    logger.debug(f"Binop Shr: tmp_values[{stmt.tmp}]={hex(tmp_values[stmt.tmp])}")
            else:
                logger.error(
                    f"Binop {stmt.data.op.split('_')[1]}: One of the arguments is None, arg0={arg0}, arg1={arg1}")
        else:
            logger.error(f"Binop: Operation not handled, stmt={stmt}")

    def handle_put(self, stmt, tmp_values, tmp_taint, node):
        """Handle Put statements.
        :param index:
        """
        reg_name = lift.get_register_name(stmt.offset)
        if reg_name.startswith("cc"):
            logger.debug(f"Skipping condition code register: {reg_name}")
            return
        if isinstance(stmt.data, pyvex.expr.RdTmp):
            src_tmp = stmt.data.tmp
            if tainted_val := tmp_taint.get(src_tmp):
                if isinstance(tainted_val, tuple):
                    self.taint_map[reg_name] = tainted_val
                else:
                    self.taint_map[reg_name] = (tmp_taint[src_tmp], 'default_value')

            if reg_name not in self.global_state['registers']:
                self.global_state['registers'][reg_name] = tmp_values.get(src_tmp)
            logger.debug(
                f"RdTmp: reg_name={reg_name}, src_tmp={src_tmp}, self.global_state['registers'][{reg_name}]={self.global_state['registers'][reg_name]}, self.taint_map[{reg_name}]={self.taint_map.get(reg_name)}")

            if src_tmp in self.tmp_to_stmt:
                src_node = self.tmp_to_stmt[src_tmp]
                node.add_dependency(src_node)
                src_node.add_dependent(node)

                # Get all dependencies
            index = node.index
            dependencies = self.get_dependencies_from_node_stmt(node)
            logger.debug(f"Dependencies for statement {stmt}: {dependencies}")
            for dep in dependencies:
                if dep.is_reg:
                    self.add_link(reg_name, 0, dep.reg_name, 0,
                                  NodeKind.REGISTER, NodeKind.REGISTER, self.global_state['registers'][reg_name],
                                  self.current_rip, self.current_instruction, dep.reg_name)
            # Get all dependents
            dependents = self.get_dependents(index)
            logger.debug(f"Dependents for statement {index}: {dependents}")

        elif isinstance(stmt.data, pyvex.expr.Const):
            self.global_state['registers'][reg_name] = stmt.data.con.value
            logger.debug(
                f"Const: reg_name={reg_name}, self.global_state['registers'][{reg_name}]={self.global_state['registers'][reg_name]}")

    def handle_store(self, stmt, tmp_values, tmp_taint, operand_map, node):
        """Handle Store statements.
        :param index:
        """
        if isinstance(stmt.data, pyvex.expr.RdTmp):
            src_tmp = stmt.data.tmp
            operand_map[src_tmp].kind = OperandKind.SOURCE
            if isinstance(stmt.addr, pyvex.expr.RdTmp):
                addr_tmp = stmt.addr.tmp
                addr = tmp_values.get(addr_tmp)
                operand_map[stmt.addr.tmp].kind = OperandKind.DESTINATION
                logger.debug(f"RdTmp addr: addr_tmp={addr_tmp}, addr={hex(addr)}")

                if addr is not None:
                    self.stack_variables[addr] = operand_map[stmt.addr.tmp]
                    if isinstance(self.stack_variables[addr].value, tuple):
                        self.stack_variables[addr].value = self.stack_variables[addr].value[0]
                    # assert(not isinstance(self.stack_variables[addr].value, tuple))
                    # logger.debug(f"Creating node for address: {hex(addr)}")
                    # node = self.create_node(hex(addr), addr, tmp_values.get(src_tmp), 0, "", NodeKind.MEMORY)  # TODO stack
                    # self.add_node_to_graph(node)

                    if tmp_taint.get(src_tmp):
                        self.taint_map[addr] = tmp_taint[src_tmp]
                    logger.debug(
                        f"Store: addr={addr}, stack_variables[{addr}]={self.stack_variables[addr].value}, self.taint_map[{addr}]={self.taint_map.get(addr)}")
            else:
                addr = stmt.addr.con.value
                logger.debug(f"Const addr: addr={addr}")
                if addr is not None:

                    self.stack_variables[addr] = operand_map[stmt.data.tmp]
                    if isinstance(self.stack_variables[addr].value, tuple):
                        self.stack_variables[addr].value = self.stack_variables[addr].value[0]
                    #assert(not isinstance(self.stack_variables[addr].value, tuple))
                    #logger.debug(f"Creating node for address: {hex(addr)}")
                    #node = self.create_node(hex(addr), addr, tmp_values.get(src_tmp), 0, "", NodeKind.MEMORY)  # TODO stack
                    #self.add_node_to_graph(node)

                    if tmp_taint.get(src_tmp):
                        self.taint_map[addr] = tmp_taint[src_tmp]
                    logger.debug(
                        f"Store: addr={addr}, stack_variables[{addr}]={self.stack_variables[addr].value}, self.taint_map[{addr}]={self.taint_map.get(addr)}")
        elif isinstance(stmt.data, pyvex.expr.Const):
            if isinstance(stmt.addr, pyvex.expr.RdTmp):
                addr_tmp = stmt.addr.tmp
                addr = tmp_values.get(addr_tmp)
                logger.debug(f"RdTmp addr: addr_tmp={addr_tmp}, addr={hex(addr)}")
            else:
                addr = stmt.addr.con.value
                logger.debug(f"Const addr: addr={addr}")
            if addr is not None:
                self.stack_variables[addr] = StackVariableOperand(OperandKind.SOURCE, addr, stmt.data.con.value,
                                                                  "unknown")
                logger.debug(
                    f"Store: addr={addr}, stack_variables[{addr}]={self.stack_variables[addr].value}, self.taint_map[{addr}]={self.taint_map.get(addr)}")
                node = self.create_node(hex(addr), addr, stmt.data.con.value, 0, "", NodeKind.MEMORY)  # TODO stack
                self.add_node_to_graph(node)
        else:
            logger.error(f"Store statement with data type {type(stmt.data)} not implemented")

    def intra_instruction_taint_analysis(self, irsb) -> Tuple[Dict[int, Any], Dict[int, Any], Dict[int, Any]]:
        """Perform intra-instruction taint analysis on the given IRSB."""
        tmp_values = {}
        tmp_taint = {}
        operand_map = {}
        logger.debug("Starting intra-instruction taint analysis")
        index = 0
        for stmt in irsb.statements:
            logger.debug(f"Processing statement: {stmt}")
            node = self.create_statement_node(stmt, index)
            if isinstance(stmt, pyvex.stmt.WrTmp):
                logger.debug(f"Handling WrTmp statement: {stmt}")
                self.handle_wr_tmp(stmt, tmp_values, tmp_taint, operand_map, node)
            elif isinstance(stmt, pyvex.stmt.Put):
                logger.debug(f"Handling Put statement: {stmt}")
                self.handle_put(stmt, tmp_values, tmp_taint, node)
            elif isinstance(stmt, pyvex.stmt.Store):
                logger.debug(f"Handling Store statement: {stmt}")
                self.handle_store(stmt, tmp_values, tmp_taint, operand_map, node)
            elif isinstance(stmt, pyvex.stmt.IMark) or isinstance(stmt, pyvex.stmt.AbiHint) or isinstance(stmt,
                                                                                                          pyvex.stmt.Exit):
                pass
            else:
                raise NotImplementedError(f"Statement {type(stmt)} not implemented")

            index += 1

        logger.debug("Completed intra-instruction taint analysis")
        return tmp_values, tmp_taint, operand_map

        # Function to process IRSB and track taint flows

    def process_irsb(self, irsb, instruction_bytes, instructions_text, taint_flows, rip):
        logger.debug(f"Processing IRSB: rip={hex(rip)}, instruction_bytes={instruction_bytes.hex()}")
        tmp_values, tmp_taint, operand_map = self.intra_instruction_taint_analysis(irsb)

        for stmt in irsb.statements:
            logger.debug(f"Processing statement for taint flow: {stmt}")
            if isinstance(stmt, pyvex.stmt.Store):
                logger.debug(f"Handling Store statement: {stmt}")
                if isinstance(stmt.data, pyvex.expr.RdTmp):
                    src_tmp = stmt.data.tmp
                    if isinstance(stmt.addr, pyvex.expr.RdTmp):
                        addr_tmp = stmt.addr.tmp
                        addr = self.get_tmp_value(addr_tmp, tmp_values)
                        logger.debug(f"RdTmp addr: addr_tmp={addr_tmp}, addr={addr}")
                    else:
                        addr = stmt.addr.con.value
                        logger.debug(f"Const addr: addr={addr}")

                    if addr is not None and addr in self.stack_variables:
                        taint_flows.append({
                            'rip': rip,
                            'src': operand_map[src_tmp].name,
                            'src_value': self.stack_variables[addr].value,
                            'dest': addr,
                            'dest_type': 'mem',
                            'instr': instructions_text
                        })
                        logger.debug(
                            f"Taint flow added: rip={hex(rip)}, src_tmp={src_tmp}, src_value={self.stack_variables[addr].value}, dest={addr}, instr={instructions_text}")
                        # Add nodes and edges to the graph
                        logger.debug(f"Adding link for memory write: {operand_map[src_tmp].name} := {hex(self.stack_variables[addr].value)}")
                        target_name = self.stack_variables[addr].name
                        instruction = " ".join(instructions_text)
                        self.add_link(target_name, addr,
                                      operand_map[src_tmp].name,
                                      operand_map[src_tmp].name,
                                      NodeKind.STACK,
                                      operand_map[src_tmp].location_kind,
                                      self.stack_variables[addr].value,
                                      rip,
                                      instruction,
                                      operand_map[src_tmp].name)
                    else:
                        logger.warning(f"Maybe missing stack variable")


    def handle_memory_read(self, mem_addr, mem_value, instr, rip, taint_flows, source_buffer, source_size):

        # Determine the number of bytes needed
        num_bytes = (mem_value.bit_length() + 7) // 8

        # Convert the integer to bytes in little endian and then back to an integer in big endian
        mem_value = int.from_bytes(mem_value.to_bytes(num_bytes, byteorder='little'), byteorder='big')

        logger.debug(f"Memory read operation at address: {mem_addr}")
        if source_buffer < mem_addr < source_buffer + source_size:
            origin = f"source+{mem_addr - source_buffer}"
            self.update_taint_map(mem_addr, mem_value, origin)
            # check if digraph contains a node named origin

            self.add_link(origin, mem_addr, "source", self.source_buffer, NodeKind.MEMORY, NodeKind.MEMORY, mem_value, rip, " ".join(instr.split()[1:]), origin)
            #self.add_link(origin, mem_value, rip, instr.split()[1:], origin)

        else:
            origin = self.get_origin(mem_addr)
            if origin:
                self.update_taint_map(mem_addr, mem_value, origin)
                #self.add_link(hex(mem_addr), mem_value, rip, instr.split()[1:], origin)
        irsb = lift.analyze_instruction(bytes.fromhex(instr.split()[0]), rip)
        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.stmt.Put):
                reg_name = lift.get_register_name(stmt.offset)
                if reg_name:
                    taint_flows.append({
                        'rip': rip,
                        'src': mem_addr,
                        'src_value': mem_value,
                        'dest': reg_name,
                        'dest_type': 'reg',
                        'instr': instr.split()[1:]
                    })
                    logger.debug(
                        f"Taint flow added: rip={rip}, src={mem_addr}, src_value={mem_value}, dest={reg_name}, instr={instr}")
                    # Add nodes and edges to the graph
                    logger.debug(f"Adding link for memory read: {hex(mem_addr)} -> {reg_name}")
                    target_name = reg_name
                    source_name = origin

                    if origin is None:
                        source_name = hex(mem_addr)

                    source_loc = mem_addr
                    current_value = mem_value
                    instruction = " ".join(instr.split()[1:])
                    self.add_link(target_name, None, source_name, source_loc, NodeKind.REGISTER, NodeKind.MEMORY, current_value, rip, instruction, origin)
                    # self.add_link(target_name, source_name, source_loc, current_value, rip, instr.split()[1:], origin)
                    # self.add_link(mem_addr, mem_value, rip, instr.split()[1:], origin)

    def handle_memory_write(self, mem_addr, instr, rip, taint_flows):
        logger.debug(f"Memory write operation at address: {mem_addr}")
        irsb = lift.analyze_instruction(bytes.fromhex(instr.split()[0]), rip)
        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.stmt.Put):
                reg_name = lift.get_register_name(stmt.offset)
                if reg_name and reg_name in self.global_state['registers']:
                    mem_value = self.global_state['registers'][reg_name]  # Use the tracked register value
                    if mem_value in self.taint_map or mem_addr in self.taint_map:
                        taint_flows.append({
                            'rip': rip,
                            'src': reg_name,
                            'src_value': mem_value,
                            'dest': mem_addr,
                            'dest_type': 'mem',
                            'instr': instr.split()[1:]
                        })
                        logger.debug(
                            f"Taint flow added: rip={rip}, src={reg_name}, src_value={mem_value}, dest={mem_addr}, instr={instr}")
                        self.update_taint_map(mem_addr, mem_value, self.get_origin(mem_value))
                        # Add nodes and edges to the graph
                        logger.debug(f"Adding link for memory write: {reg_name} -> {hex(mem_addr)}")
                        #elf.add_link(reg_name, mem_value, rip, instr.split()[1:], self.get_origin(mem_value))
                        logger.warning("TODO: check if redondant")
                        self.add_link(hex(mem_addr), mem_addr, reg_name, mem_addr, NodeKind.MEMORY, NodeKind.REGISTER, mem_value, rip, " ".join(instr.split()[1:]), self.get_origin(mem_value))
                    else:
                        logger.debug(f"Memory address {hex(mem_addr)} not tainted, skipping")
            else:
                logger.warning(f"Unsupported statement type for memory write: {stmt}")

    def handle_undetected_memory_write(self, regs, instr):
        rip = parse.extract_reg_value(regs, 'rip')
        instr_bytes = bytes.fromhex(instr.split()[0])
        irsb = lift.analyze_instruction(instr_bytes, rip)
        # extract both source and destination registers
        reg_list = [lift.arch.register_names.get(a.offset) for a in irsb.statements if hasattr(a, 'offset')]
        reg_list.extend([lift.arch.register_names.get(a.data.offset) for a in irsb.statements if
                         hasattr(a, 'data') and hasattr(a.data, 'offset')])
        # remove all registers that start with "cc":
        reg_list = list(set([reg for reg in reg_list if not reg.startswith("cc")]))
        if len(reg_list) == 1:
            new_reg_name = reg_list[0]
            if new_reg_name.startswith("ymm"):
                new_reg_name = new_reg_name.replace("ymm", "xmm")

            logger.debug(f"XOR: Updating register {new_reg_name} value: 0")
            self.global_state['registers'][new_reg_name] = 0
        elif reg_list[0] in self.global_state['registers'] and reg_list[1] in self.global_state['registers']:
            # self.global_state['registers'][regs[0]] = self.global_state['registers'][regs[1]] ^ self.global_state['registers'][regs[0]]
            # normally not needed, because we already have the updated register value provided in the trace
            # but probably a good place to have an assert
            pass
        else:
            logger.warning(f"XOR: Could not find both registers in global state: {reg_list}")

    def update_all_registers(self, regs):

        if regs:

            # finally, update register values
            # do it at the end because of operations such as movzx eax,byte ptr [rax+r9+0C40120h]
            for reg in lift.arch.register_names.values():
                reg_value = parse.extract_reg_value(regs, reg)
                if reg_value is not None:
                    logger.debug(f"Updating register {reg} value: {hex(reg_value)}")
                    self.global_state['registers'][reg] = reg_value

    def handle_initialization(self, regs, instr, line):
        if regs is None and instr is None:
            if "rax" in line:
                for reg in lift.arch.register_names.values():
                    reg_value = parse.extract_reg_value(line, reg)
                    if reg_value is not None:
                        logger.debug(f"Updating register {reg} value: {hex(reg_value)}")
                        self.global_state['registers'][reg] = reg_value
                        instruction = " ".join(line.split()[1:])
                        node = self.create_node(reg, None, reg_value, 0, instruction, NodeKind.REGISTER, None)
                        self.add_node_to_graph(node)

    def handle_instruction(self, mem_op, mem_addr, mem_value, instr, regs, rip, taint_flows, source_buffer,
                           source_size):

        if mem_op is not None and "gs:" not in instr and not "ret" in instr:
            # Analyze the instruction using PyVEX
            self.global_state['memory'][mem_addr] = mem_value
            logger.info(f"Updating global state. Memory: {mem_op} at address: {hex(mem_addr)}")

        if mem_op == 'mr':

            self.handle_memory_read(mem_addr, mem_value, instr, rip, taint_flows, source_buffer, source_size)

        elif mem_op == 'mw':

            self.handle_memory_write(mem_addr, instr, rip, taint_flows)

        if mem_op is not None or len(regs) > 1:

            # Analyze the instruction using PyVEX
            instr_bytes = bytes.fromhex(instr.split()[0])
            logger.debug(f"Instruction bytes: {instr_bytes}")
            irsb = lift.analyze_instruction(instr_bytes, rip)

            if lift.can_handle_instruction(instr, irsb):
                self.process_irsb(irsb, instr_bytes, instr.split()[1:], taint_flows, rip)
            else:
                logger.warning(f"CCall or unsupported instruction detected, skipping: {instr}")

        if mem_op is None and instr and regs and "xor" in instr and regs:
            # only rip was detected because the xor had no effect on the registers
            # however we can handle this case because we know the xor operation, if applied to the same register
            # will result in 0 and we might not have the register in the trace or we might have missed it
            # from an unsupported instruction
            self.handle_undetected_memory_write(regs, instr)

        # Function to perform taint analysis

    def taint_analysis(self, parsed_trace):

        taint_flows = []
        has_initialized = False

        for line in parsed_trace:
            regs, instr = parse.parse_line(line)
            logger.info(f"Parsed line: regs={regs}, instr={instr}"[:1024])

            self.tmp_to_stmt = {}
            self.statements = []



            if not has_initialized:
                self.handle_initialization(regs, instr, line)
                has_initialized = True

            if regs and instr:
                rip = parse.extract_reg_value(regs, 'rip')
                mem_infos = parse.extract_mem_info(regs)
                self.current_instruction = " ".join(instr.split()[1:])
                self.current_rip = rip

                mem_op, mem_addr, mem_value = None, None, None
                if len(mem_infos) > 1:
                    logger.warning(f"Multiple memory operations detected: {mem_infos}")
                    mem_op, mem_addr, mem_value = mem_infos[0]
                else:
                    mem_op, mem_addr, mem_value = mem_infos[0] if mem_infos else (None, None, None)

                logger.debug(
                    f"Processing instruction at RIP: {hex(rip)}, mem_op: {mem_op}, mem_addr: {mem_addr}, mem_value: {mem_value}")

                self.handle_instruction(mem_op, mem_addr, mem_value, instr, regs, rip, taint_flows,
                                        self.source_buffer, self.source_size)

                self.update_all_registers(regs)

                if len(mem_infos) > 1:
                    # update all memory operations
                    for mem_op, mem_addr, mem_value in mem_infos[1:]:
                        if mem_op == 'mw':
                            self.global_state['memory'][mem_addr] = mem_value

        # now the taint is complete, we can print the taint flow
        # print_taint_flow(taint_flows)

        return taint_flows

        # Function to visualize the taint flow graph

    def visualize_graph(self, layout='spring', figsize=(20, 20), node_size=500, font_size=8):
        plt.figure(figsize=figsize)

        # Create a new graph that only includes nodes with outgoing edges
        #filtered_digraph = nx.DiGraph((u, v, d) for u, v, d in self.digraph.edges(data=True) if self.digraph.out_degree(u) > 0)
        # Find the node with the name attribute "source"
        source_node = None
        for node in self.digraph.nodes(data=True):
            if node[0].name == 'source':
                source_node = node[0]
                break

        if source_node is None:
            raise ValueError("No node with the name attribute 'source' found.")

        # Get all successors of the source node
        successors = nx.descendants(self.digraph, source_node)
        successors.add(source_node)  # Include the source node itself

        # Create a subgraph with the source node and its successors
        filtered_digraph = self.digraph.subgraph(successors)


        if layout == 'spring':
            pos = nx.spring_layout(filtered_digraph)
        elif layout == 'shell':
            pos = nx.shell_layout(filtered_digraph)
        elif layout == 'circular':
            pos = nx.circular_layout(filtered_digraph)
        elif layout == 'kamada_kawai':
            pos = nx.kamada_kawai_layout(filtered_digraph)
        else:
            pos = nx.spring_layout(filtered_digraph)  # Default to spring layout

        # Convert node labels to hexadecimal if they are numbers
        hex_labels = {node: hex(node) if isinstance(node, int) else node for node in filtered_digraph.nodes()}

        # Convert edge labels to hexadecimal if they are numbers
        edge_labels = nx.get_edge_attributes(filtered_digraph, 'value')
        hex_edge_labels = {(u, v): hex(data) if isinstance(data, int) else data for (u, v), data in
                           edge_labels.items()}

        nx.draw(filtered_digraph, pos, labels=hex_labels, with_labels=True, node_size=node_size, node_color='lightblue',
                font_size=font_size, font_weight='bold')
        nx.draw_networkx_edge_labels(filtered_digraph, pos, edge_labels=hex_edge_labels, font_size=font_size)
        plt.savefig("graph.png")
        plt.show()

    def export_graph(self, filename):
        nx.write_gml(self.digraph, filename)
        logger.info(f"Graph exported to {filename}")
