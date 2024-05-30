
from  helpers import parse
from  helpers import lift
from  helpers.operand import OperandKind, StackVariableOperand, RegisterOperand
from helpers.log import logger

import pyvex
from typing import Dict, Any, Tuple


class DataFlowAnalyzer:
    
    def __init__(self, source_buffer, source_size, global_state, taint_map):
        self.source_buffer = source_buffer
        self.source_size = source_size
        self.taint_map = taint_map
        self.global_state = global_state
        self.stack_variables = {}

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
        logger.debug(f"Updating taint map: {dest} -> ({value}, {origin})")
        self.taint_map[dest] = (value, origin)
    
    
    # Function to get the origin of a tainted value

    def get_origin(self, value):
        if value in self.taint_map:
            return self.taint_map[value][1]
        return None
    
    
    # Function to get the value of a temporary variable
    @staticmethod
    def get_tmp_value(tmp, tmp_values):
        return tmp_values.get(tmp, None)
    
    
    # Function to perform intra-instruction taint analysis
    def handle_wr_tmp(self, stmt, tmp_values, tmp_taint, operand_map):
        """Handle WrTmp statements."""
        if isinstance(stmt.data, pyvex.expr.RdTmp):
            self.handle_wr_tmp_rdtmp(stmt, tmp_values, tmp_taint, operand_map)
        elif isinstance(stmt.data, pyvex.expr.Unop):
           self.handle_wr_tmp_unop(stmt, tmp_values, tmp_taint, operand_map)
        elif isinstance(stmt.data, pyvex.expr.Load):
           self.handle_wr_tmp_load(stmt, tmp_values, tmp_taint, operand_map)
        elif isinstance(stmt.data, pyvex.expr.Get):
           self.handle_wr_tmp_get(stmt, tmp_values, tmp_taint, operand_map)
        elif isinstance(stmt.data, pyvex.expr.Const):
           self.handle_wr_tmp_const(stmt, tmp_values, tmp_taint)
        elif isinstance(stmt.data, pyvex.expr.Binop):
           self.handle_wr_tmp_binop(stmt, tmp_values, tmp_taint, operand_map)
        else:
            logger.error(f"WrTmp statement with data type {type(stmt.data)} not implemented")
    
    
    def handle_wr_tmp_rdtmp(self, stmt, tmp_values, tmp_taint, operand_map):
        """Handle WrTmp statements with RdTmp data."""
        src_tmp = stmt.data.tmp
        tmp_values[stmt.tmp] = tmp_values.get(src_tmp)
        tmp_taint[stmt.tmp] = tmp_taint.get(src_tmp)
        logger.debug(
            f"RdTmp: src_tmp={src_tmp}, tmp_values[{stmt.tmp}]={hex(tmp_values[stmt.tmp])}, tmp_taint[{stmt.tmp}]={tmp_taint[stmt.tmp]}")


    def handle_wr_tmp_unop(self, stmt, tmp_values, tmp_taint, operand_map):
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


    def handle_wr_tmp_load(self, stmt, tmp_values, tmp_taint, operand_map):
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
                operand_map[stmt.tmp] = self.stack_variables.get(addr)
        else:
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


    def handle_wr_tmp_get(self, stmt, tmp_values, tmp_taint, operand_map):
        """Handle WrTmp statements with Get data."""
        reg_name = lift.get_register_name(stmt.data.offset)
        new_tmp_value = self.global_state['registers'].get(reg_name)

        if new_tmp_value is None and reg_name == 'd' or reg_name.startswith('xmm'):

            new_tmp_value = lift.arch.get_default_reg_value('d')
            logger.warning(f"Using default value for register 'd': {hex(new_tmp_value)}")

        if new_tmp_value is None:
            logger.error(f"Get: New temp value is None, stmt={stmt}")
            raise ValueError(f"Get: New temp value is None, stmt={stmt}")

        tmp_values[stmt.tmp] = new_tmp_value
        tmp_taint[stmt.tmp] = self.taint_map.get(reg_name)
        logger.debug(
            f"Get: reg_name={reg_name}, tmp_values[{stmt.tmp}]={tmp_values[stmt.tmp]}, tmp_taint[{stmt.tmp}]={tmp_taint[stmt.tmp]}")
        if reg_name == "rsp":
            operand_map[stmt.tmp] = StackVariableOperand(OperandKind.SOURCE, tmp_values[stmt.tmp], tmp_taint[stmt.tmp],
                                                         "unknown")
        else:
            operand_map[stmt.tmp] = RegisterOperand(OperandKind.SOURCE, tmp_taint[stmt.tmp], tmp_taint[stmt.tmp], reg_name)


    def handle_wr_tmp_const(self, stmt, tmp_values, tmp_taint):
        """Handle WrTmp statements with Const data."""
        tmp_values[stmt.tmp] = stmt.data.con.value
        tmp_taint[stmt.tmp] = None
        logger.debug(
            f"Const: tmp_values[{stmt.tmp}]={tmp_values[stmt.tmp]}, tmp_taint[{stmt.tmp}]={hex(tmp_taint[stmt.tmp])}")


    def handle_wr_tmp_binop(self, stmt, tmp_values, tmp_taint, operand_map):
        """Handle WrTmp statements with Binop data."""
        arg0 = self.get_tmp_value(stmt.data.args[0].tmp, tmp_values) if isinstance(stmt.data.args[0], pyvex.expr.RdTmp) else \
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
            else:
                logger.error(f"Binop: Stack variable offset is None, stmt={stmt}")
        else:
            offset = stmt.data.args[1].con.value if isinstance(stmt.data.args[1], pyvex.expr.Const) else None
            if offset is not None:
                name = f"{operand.name}+{hex(offset)}"
                address = tmp_values.get(stmt.data.args[0].tmp) + offset
                operand_map[stmt.tmp] = RegisterOperand(OperandKind.SOURCE, address, tmp_values.get(stmt.data.args[0].tmp),
                                                        name)
                logger.debug(f"Register + offset: {name}, address={hex(address)}, pyvex_name={stmt.tmp}")


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
            else:
                logger.error(f"Binop: Stack variable offset is None, stmt={stmt}")


    def handle_binop_operations(self, stmt, tmp_values, arg0, arg1):
        """Handle Binop operations."""
        if stmt.data.op.startswith('Iop_Add') or stmt.data.op.startswith('Iop_And') or stmt.data.op.startswith(
                'Iop_Sub') or stmt.data.op.startswith('Iop_Xor') or stmt.data.op.startswith(
                'Iop_Shl') or stmt.data.op.startswith('Iop_Or') or stmt.data.op.startswith('Iop_Mul'):
            if arg0 is not None and arg1 is not None:
                size_in_bits = stmt.data.tag_int * 8
                mask = (1 << size_in_bits) - 1
                if stmt.data.op.startswith('Iop_Add'):
                    result = (arg0 + arg1) & mask
                    tmp_values[stmt.tmp] = result
                    logger.debug(f"Binop Add: tmp_values[{stmt.tmp}]={hex(arg0)}+{hex(arg1)} = {hex(tmp_values[stmt.tmp])}")
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
            else:
                logger.error(f"Binop {stmt.data.op.split('_')[1]}: One of the arguments is None, arg0={arg0}, arg1={arg1}")
        else:
            logger.error(f"Binop: Operation not handled, stmt={stmt}")


    def handle_put(self, stmt, tmp_values, tmp_taint):
        """Handle Put statements."""
        reg_name = lift.get_register_name(stmt.offset)
        if reg_name.startswith("cc"):
            logger.debug(f"Skipping condition code register: {reg_name}")
            return
        if isinstance(stmt.data, pyvex.expr.RdTmp):
            src_tmp = stmt.data.tmp
            if tmp_taint.get(src_tmp):
                self.taint_map[reg_name] = tmp_taint[src_tmp]

            if reg_name not in self.global_state['registers']:
                self.global_state['registers'][reg_name] = tmp_values.get(src_tmp)
            logger.debug(
                f"RdTmp: reg_name={reg_name}, src_tmp={src_tmp}, self.global_state['registers'][{reg_name}]={self.global_state['registers'][reg_name]}, self.taint_map[{reg_name}]={self.taint_map.get(reg_name)}")
        elif isinstance(stmt.data, pyvex.expr.Const):
            self.global_state['registers'][reg_name] = stmt.data.con.value
            logger.debug(
                f"Const: reg_name={reg_name}, self.global_state['registers'][{reg_name}]={self.global_state['registers'][reg_name]}")


    def handle_store(self, stmt, tmp_values, tmp_taint, operand_map):
        """Handle Store statements."""
        if isinstance(stmt.data, pyvex.expr.RdTmp):
            src_tmp = stmt.data.tmp
            operand_map[src_tmp].kind = OperandKind.SOURCE
            if isinstance(stmt.addr, pyvex.expr.RdTmp):
                addr_tmp = stmt.addr.tmp
                addr = tmp_values.get(addr_tmp)
                operand_map[stmt.addr.tmp].kind = OperandKind.DESTINATION
                logger.debug(f"RdTmp addr: addr_tmp={addr_tmp}, addr={hex(addr)}")
            else:
                addr = stmt.addr.con.value
                logger.debug(f"Const addr: addr={addr}")
            if addr is not None:
                self.stack_variables[addr] = StackVariableOperand(OperandKind.SOURCE, addr, tmp_values.get(src_tmp), "unknown")
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
                self.stack_variables[addr] = StackVariableOperand(OperandKind.SOURCE, addr, stmt.data.con.value, "unknown")
                logger.debug(
                    f"Store: addr={addr}, stack_variables[{addr}]={self.stack_variables[addr].value}, self.taint_map[{addr}]={self.taint_map.get(addr)}")
        else:
            logger.error(f"Store statement with data type {type(stmt.data)} not implemented")


    def intra_instruction_taint_analysis(self, irsb)-> Tuple[Dict[int, Any], Dict[int, Any], Dict[int, Any]]:
        """Perform intra-instruction taint analysis on the given IRSB."""
        tmp_values = {}
        tmp_taint = {}
        operand_map = {}
        logger.debug("Starting intra-instruction taint analysis")

        for stmt in irsb.statements:
            logger.debug(f"Processing statement: {stmt}")
            if isinstance(stmt, pyvex.stmt.WrTmp):
                logger.debug(f"Handling WrTmp statement: {stmt}")
                self.handle_wr_tmp(stmt, tmp_values, tmp_taint, operand_map)
            elif isinstance(stmt, pyvex.stmt.Put):
                logger.debug(f"Handling Put statement: {stmt}")
                self.handle_put(stmt, tmp_values, tmp_taint)
            elif isinstance(stmt, pyvex.stmt.Store):
                logger.debug(f"Handling Store statement: {stmt}")
                self.handle_store(stmt, tmp_values, tmp_taint, operand_map)
            elif isinstance(stmt, pyvex.stmt.IMark) or isinstance(stmt, pyvex.stmt.AbiHint) or isinstance(stmt,
                                                                                                          pyvex.stmt.Exit):
                pass
            else:
                raise NotImplementedError(f"Store statement with data type {type(stmt)} not implemented")

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
                            f"Taint flow added: rip={rip}, src_tmp={src_tmp}, src_value={self.stack_variables[addr].value}, dest={addr}, instr={instructions_text}")


    def handle_memory_read(self, mem_addr, mem_value, instr, rip, taint_flows, source_buffer, source_size):
        logger.debug(f"Memory read operation at address: {mem_addr}")
        if source_buffer <= mem_addr < source_buffer + source_size:
            origin = f"{mem_addr - source_buffer} (byte offset in source buffer)"
            self.update_taint_map(mem_addr, mem_value, origin)
        else:
            origin = self.get_origin(mem_addr)
            if origin:
                self.update_taint_map(mem_addr, mem_value, origin)
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
                    else:
                        logger.debug(f"Memory address {hex(mem_addr)} not tainted, skipping")


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


    def handle_instruction(self, mem_op, mem_addr, mem_value, instr, regs, rip, taint_flows, source_buffer, source_size):

        if mem_op is not None and "gs:" not in instr and not "ret" in instr:
            # Analyze the instruction using PyVEX
            self.global_state['memory'][mem_addr] = mem_value
            logger.info(f"Updating global state. Memory: {mem_op} at address: {hex(mem_addr)}")

        if mem_op == 'mr':

           self.handle_memory_read(mem_addr, mem_value, instr, rip, taint_flows, source_buffer, source_size)

        elif mem_op == 'mw':

           self.handle_memory_write(mem_addr, instr, rip, taint_flows)

        if mem_op is not None:

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

            if not has_initialized:
                self.handle_initialization(regs, instr, line)
                has_initialized = True

            if regs and instr:
                rip = parse.extract_reg_value(regs, 'rip')
                mem_infos = parse.extract_mem_info(regs)

                mem_op, mem_addr, mem_value = None, None, None
                if len(mem_infos) > 1:
                    logger.warning(f"Multiple memory operations detected: {mem_infos}")
                    mem_op, mem_addr, mem_value = mem_infos[0]
                else:
                    mem_op, mem_addr, mem_value = mem_infos[0] if mem_infos else (None, None, None)

                logger.debug(
                    f"Processing instruction at RIP: {hex(rip)}, mem_op: {mem_op}, mem_addr: {mem_addr}, mem_value: {mem_value}")

                self.handle_instruction(mem_op, mem_addr, mem_value, instr, regs, rip, taint_flows, self.source_buffer, self.source_size)

                self.update_all_registers(regs)

                if len(mem_infos) > 1:
                    # update all memory operations
                    for mem_op, mem_addr, mem_value in mem_infos[1:]:
                        if mem_op == 'mw':
                            self.global_state['memory'][mem_addr] = mem_value

        # now the taint is complete, we can print the taint flow
        #print_taint_flow(taint_flows)

        return taint_flows