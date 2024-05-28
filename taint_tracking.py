import re
import sys
import pyvex
import archinfo

def parse_trace(trace_lines):
    trace_entries = []

    for line in trace_lines:
        entry = {}

        # Parse the instruction pointer
        rip_match = re.search(r'rip=0x([0-9a-fA-F]+)', line)
        if rip_match:
            entry['rip'] = int(rip_match.group(1), 16)

        # Parse register state
        registers = re.findall(r'(\w+)=0x([0-9a-fA-F]+)', line)
        if registers:
            entry['type'] = 'registers'
            entry['registers'] = {reg: int(val, 16) for reg, val in registers}

        # Parse memory read
        mr_match = re.search(r'mr=0x([0-9a-fA-F]+):([0-9a-fA-F]+)', line)
        if mr_match:
            entry['type'] = 'memory_read'
            entry['address'] = int(mr_match.group(1), 16)
            entry['value'] = int(mr_match.group(2), 16)
            entry['size'] = len(mr_match.group(2)) // 2  # Size in bytes

        # Parse memory write
        mw_match = re.search(r'mw=0x([0-9a-fA-F]+):([0-9a-fA-F]+)', line)
        if mw_match:
            entry['type'] = 'memory_write'
            entry['address'] = int(mw_match.group(1), 16)
            entry['value'] = int(mw_match.group(2), 16)
            entry['size'] = len(mw_match.group(2)) // 2  # Size in bytes

        if entry:
            trace_entries.append(entry)

    return trace_entries

def lift_and_analyze_instruction(instruction_bytes, address):
    arch = archinfo.ArchAMD64()
    irsb = pyvex.lift(instruction_bytes, address, arch)
    return irsb

def extract_memory_operations(irsb):
    memory_operations = []

    for stmt in irsb.statements:
        if isinstance(stmt, pyvex.IRStmt.Store):
            # Memory write operation
            addr = stmt.addr
            data = stmt.data
            memory_operations.append(('write', addr, data))
        elif isinstance(stmt, pyvex.IRStmt.LoadG):
            # Memory read operation
            addr = stmt.addr
            data = stmt.data
            memory_operations.append(('read', addr, data))
        elif isinstance(stmt, pyvex.IRStmt.WrTmp):
            if isinstance(stmt.data, pyvex.expr.Load):
                # Memory read operation
                addr = stmt.data.addr
                data = stmt.tmp
                memory_operations.append(('read', addr, data))

    return memory_operations

def get_register_name(offset):
    reg_map = {
        16: 'rax', 24: 'rbx', 32: 'rcx', 40: 'rdx',
        48: 'rsi', 56: 'rdi', 64: 'rbp', 72: 'rsp',
        80: 'r8', 88: 'r9', 96: 'r10', 104: 'r11',
        112: 'r12', 120: 'r13', 128: 'r14', 136: 'r15'
    }
    return reg_map.get(offset, None)

def log_taint_update(location, taint_set, rip, operation):
    if taint_set:
        print(f"[RIP 0x{rip:x}] {operation} - Taint update at {location}: {taint_set}")

def taint_analysis(trace_entries, input_buffer_address, input_buffer_size):
    # Initialize taint map with input buffer addresses
    taint_map = {addr: {i} for i, addr in enumerate(range(input_buffer_address, input_buffer_address + input_buffer_size))}
    register_taint = {}

    for entry in trace_entries:
        rip = entry['rip']

        if entry['type'] == 'registers':
            # Update register taint information
            for reg, val in entry['registers'].items():
                if val in taint_map:
                    register_taint[reg] = taint_map[val].copy()
                else:
                    register_taint[reg] = set()
                log_taint_update(f"register {reg}", register_taint[reg], rip, "register update")

        elif entry['type'] == 'memory_read':
            addr = entry['address']
            if addr in taint_map:
                # Propagate taint to the destination register
                for reg, val in entry['registers'].items():
                    if reg in register_taint:
                        register_taint[reg].update(taint_map[addr])
                    else:
                        register_taint[reg] = taint_map[addr].copy()
                    log_taint_update(f"register {reg} from memory {hex(addr)}", register_taint[reg], rip, "memory read")

        elif entry['type'] == 'memory_write':
            addr = entry['address']
            # Lift the instruction and analyze it to find the source register
            instruction_bytes = bytes.fromhex(entry.get('instruction', ''))
            if instruction_bytes:
                irsb = lift_and_analyze_instruction(instruction_bytes, rip)
                mem_ops = extract_memory_operations(irsb)

                for op_type, mem_addr, data in mem_ops:
                    if op_type == 'write' and isinstance(mem_addr, pyvex.expr.Const) and mem_addr.con.value == addr:
                        if isinstance(data, pyvex.expr.RdTmp):
                            data_tmp = data.tmp
                            for stmt in irsb.statements:
                                if isinstance(stmt, pyvex.IRStmt.WrTmp) and stmt.tmp == data_tmp:
                                    if isinstance(stmt.data, pyvex.expr.RdTmp):
                                        src_tmp = stmt.data.tmp
                                        for stmt2 in irsb.statements:
                                            if isinstance(stmt2, pyvex.IRStmt.WrTmp) and stmt2.tmp == src_tmp:
                                                if isinstance(stmt2.data, pyvex.expr.Get):
                                                    src_reg = stmt2.data.offset
                                                    reg_name = get_register_name(src_reg)
                                                    if reg_name and reg_name in register_taint:
                                                        if addr in taint_map:
                                                            taint_map[addr].update(register_taint[reg_name])
                                                        else:
                                                            taint_map[addr] = register_taint[reg_name].copy()
                                                        log_taint_update(f"memory {hex(addr)} from register {reg_name}", taint_map[addr], rip, "memory write")

    return taint_map

def format_taint_map(taint_map):
    formatted_taint = []
    for addr, taint in taint_map.items():

        taint_chain = " -> ".join(f"input[{i}]" for i in sorted(taint))
        formatted_taint.append(f"Address 0x{addr:x}: {taint_chain}")
    return "\n".join(formatted_taint)

def run():
    with open("full_trace.txt") as f:
        full_trace = f.readlines()

    # map: address -> assembly
    address_to_assembly = {}
    for line in full_trace:
        curr_addr = "0x" + line.split()[0].replace("`", "")
        #curr_assembly = " ".join(line.split()[2:])
        curr_assembly = line.split()[1]
        address_to_assembly[curr_addr] = curr_assembly

    trace_path = sys.argv[1] if len(sys.argv) > 1 else 'trace.tt'
    with open(trace_path) as f:
        trace_lines = f.readlines()

    parsed_trace = parse_trace(trace_lines[:60])
    for entry in parsed_trace[:60]:
        memory_address = entry.get('address', 0)
        memory_value = hex(entry.get('value', 0))
        regs_str = ', '.join(f"{reg}={hex(val)}" for reg, val in entry.get('registers', {}).items())
        assembly = address_to_assembly.get(hex(entry['rip']), "")# if entry.get('type', '') == 'memory_write' else ""
        print(
            f"{hex(entry['rip'])}: {entry.get('type', 'unknown')} {regs_str} {hex(memory_address)} {memory_value} {entry.get('size', '')} {assembly}")
        entry['instruction'] = assembly

    # Example usage with placeholder values
    input_buffer_address = 0xffff82836a9d7420  # Example address of input buffer
    input_buffer_size = 0x3aab  # Example size of input buffer

    taint_map = taint_analysis(parsed_trace, input_buffer_address, input_buffer_size)
    formatted_taint = format_taint_map(taint_map)
    print("Taint Map:")
    print(formatted_taint)

if __name__ == "__main__":
    run()