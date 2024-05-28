import re
import pyvex
import archinfo
import logging

# Configure logging
fmt = '%(asctime)s | %(levelname)3s | [%(filename)s:%(lineno)3d] %(funcName)s() | %(message)s'
datefmt = '%Y-%m-%d %H:%M:%S'  # Date format without milliseconds

class CustomFormatter(logging.Formatter):

    COLOR_CODES = {
        'DEBUG': '\033[36m',  # Cyan
        'INFO': '\033[35m',  # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',  # Red
        'CRITICAL': '\033[41m',  # Red background
        'RESET': '\033[0m'  # Reset to default
    }
    def format(self, record):
        color_code = self.COLOR_CODES.get(record.levelname, self.COLOR_CODES['RESET'])
        record.msg = f"{color_code}{record.msg}{self.COLOR_CODES['RESET']}"
        return super().format(record)


logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(CustomFormatter(fmt, datefmt))
logger.addHandler(handler)

# Add a file handler to the logger
file_handler = logging.FileHandler('logfile.log')
file_handler.setFormatter(CustomFormatter(fmt, datefmt))
logger.addHandler(file_handler)

logger.setLevel(logging.DEBUG)

# Define the source buffer and its size
source_buffer = 0xffff82836a9d7420
source_size = 0x3aab

# Define a dictionary to track tainted values and their origins
# Example taint map
taint_map = {
    'rsp': (0xffff82836a9d7380, "source")
}

# Initialize the architecture
arch = archinfo.ArchAMD64()

# Global state for register values and stack offsets
# Example global state and taint map for testing
global_state = {
    'registers': {
        'rax': 2074114048112,
        'rsp': 18446606099673871232,
    },
    'stack': {}
}

class StackVariable:
    def __init__(self, address, value):
        self.address = address
        self.value = value

stack_variables = {}

# Function to get the register name from the offset using archinfo
def get_register_name(offset):
    return arch.register_names.get(offset, None)

# Function to extract memory read/write information
def extract_mem_info(regs):
    logger.debug(f"Extracting memory info from: {regs}")
    mem_info = re.search(r'(mr|mw)=(0x[0-9a-fA-F]+):([0-9a-fA-F]+)', regs)
    if mem_info:
        logger.debug(f"Memory operation found: {mem_info.groups()}")
        return mem_info.group(1), int(mem_info.group(2), 16), int(mem_info.group(3), 16)
    logger.debug("No memory operation found.")
    return None, None, None

# Function to parse a line from the trace
def parse_line(line):
    parts = line.split('|')
    if len(parts) == 2:
        regs, instr = parts
        instr = instr.strip()
        return regs.strip(), instr
    return None, None

# Function to extract register values
def extract_reg_value(regs, reg_name):
    match = re.search(rf'{reg_name}=(0x[0-9a-fA-F]+)', regs)
    if match:
        return int(match.group(1), 16)
    return None

# Function to update the taint map
def update_taint_map(dest, value, origin):
    logger.debug(f"Updating taint map: {dest} -> ({value}, {origin})")
    taint_map[dest] = (value, origin)

# Function to get the origin of a tainted value
def get_origin(value):
    if value in taint_map:
        return taint_map[value][1]
    return None

# Function to lift an instruction to VEX IR and analyze it
def analyze_instruction(instr_bytes, rip):
    logger.debug(f"Lifting instruction at RIP: {hex(rip)}")
    arch = archinfo.ArchAMD64()
    irsb = pyvex.lift(instr_bytes, rip, arch)
    return irsb

# Function to get the value of a temporary variable
def get_tmp_value(tmp, tmp_values):
    return tmp_values.get(tmp, None)

# Function to perform intra-instruction taint analysis
def intra_instruction_taint_analysis(irsb):
    tmp_values = {}
    tmp_taint = {}

    logger.debug("Starting intra-instruction taint analysis")

    for stmt in irsb.statements:
        logger.debug(f"Processing statement: {stmt}")

        if isinstance(stmt, pyvex.stmt.WrTmp):
            logger.debug(f"Handling WrTmp statement: {stmt}")
            if isinstance(stmt.data, pyvex.expr.RdTmp):
                src_tmp = stmt.data.tmp
                tmp_values[stmt.tmp] = tmp_values.get(src_tmp)
                tmp_taint[stmt.tmp] = tmp_taint.get(src_tmp)
                logger.debug(f"RdTmp: src_tmp={src_tmp}, tmp_values[{stmt.tmp}]={hex(tmp_values[stmt.tmp])}, tmp_taint[{stmt.tmp}]={tmp_taint[stmt.tmp]}")
            elif isinstance(stmt.data, pyvex.expr.Get):
                reg_name = get_register_name(stmt.data.offset)
                tmp_values[stmt.tmp] = global_state['registers'].get(reg_name)
                tmp_taint[stmt.tmp] = taint_map.get(reg_name)
                logger.debug(f"Get: reg_name={reg_name}, tmp_values[{stmt.tmp}]={tmp_values[stmt.tmp]}, tmp_taint[{stmt.tmp}]={tmp_taint[stmt.tmp]}")
            elif isinstance(stmt.data, pyvex.expr.Const):
                tmp_values[stmt.tmp] = stmt.data.con.value
                tmp_taint[stmt.tmp] = None
                logger.debug(f"Const: tmp_values[{stmt.tmp}]={tmp_values[stmt.tmp]}, tmp_taint[{stmt.tmp}]={hex(tmp_taint[stmt.tmp])}")
            elif isinstance(stmt.data, pyvex.expr.Binop):
                if stmt.data.op.startswith('Iop_Add'):
                    arg0 = get_tmp_value(stmt.data.args[0].tmp, tmp_values)
                    arg1 = stmt.data.args[1].con.value if isinstance(stmt.data.args[1], pyvex.expr.Const) else get_tmp_value(stmt.data.args[1].tmp, tmp_values)
                    if arg0 is not None and arg1 is not None:
                        tmp_values[stmt.tmp] = arg0 + arg1
                        logger.debug(f"Binop Add: tmp_values[{stmt.tmp}]={tmp_values[stmt.tmp]}")
                    else:
                        logging.error(f"Binop Add: One of the arguments is None, arg0={arg0}, arg1={arg1}")
                else:
                    logger.debug(f"Binop: Not handled, stmt={stmt}")

        elif isinstance(stmt, pyvex.stmt.Put):
            logger.debug(f"Handling Put statement: {stmt}")
            reg_name = get_register_name(stmt.offset)
            if isinstance(stmt.data, pyvex.expr.RdTmp):
                src_tmp = stmt.data.tmp
                #logger.debug(f"Updating register {reg_name} with value from temp {hex(src_tmp)}")
                #global_state['registers'][reg_name] = tmp_values.get(src_tmp)
                if tmp_taint.get(src_tmp):
                    taint_map[reg_name] = tmp_taint[src_tmp]
                logger.debug(f"RdTmp: reg_name={reg_name}, src_tmp={src_tmp}, global_state['registers'][{reg_name}]={global_state['registers'][reg_name]}, taint_map[{reg_name}]={taint_map.get(reg_name)}")
            elif isinstance(stmt.data, pyvex.expr.Const):
                logger.debug(f"Updating register {reg_name} with value from temp {hex(stmt.data.con.value)}")
                global_state['registers'][reg_name] = stmt.data.con.value
                logger.debug(f"Const: reg_name={reg_name}, global_state['registers'][{reg_name}]={global_state['registers'][reg_name]}")

        elif isinstance(stmt, pyvex.stmt.Store):
            logger.debug(f"Handling Store statement: {stmt}")
            if isinstance(stmt.data, pyvex.expr.RdTmp):
                src_tmp = stmt.data.tmp
                if isinstance(stmt.addr, pyvex.expr.RdTmp):
                    addr_tmp = stmt.addr.tmp
                    addr = tmp_values.get(addr_tmp)
                    logger.debug(f"RdTmp addr: addr_tmp={addr_tmp}, addr={addr}")
                else:
                    addr = stmt.addr.con.value
                    logger.debug(f"Const addr: addr={addr}")

                if addr is not None:
                    stack_variables[addr] = StackVariable(addr, tmp_values.get(src_tmp))
                    if tmp_taint.get(src_tmp):
                        taint_map[addr] = tmp_taint[src_tmp]
                    logger.debug(f"Store: addr={addr}, stack_variables[{addr}]={stack_variables[addr].value}, taint_map[{addr}]={taint_map.get(addr)}")

    logger.debug("Completed intra-instruction taint analysis")
    return tmp_values, tmp_taint

# Function to process IRSB and track taint flows
def process_irsb(irsb, instruction_bytes, taint_flows, rip):
    logger.debug(f"Processing IRSB: rip={hex(rip)}, instruction_bytes={instruction_bytes.hex()}")
    tmp_values, tmp_taint = intra_instruction_taint_analysis(irsb)

    for stmt in irsb.statements:
        logger.debug(f"Processing statement for taint flow: {stmt}")
        if isinstance(stmt, pyvex.stmt.Store):
            logger.debug(f"Handling Store statement: {stmt}")
            if isinstance(stmt.data, pyvex.expr.RdTmp):
                src_tmp = stmt.data.tmp
                if isinstance(stmt.addr, pyvex.expr.RdTmp):
                    addr_tmp = stmt.addr.tmp
                    addr = get_tmp_value(addr_tmp, tmp_values)
                    logger.debug(f"RdTmp addr: addr_tmp={addr_tmp}, addr={addr}")
                else:
                    addr = stmt.addr.con.value
                    logger.debug(f"Const addr: addr={addr}")

                if addr is not None and addr in stack_variables:
                    taint_flows.append({
                        'rip': rip,
                        'src': src_tmp,
                        'src_value': stack_variables[addr].value,
                        'dest': addr,
                        'dest_type': 'mem',
                        'instr': instruction_bytes.hex()
                    })
                    logger.debug(f"Taint flow added: rip={rip}, src_tmp={src_tmp}, src_value={stack_variables[addr].value}, dest={addr}, instr={instruction_bytes.hex()}")








# Function to perform taint analysis
def taint_analysis(parsed_trace, source_buffer, source_size):
    taint_flows = []
    for line in parsed_trace:
        regs, instr = parse_line(line)
        logger.info(f"Parsed line: regs={regs}, instr={instr}")
        if regs and instr:
            rip = extract_reg_value(regs, 'rip')
            mem_op, mem_addr, mem_value = extract_mem_info(regs)
            logger.debug(
                f"Processing instruction at RIP: {hex(rip)}, mem_op: {mem_op}, mem_addr: {mem_addr}, mem_value: {mem_value}")

            # update register values
            for reg in arch.register_names.values():
                reg_value = extract_reg_value(regs, reg)
                if reg_value is not None:
                    logger.debug(f"Updating register {reg} value: {hex(reg_value)}")
                    global_state['registers'][reg] = reg_value
            if mem_op == 'mr':
                logger.debug(f"Memory read operation at address: {mem_addr}")
                if source_buffer <= mem_addr < source_buffer + source_size:
                    origin = f"{mem_addr - source_buffer} (byte offset in source buffer)"
                    update_taint_map(mem_addr, mem_value, origin)
                else:
                    origin = get_origin(mem_addr)
                    if origin:
                        update_taint_map(mem_addr, mem_value, origin)
                irsb = analyze_instruction(bytes.fromhex(instr.split()[0]), rip)
                for stmt in irsb.statements:
                    if isinstance(stmt, pyvex.stmt.Put):
                        reg_name = get_register_name(stmt.offset)
                        if reg_name:
                            taint_flows.append({
                                'rip': rip,
                                'src': mem_addr,
                                'src_value': mem_value,
                                'dest': reg_name,
                                'dest_type': 'reg',
                                'instr': instr
                            })
                            global_state['registers'][reg_name] = mem_value  # Update register value
            elif mem_op == 'mw':
                logger.debug(f"Memory write operation at address: {mem_addr}")
                irsb = analyze_instruction(bytes.fromhex(instr.split()[0]), rip)
                for stmt in irsb.statements:
                    if isinstance(stmt, pyvex.stmt.Put):
                        reg_name = get_register_name(stmt.offset)
                        if reg_name and reg_name in global_state['registers']:
                            mem_value = global_state['registers'][reg_name]  # Use the tracked register value
                            taint_flows.append({
                                'rip': rip,
                                'src': reg_name,
                                'src_value': mem_value,
                                'dest': mem_addr,
                                'dest_type': 'mem',
                                'instr': instr
                            })
                            update_taint_map(mem_addr, mem_value, get_origin(mem_value))

            if mem_op is not None:
                # Analyze the instruction using PyVEX
                instr_bytes = bytes.fromhex(instr.split()[0])
                logger.debug(f"Instruction bytes: {instr_bytes}")
                irsb = analyze_instruction(instr_bytes, rip)
                process_irsb(irsb, instr_bytes, taint_flows, rip)


    print_taint_flow(taint_flows)

# Function to print the taint flow in the desired format
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

if __name__ == "__main__":
    # Read the augmented trace file
    with open('test_trace2.txt', 'r') as file:
        parsed_trace = file.readlines()

    taint_analysis(parsed_trace, source_buffer, source_size)