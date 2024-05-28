import re
import sys


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
            #entry['value'] = int(mr_match.group(2), 16)
            entry['size'] = len(mr_match.group(2)) // 2  # Size in bytes
            value_str = mr_match.group(2)
            # Convert from little-endian to integer
            entry['value'] = int.from_bytes(bytes.fromhex(value_str), byteorder='little')

        # Parse memory write
        mw_match = re.search(r'mw=0x([0-9a-fA-F]+):([0-9a-fA-F]+)', line)
        if mw_match:
            entry['type'] = 'memory_write'
            entry['address'] = int(mw_match.group(1), 16)
            value_str = mw_match.group(2)
            # Convert from little-endian to integer
            entry['value'] = int.from_bytes(bytes.fromhex(value_str), byteorder='little')
            entry['size'] = len(mw_match.group(2)) // 2  # Size in bytes

        if entry:
            trace_entries.append(entry)

    return trace_entries


def taint_analysis(trace_entries, input_buffer_address, input_buffer_size):
    # Initialize taint map with input buffer addresses
    taint_map = {addr: {i} for i, addr in enumerate(range(input_buffer_address, input_buffer_address + input_buffer_size))}
    register_taint = {}

    for entry in trace_entries[:50]:
        rip = entry['rip']

        if entry['type'] == 'registers':
            # Update register taint information
            for reg, val in entry['registers'].items():
                if val in taint_map:
                    register_taint[reg] = taint_map[val]
                else:
                    register_taint[reg] = set()

        elif entry['type'] == 'memory_read':
            addr = entry['address']
            if addr in taint_map:
                # Propagate taint to the destination register
                for reg, val in entry['registers'].items():
                    if reg in register_taint:
                        register_taint[reg].update(taint_map[addr])
                    else:
                        register_taint[reg] = taint_map[addr]

        elif entry['type'] == 'memory_write':
            addr = entry['address']
            # Check if the source register is tainted
            for reg, val in entry['registers'].items():
                if reg in register_taint and register_taint[reg]:
                    taint_map[addr] = register_taint[reg]

    return taint_map


def run():

    with open("full_trace.txt") as f:
        full_trace = f.readlines()

    # map: address -> assembly
    address_to_assembly = {}
    for line in full_trace:
        curr_addr = "0x" + line.split()[0].replace("`", "")
        curr_assembly = " ".join(line.split()[2:])
        address_to_assembly[curr_addr] = curr_assembly

    trace_path = sys.argv[1] if len(sys.argv) > 1 else 'trace.tt'
    with open(trace_path) as f:
        trace_lines = f.readlines()

    parsed_trace = parse_trace(trace_lines)
    for entry in parsed_trace[:60]:
        memory_address = entry.get('address', 0)
        memory_value = hex(entry.get('value', 0))
        regs_str = ', '.join(f"{reg}={hex(val)}" for reg, val in entry.get('registers', {}).items())
        assembly = address_to_assembly.get(hex(entry['rip']), "") if entry.get('type', '') == 'memory_write' else ""
        print(
            f"{hex(entry['rip'])}: {entry.get('type', 'unknown')} {regs_str} {hex(memory_address)} {memory_value} {entry.get('size', '')} {assembly}")

    # Example usage with placeholder values
    input_buffer_address = 0xffff82836a9d7420  # Example address of input buffer
    input_buffer_size = 0x3aab  # Example size of input buffer

    taint_map = taint_analysis(parsed_trace[:60], input_buffer_address, input_buffer_size)
    for addr, taint in taint_map.items():
        if len(taint) > 1:
            print(f"Address: 0x{addr:x}, Taint: {taint}")


if __name__ == "__main__":

 run()