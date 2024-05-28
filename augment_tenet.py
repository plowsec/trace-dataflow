import re


def parse_trace_tt(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    trace_entries = []
    for line in lines:
        line = line.strip()
        if line:
            trace_entries.append(line)

    return trace_entries


def parse_full_trace(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    full_trace = []
    for line in lines:
        line = line.strip()
        if line:
            parts = re.split(r'\s+', line, maxsplit=2)
            if len(parts) == 3:
                address, opcode, instruction = parts
                full_trace.append((address, opcode, instruction))

    return full_trace


def create_rip_mapping(trace_entries, full_trace):
    rip_mapping = {}
    for i in range(1, len(full_trace)):
        current_address = full_trace[i][0]
        previous_instruction = full_trace[i - 1]
        rip_mapping[current_address] = previous_instruction

    return rip_mapping


def add_disassembly_to_trace(trace_entries, rip_mapping):
    updated_trace = []
    for entry in trace_entries:
        match = re.search(r'rip=0x([0-9a-fA-F]+)', entry)
        if match:
            rip = match.group(1)
            rip_key = f"fffff801`{rip[-8:]}"  # Format the rip to match the full_trace format
            if rip_key in rip_mapping:
                opcode, instruction = rip_mapping[rip_key][1], rip_mapping[rip_key][2]
                updated_entry = f"{entry} | {opcode} {instruction}"
                updated_trace.append(updated_entry)
            else:
                updated_trace.append(entry)
        else:
            updated_trace.append(entry)

    return updated_trace


def write_updated_trace(file_path, updated_trace):
    with open(file_path, 'w') as file:
        for entry in updated_trace:
            file.write(entry + '\n')


def main():
    trace_tt_path = 'trace.tt'
    full_trace_path = 'full_trace.txt'

    trace_entries = parse_trace_tt(trace_tt_path)
    full_trace = parse_full_trace(full_trace_path)
    rip_mapping = create_rip_mapping(trace_entries, full_trace)
    updated_trace = add_disassembly_to_trace(trace_entries, rip_mapping)
    write_updated_trace('updated_trace.tt', updated_trace)


if __name__ == "__main__":
    main()