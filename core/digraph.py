import networkx as nx
import matplotlib.pyplot as plt


def print_edges_from_source(G, source_buffer):
    source_str = f"{hex(source_buffer)} (memory)"
    if source_str in G:
        print(f"Taint flow starting from source buffer {source_str}:\n")
        for edge in nx.edge_dfs(G, source_str):
            src, dest = edge
            data = G.get_edge_data(src, dest)
            print(f"Instruction Pointer: {hex(data['rip'])}")
            print(f"  {src} --[{data['value']}]--> {dest}")
            print(f"    Instruction: {data['instr']}\n")

def build_taint_digraph(taint_flows, source_buffer, source_size):
    G = nx.DiGraph()
    taint_map = {}

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

        hex_src_value = hex(src_value) if isinstance(src_value, int) else src_value

        # Check if the source is within the source buffer range
        if isinstance(src, int) and source_buffer <= src < source_buffer + source_size:
            taint_map[dest] = src
            G.add_edge(src_str, dest_str, value=hex_src_value, instr=instr, rip=rip)
        elif src in taint_map:
            taint_map[dest] = src
            G.add_edge(src_str, dest_str, value=hex_src_value, instr=instr, rip=rip)

    return G
def plot(G):
    pos = nx.nx_agraph.graphviz_layout(G, prog='dot')
    plt.figure(figsize=(98, 48))
    nx.draw(G, pos, with_labels=True, node_size=3000, node_color="lightblue", font_size=10, font_weight="bold",
            arrows=True)
    edge_labels = nx.get_edge_attributes(G, 'value')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)
    plt.title("Taint Flow Graph")
    plt.show()