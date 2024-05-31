import json

from core import digraph
from core import dataflow


def run():

    # Define the source buffer and its size
    source_buffer = 0xffff82836a9d7420
    source_size = 0x3aab

    # Define a dictionary to track tainted values and their origins
    taint_map = {
        'rsp': (0xffff82836a9d7380, "source")
    }

    # Global state for register values and stack offsets
    global_state = {
        'registers': {
            'rax': 2074114048112,
            'rsp': 18446606099673871232,
        },
        'stack': {},
        'memory': {}
    }

    df = dataflow.DataFlowAnalyzer(source_buffer, source_size, global_state, taint_map)
    taint_flows = df.taint_analysis(parsed_trace)
    df.visualize_graph(layout='kamada_kawai', figsize=(30, 30), node_size=700, font_size=10)



    df.export_graph("test_graph.png")

    with open('taint_flows.json', 'w') as f:
        json.dump(taint_flows, f, indent=4)
    G = digraph.build_taint_digraph(taint_flows, source_buffer, source_size)
    digraph.print_edges_from_source(G, source_buffer)



if __name__ == "__main__":
    # Read the augmented trace file
    #with open('updated_trace.tt', 'r') as file:
    with open('tests/test_trace2.txt', 'r') as file:
        parsed_trace = file.readlines()

    run()