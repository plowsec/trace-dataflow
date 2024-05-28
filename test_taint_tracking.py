import unittest
from taint_tracking import parse_trace, taint_analysis, format_taint_map

# Mock trace content
mock_trace_content = """
rip=0x1000,rax=0x2000,rbx=0x3000,rcx=0x4000,rdx=0x5000
rip=0x1001,rax=0x1234,mr=0x2000:0x1234
rip=0x1002,mw=0x3000:0x1234
rip=0x1003,rax=0x3000
"""

class TestTaintAnalysis(unittest.TestCase):
    def setUp(self):
        # Create a mock trace file
        self.trace_lines = mock_trace_content.strip().split('\n')

    def test_taint_analysis(self):
        # Parse the trace
        parsed_trace = parse_trace(self.trace_lines)
        for entry in parsed_trace:
            if entry['type'] == 'memory_read':
                entry['instruction'] = "c644245001"
            elif entry['type'] == 'memory_write':
                entry['instruction'] = "8b8424a8000000"
            else:
                entry['instruction'] = "9090"

        # Define input buffer address and size
        input_buffer_address = 0x2000
        input_buffer_size = 0x10  # Example size of input buffer

        # Perform taint analysis
        taint_map = taint_analysis(parsed_trace, input_buffer_address, input_buffer_size)

        # Format the taint map for human-friendly output
        formatted_taint = format_taint_map(taint_map)

        # Expected taint map output
        expected_taint_map = {
            0x2000: {0},
            0x2001: {1},
            0x2002: {2},
            0x2003: {3},
            0x2004: {4},
            0x2005: {5},
            0x2006: {6},
            0x2007: {7},
            0x2008: {8},
            0x2009: {9},
            0x200a: {10},
            0x200b: {11},
            0x200c: {12},
            0x200d: {13},
            0x200e: {14},
            0x200f: {15},
            0x3000: {0}  # Memory at 0x3000 should be tainted by input[0]
        }

        # Verify the taint map
        for addr, taint in expected_taint_map.items():
            self.assertIn(addr, taint_map)
            self.assertEqual(taint_map[addr], taint)

        # Print the formatted taint map
        print("Formatted Taint Map:")
        print(formatted_taint)

if __name__ == '__main__':
    unittest.main()