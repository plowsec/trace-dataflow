import unittest
from unittest.mock import patch, mock_open
from main import taint_analysis, source_buffer, source_size

class TestTaintAnalysis(unittest.TestCase):

    def test_taint_analysis(self):
        # Expected output
        expected_output = [
            {'rip': 18446735283850065508, 'src': 18446606099673871392, 'src_value': 8124727833055526912, 'dest': 'rax', 'dest_type': 'reg', 'instr': ['mov', 'rax,qword', 'ptr', '[rsp+0A0h]']},
            {'rip': 18446735283850065513, 'src': 'rax', 'src_value': 2074114048112, 'dest': 18446606099673871280, 'dest_type': 'mem', 'instr': ['mov', 'qword', 'ptr', '[rsp+30h],rax']},
            {'rip': 18446735283850065669, 'src': 18446606099673871280, 'src_value': 8124727833055526912, 'dest': 'r8', 'dest_type': 'reg', 'instr': ['mov', 'r8,qword', 'ptr', '[rsp+220h]']},
            {'rip': 18446735283850065677, 'src': 'r8', 'src_value': 2074114048112, 'dest': 18446606099673871368, 'dest_type': 'mem', 'instr': ['mov', 'qword', 'ptr', '[rsp+90h],r8']}
        ]
        with open('test_trace2.txt', 'r') as file:
            parsed_trace = file.readlines()

        output = taint_analysis(parsed_trace, source_buffer, source_size)

        # Compare the output with the expected output
        self.assertEqual(output, expected_output)

if __name__ == '__main__':
    unittest.main()