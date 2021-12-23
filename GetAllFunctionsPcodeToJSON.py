# Retrieves the sequence of PCode ops for each function, and organizes these lists
# into a JSON file
#
# @category colemankane
#
# Use the Python json library
import json

# Add the Python argument parser
from argparse import ArgumentParser

# Import some of the Ghidra classes we will be using
from ghidra.util.task import ConsoleTaskMonitor

# Map each Ghidra PCode op to a unique byte value
pcode_maps = {
	'BOOL_AND': 'A',
	'BOOL_NEGATE': 'B',
	'BOOL_OR': 'C',
	'BOOL_XOR': 'D',
	'BRANCH': 'E',
	'BRANCHIND': 'F',
	'CALL': 'G',
	'CALLIND': 'H',
	'CALLOTHER': 'I',
	'CAST': 'J',
	'CBRANCH': 'K',
	'COPY': 'L',
	'CPOOLREF': 'M',
	'EXTRACT': 'N',
	'FLOAT_ABS': 'O',
	'FLOAT_ADD': 'P',
	'FLOAT_CEIL': 'Q',
	'FLOAT_DIV': 'R',
	'FLOAT_EQUAL': 'S',
	'FLOAT_FLOAT2FLOAT': 'T',
	'FLOAT_FLOOR': 'U',
	'FLOAT_INT2FLOAT': 'V',
	'FLOAT_LESS': 'W',
	'FLOAT_LESSEQUAL': 'X',
	'FLOAT_MULT': 'Y',
	'FLOAT_NAN': 'Z',
	'FLOAT_NEG': 'a',
	'FLOAT_NOTEQUAL': 'b',
	'FLOAT_ROUND': 'c',
	'FLOAT_SQRT': 'd',
	'FLOAT_SUB': 'e',
	'FLOAT_TRUNC': 'f',
	'INDIRECT': 'g',
	'INSERT': 'h',
	'INT_2COMP': 'i',
	'INT_ADD': 'j',
	'INT_AND': 'k',
	'INT_CARRY': 'l',
	'INT_DIV': 'm',
	'INT_EQUAL': 'n',
	'INT_LEFT': 'o',
	'INT_LESS': 'p',
	'INT_LESSEQUAL': 'q',
	'INT_MULT': 'r',
	'INT_NEGATE': 's',
	'INT_NOTEQUAL': 't',
	'INT_OR': 'u',
	'INT_REM': 'v',
	'INT_RIGHT': 'w',
	'INT_SBORROW': 'x',
	'INT_SCARRY': 'y',
	'INT_SDIV': 'z',
	'INT_SEXT': '0',
	'INT_SLESS': '1',
	'INT_SLESSEQUAL': '2',
	'INT_SREM': '3',
	'INT_SRIGHT': '4',
	'INT_SUB': '5',
	'INT_XOR': '6',
	'INT_ZEXT': '7',
	'LOAD': '8',
	'MULTIEQUAL': '9',
	'NEW': '0',
	'PCODE_MAX': '~',
	'PIECE': '!',
	'POPCOUNT': '@',
	'PTRADD': '#',
	'PTRSUB': '$',
	'RETURN': '%',
	'SEGMENTOP': '^',
	'STORE': '&',
	'SUBPIECE': '*',
	'UNIMPLEMENTED': '-'
}

# Initialize an empty dict for the "all functions" report
fn_report = {}

# Set up parser for the script arguments
arg_parser = ArgumentParser(description="P-Code statistical analysis", prog='script', prefix_chars='+')

# The "raw" JSON output file containing all the details
arg_parser.add_argument('+o', '++output', required=True, help='Output file for JSON')

# Optionally, a text file for the "signature strings"
arg_parser.add_argument('+s', '++strings', required=False, default=None, help='Output file for strings')

# Parse the arguments like a normal Python program
args = arg_parser.parse_args(args=getScriptArgs())

# the Program.getFunctionManager() provides an interface to navigate the functions
# that Ghidra has found within the program. The getFunctions() method will provide
# an iterator that allows you to walk through the list forward (True) or
# backward (False).
for fn in getCurrentProgram().getFunctionManager().getFunctions(True):

    # Get the earliest instruction defined within the function, to start our exploration
    instr = getInstructionAt(fn.getBody().getMinAddress())

    # Walk through each instruction that's determined to be part of this function
    while instr and instr.getMinAddress() <= fn.getBody().getMaxAddress():
        if fn.getBody().contains(instr.getMinAddress()):
            # Iterate across the list of P-Code operations that are expanded from
            # the parsed machine instruction
            for pcode_op in instr.getPcode():

                # Get the string name of the PCode operation
                pcode_name = pcode_op.getMnemonic()

                # Create a new empty list for this function the first time we get a valid instruction
                # This way we can easily assume to use .append() below
                if fn.getName() not in fn_report:
                    fn_report[fn.getName()] = []

                # Push the PCode op name on the end of the list
                fn_report[fn.getName()].append(pcode_name)

        # Advance to the next instruction
        instr = instr.getNext()

# Now, open the file provided by the user, and write the JSON into it
with open(args.output, 'w') as outfile:
    outfile.write(json.dumps(fn_report))

if args.strings:
    # Finally, if provided, condense the PCode lists into a string where each byte represents a single
    # PCode opcode, as mapped in the pcode_maps data structure
    with open(args.strings, 'w') as stringsfile:
        for fn in fn_report.keys():
            outstr = ''.join(pcode_maps[x] for x in fn_report[fn])
            stringsfile.write('{fn}:{s}\n'.format(fn=fn, s=outstr))  # Write one signature per line
