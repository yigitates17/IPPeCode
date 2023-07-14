import re
import sys
import argparse

op_codes = ["MOV", "ADD", "SUB", "MUL", "DIV", "READINT", "READSTR", "PRINT", "LABEL", "JUMP", "JUMPIFEQ", "JUMPIFLT",
            "CALL", "RETURN", "PUSH", "POP"]

ret_codes = {"Unknown Operation": 11,
             "Missing Operand": 12,
             "Bad Operand": 14,
             "Other Errors": 17,
             "Internal Errors": 19}

regex_dict = {
    'MOV': r"(?i)^\s*(MOV)\s+(\w+)\s+(\d+)\s*$",
    'ADD': r'(?i)ADD\s+([a-zA-Z$_][a-zA-Z\d$_]*)\s+([a-zA-Z$_][a-zA-Z\d$_]*)\s+([+-]?\d+|[a-zA-Z$_][a-zA-Z\d$_]*)',
    'SUB': r'(?i)SUB\s+([a-zA-Z$_][a-zA-Z\d$_]*)\s+([a-zA-Z$_][a-zA-Z\d$_]*)\s+([+-]?\d+|[a-zA-Z$_][a-zA-Z\d$_]*)',
    'MUL': r'(?i)MUL\s+([a-zA-Z$_][a-zA-Z\d$_]*)\s+([a-zA-Z$_][a-zA-Z\d$_]*)\s+([+-]?\d+|[a-zA-Z$_][a-zA-Z\d$_]*)',
    'DIV': r'(?i)DIV\s+([a-zA-Z$_][a-zA-Z\d$_]*)\s+([a-zA-Z$_][a-zA-Z\d$_]*)\s+([+-]?\d+|[a-zA-Z$_][a-zA-Z\d$_]*)',
    'READINT': r'(?i)READINT\s+([a-zA-Z$_][a-zA-Z\d$_]*)',
    'READSTR': r'(?i)READSTR\s+([a-zA-Z$_][a-zA-Z\d$_]*)',
    'PRINT': r'(?i)PRINT\s+([a-zA-Z$_][a-zA-Z\d$_]*|[0-9-+]+|"[^"]*")',
    'LABEL': r'(?i)LABEL\s+(@[a-zA-Z$_][a-zA-Z\d$_]*)',
    'JUMP': r'(?i)JUMP\s+(@[a-zA-Z$_][a-zA-Z\d$_]*)',
    'JUMPIFEQ': r'(?i)JUMPIFEQ\s+(@[a-zA-Z$_][a-zA-Z\d$_]*)\s+([a-zA-Z$_][a-zA-Z\d$_]*)\s+([+-]?\d+|"[^"]*")',
    'JUMPIFLT': r'(?i)JUMPIFEQ\s+(@[a-zA-Z$_][a-zA-Z\d$_]*)\s+([a-zA-Z$_][a-zA-Z\d$_]*)\s+([+-]?\d+|"[^"]*")',
    'CALL': r'(?i)CALL\s+(@[a-zA-Z$_][a-zA-Z\d$_]*)',
    'RETURN': r'(?i)RETURN',
    'PUSH': r'(?i)PUSH\s+([a-zA-Z$_][a-zA-Z\d$_]*|[0-9-+]+|"[^"]*")',
    'POP': r'(?i)READINT\s+([a-zA-Z$_][a-zA-Z\d$_]*)'
}


def missing_op():
    print(f'Parsing Error {ret_codes["Missing Operand"]}: Missing or excessing operand of instruction.',
          file=sys.stderr)
    sys.exit(ret_codes["Missing Operand"])


# Checks the arguments number in the IPPeCode
def arg_check(line):
    op_code, *operands = line.split()

    if op_code.upper() not in op_codes:
        print(f'Parsing Error {ret_codes["Unknown Operation"]}: Unknown operation code of instruction.',
              file=sys.stderr)
        sys.exit(ret_codes["Unknown Operation"])

    elif op_code.upper() == "RETURN":
        if len(operands) != 0:
            missing_op()

    elif op_code.upper() in ["READINT", "READSTR", "PRINT", "LABEL", "JUMP", "CALL", "PUSH", "POP"]:
        if len(operands) != 1:
            missing_op()

    elif op_code.upper() == "MOV":
        if len(operands) != 2:
            missing_op()

    elif op_code.upper() in ["JUMPIFEQ", "JUMPIFLT", "ADD", "SUB", "DIV", "MUL"]:
        if len(operands) != 3:
            missing_op()

    return True


# To be able to accept '-' string as arguments
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=argparse.FileType('r'), default='-')
    parser.add_argument('output', type=argparse.FileType('w'), default='-')
    parsed_args = parser.parse_args()

    if parsed_args.output is sys.stdout:
        parsed_args.output = "-"

    if parsed_args.input is sys.stdin:
        parsed_args.input = "-"

    return parsed_args


# Checks if the given IPPe instructions are valid
def is_valid_instruction(instruction):
    regex_code = instruction.split(' ')[0]
    pattern = regex_dict[regex_code]
    return re.match(pattern, instruction) is not None


def syntax_check(filename=None, stdin_input=None):
    if stdin_input is None:
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                instructions = f.readlines()
        except FileNotFoundError:
            print(f'Internal Error {ret_codes["Internal Errors"]}: Input file {filename} not found.', file=sys.stderr)
            sys.exit(ret_codes["Internal Errors"])
    else:
        instructions = stdin_input.split('\n')

    # Remove comments and empty lines
    instructions = [line.split('#', 1)[0].strip() for line in instructions if line.strip() != '']
    instructions = list(filter(lambda x: x != "", instructions))

    # Check syntax of instructions
    for i, instr in enumerate(instructions):

        if arg_check(instr):
            pass
        if not is_valid_instruction(instr):
            print(
                f'Other lexical and syntax errors {ret_codes["Other Errors"]}: Invalid syntax in instruction {i + 1}: {instr}',
                file=sys.stderr)
            sys.exit(ret_codes["Other Errors"])

    return instructions


escape_dict = {
    "\\n": '&eol;',
    ">": '&gt;',
    "<": '&lt;',
    "&": '&amp;'
}

esc_pattern = r"\\n|>|<|&"


# Parsing the tokens
def parse_ipp_code(code_str):
    instructions = []
    for line in code_str:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        opcode = parts[0].upper()
        operands = parts[1:]
        parsed_operands = []
        for op in operands:
            if op.startswith('$') or op.startswith('_') or op.startswith('_') or op.startswith('&') or op.startswith(
                    '%'):
                parsed_operands.append(('variable', op))
            elif op.startswith('@'):
                parsed_operands.append(('label', op))
            elif op.isdigit():
                parsed_operands.append(('integer', int(op)))
            elif re.findall(esc_pattern, op):
                for match in re.findall(esc_pattern, op):
                    op = op.replace(match, escape_dict[match])
                    parsed_operands.append(('string', op))
            else:
                parsed_operands.append(('variable', op))
        instructions.append((opcode, parsed_operands))

    return instructions


# Preparing the XML file
def instructions_to_xml(instructions, program_name="Program"):
    xml = f'<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += f'<!DOCTYPE program [\n'
    xml += f'  <!ELEMENT program (tac+)>\n'
    xml += f'  <!ELEMENT tac (dst?,src1?,src2?)>\n'
    xml += f'  <!ELEMENT dst (#PCDATA)>\n'
    xml += f'  <!ELEMENT src1 (#PCDATA)>\n'
    xml += f'  <!ELEMENT src2 (#PCDATA)>\n'
    xml += f'  <!ATTLIST program name CDATA #IMPLIED>\n'
    xml += f'  <!ATTLIST tac opcode CDATA #REQUIRED>\n'
    xml += f'  <!ATTLIST tac order CDATA #REQUIRED>\n'
    xml += f'  <!ATTLIST dst type (integer|string|variable|label) #REQUIRED>\n'
    xml += f'  <!ATTLIST src1 type (integer|string|variable) #REQUIRED>\n'
    xml += f'  <!ATTLIST src2 type (integer|string|variable) #REQUIRED>\n'
    xml += f'  <!ENTITY language "IPPeCode">\n'
    xml += f'  <!ENTITY eol "&#xA;">\n'
    xml += f'  <!ENTITY lt "&lt;">\n'
    xml += f'  <!ENTITY gt "&gt;">\n'
    xml += f' \n'
    xml += f']>\n'
    xml += f'<program name="{program_name}">\n'

    for i, inst in enumerate(instructions):

        if len(inst[1]) == 3:
            opcode, dst, src1, src2 = inst[0], inst[1][0], inst[1][1], inst[1][2]
        elif len(inst[1]) == 2:
            opcode, dst, src1, src2 = inst[0], inst[1][0], inst[1][1], None
        elif len(inst[1]) == 1 and inst[0].upper() in ["PRINT", "PUSH"]:
            opcode, dst, src1, src2 = inst[0], None, inst[1][0], None
        elif len(inst[1]) == 1:
            opcode, dst, src1, src2 = inst[0], inst[1][0], None, None
        elif len(inst) == 1:
            opcode, dst, src1, src2 = inst[0], None, None, None

        xml += f'  <tac opcode="{opcode}" order="{i + 1}">\n'

        if dst:
            xml += f'    <dst type="{dst[0]}">{dst[1]}</dst>\n'
        if src1:
            xml += f'    <src1 type="{src1[0]}">{src1[1]}</src1>\n'
        if src2:
            xml += f'    <src2 type="{src2[0]}">{src2[1]}</src2>\n'
        xml += f'  </tac>\n'

    xml += f'</program>\n'
    return xml


# Writing the XML to the file
def write_output(output, output_file):
    has_extension = True if len(output_file.split('.')) == 2 else False

    if output_file == '-':
        sys.stdout.write(output)
        print("Return Code 0: Executed successfully.")
        sys.exit(0)
    else:
        try:
            if has_extension is True:
                with open(output_file, 'x', encoding='utf-8') as f:
                    f.write(output)
                    print("Return Code 0: Executed successfully.")
                    sys.exit(0)
            else:
                output_file += '.xml'
                with open(output_file, 'x', encoding='utf-8') as f:
                    f.write(output)
                    print("Return Code 0: Executed successfully.")
                    sys.exit(0)
        except FileExistsError:
            with open(output_file, "w", encoding='utf-8') as f:
                f.write(output)
                print("Return Code 0: Executed successfully.")
                sys.exit(0)


# Reading the input from given file or stdin
def read_input(input_file):
    if input_file == '-':
        stdin_input = sys.stdin.read()
        approved = syntax_check(stdin_input=stdin_input)
    else:
        approved = syntax_check(filename=input_file)

    parsed_ippe = parse_ipp_code(approved)
    ready_xml = instructions_to_xml(parsed_ippe)

    return ready_xml


def open_files():
    if len(sys.argv) < 3 or len(sys.argv) > 3:
        print(
            f'Internal Error {ret_codes["Internal Errors"]} -- Usage: python parser.py <input_file> <output_file>',
            file=sys.stderr)
        sys.exit(ret_codes["Internal Errors"])

    parsed_args = parse_args()

    if parsed_args.input != "-":
        input_file = parsed_args.input.name
    else:
        input_file = parsed_args.input

    if parsed_args.output != "-":
        output_file = parsed_args.output.name
    else:
        output_file = parsed_args.output

    xml_output = read_input(input_file)
    write_output(xml_output, output_file)


if __name__ == '__main__':
    open_files()
    print("Return Code 0: Executed successfully.")
    sys.exit(0)
