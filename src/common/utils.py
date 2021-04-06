# DSV: Disassembly Soundness Validation
# Copyright (C) <2021> <Xiaoxin An> <Virginia Tech>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import re
import random
import os
import sys
import errno
from typing import List
import logging
import subprocess
from . import lib
from enum import Enum

MAX_VISIT_COUNT = 25

MAX_TRACEBACK_COUNT = 20
MAX_INST_ADDR_GAP = 25

MAX_MALLOC_SIZE = 16711568
MIN_HEAP_ADDR = 0x10000000
MAX_HEAP_ADDR = MIN_HEAP_ADDR

INIT_STACK_FRAME_POINTER = 2**48-9
MAX_DEVIATION = 5
SEGMENT_REG_INIT_VAL = 0

ASSEMBLY_FILE_NAME = 'test.s'

DISASM_TYPES = ['objdump', 'radare2', 'angr', 'bap', 'ghidra', 'dyninst']

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(os.path.realpath(__file__)))))

LOG_NAMES = ['log', 'aux']

logger = logging.getLogger(LOG_NAMES[0])
aux_logger = logging.getLogger(LOG_NAMES[1])

def setup_logger(log_name, log_path, verbose, level=logging.INFO):
    file_handler = logging.FileHandler(log_path, mode='w+')
    if log_name == LOG_NAMES[0]:
        global logger
        logger = logging.getLogger(log_name)
        logger.setLevel(level)
        if not verbose:
            logger.propagate = False
        logger.addHandler(file_handler) 
    else:
        global aux_logger
        aux_logger = logging.getLogger(log_name)
        aux_logger.setLevel(level)
        if not verbose:
            aux_logger.propagate = False
        aux_logger.addHandler(file_handler) 
    

def close_logger(log_name):
    if log_name == LOG_NAMES[0]:
        global logger
        logger = logging.getLogger(log_name)
        for handler in logger.handlers:
            handler.close()
            logger.removeHandler(handler)
    else:
        global aux_logger
        aux_logger = logging.getLogger(log_name)
        for handler in aux_logger.handlers:
            handler.close()
            aux_logger.removeHandler(handler)


delimits = {'(': ')', '[': ']', '{': '}'}
exec_file_suffix = ['', '.so', '.o', '.os']
float_pat = re.compile('^[0-9.]+$|^-[0-9.]+$')
imm_pat = re.compile('^0x[0-9a-fA-F]+$|^[0-9]+$|^-[0-9]+$|^-0x[0-9a-fA-F]+$')
imm_start_pat = re.compile('^0x[0-9a-fA-F]+|^[0-9]+|^-[0-9]+|^-0x[0-9a-fA-F]+')
MEM_DATA_SEC_SUFFIX = 'mem@'

OPPOSITE_FLAG_MAP = {
    'b': 'ae',
    'be': 'a',
    'l': 'ge',
    'le': 'g'
}

def imm_str_to_int(imm_str):
    res = 0
    if imm_str.startswith(('0x', '-0x')):
        res = int(imm_str, 16)
    elif re.search(r'[a-f]+', imm_str):
        res = int(imm_str, 16)
    else:
        res = int(imm_str)
    return res

def make_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: raise

def sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)

# input: [1, 2, 3]  [1, 2, 4]
# output: [3]
def diff_list(l1, l2):
    l1_minus_l2 = list(set(l1) - set(l2))
    l2_minus_l1 = list(set(l2) - set(l1))
    l1_minus_l2.extend(l2_minus_l1)
    return l1_minus_l2


def extract_content(expr: str, left_delimit='(') -> str:
    right_delimit = delimits[left_delimit]
    return expr.split(left_delimit, 1)[1].rsplit(right_delimit, 1)[0].strip()


def subtract_list(l1, l2):
    l3 = [elem for elem in l1 if elem not in l2]
    return l3


def flatten(l):
    r"""Flatten a list of list to a list
        Args:
            l (List[List[T]]): a list whose elements are also list
        """
    return [a for sl in l for a in sl]


def has_dup(l):
    r"""Check whether there are duplicated elements in a list
        Args:
            l (List[T]): a list who might have duplicated elements
        """
    return len(l) != len(set(l))


def check_executable_file(file_path):
    cmd = 'file ' + file_path + ' | grep "ELF 64-bit LSB shared object"'
    out = execute_command(cmd)
    if out.strip():
        return True
    else:
        return False

def get_exec_path(file_dir, file_name, disasm_type='objdump'):
    exec_path = None
    exec_file_dir = file_dir.replace('-'+disasm_type, '-build')
    for suffix in exec_file_suffix:
        curr_file_name = file_name.replace('.'+disasm_type, suffix)
        exec_path = os.path.join(exec_file_dir, curr_file_name)
        if os.path.exists(exec_path) and check_executable_file(exec_path):
            return exec_path
    return exec_path

def get_exec_path_from_log(file_dir, file_name, disasm_type='objdump'):
    exec_path = None
    exec_file_dir = file_dir.replace('-'+disasm_type, '-build')
    for suffix in exec_file_suffix:
        curr_file_name = file_name.replace('.log', suffix)
        exec_path = os.path.join(exec_file_dir, curr_file_name)
        if os.path.exists(exec_path) and check_executable_file(exec_path):
            return exec_path
    return exec_path

def get_file_dir(file_path):
    file_dir = file_path.rsplit('/', 1)[0]
    return file_dir


def get_file_name(path):
    file_name = path.rsplit('/', 1)[1].split('.', 1)[0]
    return file_name


# Extract the contents inside symmetric parentheses inside the string
# input: '(123) 45 (678(42) 235) 56', '(', ')'
# output: ['(123)', '(678(42) 235)']
def extract_bk_content(args:str, left = '(', right = ')')->List[str]:
    result = []
    to_continue = False
    curr = ''
    bk_count = 0
    for c in args:
        if c == left:
            curr += left
            bk_count += 1
            to_continue = True
        elif c == right:
            bk_count -= 1
            curr += right
            if bk_count == 0:
                to_continue = False
                curr = curr.strip()
                if curr != '':
                    result.append(curr)
                curr = ''
                bk_count = 0
        else:
            if to_continue:
                curr += c
    return result


# input: '(123) 45 (678(42) 235) 56', '(', ')', ' '
# output: ['(123)', '45', '(678(42) 235)', '56']
def split_sep_bk(data:str, sep:str, left = '(', right = ')')->List[str]:
    sep_first = sep[0]
    sep_len = len(sep)
    result = []
    curr = ''
    to_continue = False
    idx = 0
    length = len(data)
    bk_count = 0
    while idx < length:
        c = data[idx]
        if c == left:
            bk_count += 1
            curr += c
            to_continue = True
            idx += 1
        elif c == right:
            curr += c
            bk_count -= 1
            if bk_count == 0:
                to_continue = False
            idx += 1
        elif c == sep_first and len(data[idx:]) >= sep_len and data[idx: idx + sep_len] == sep:
            if to_continue:
                curr += c
                idx += 1
            else:
                curr = curr.strip()
                if curr != '':
                    result.append(curr)
                curr = ''
                idx += sep_len
        else:
            curr += c
            idx += 1
    result.append(curr.strip())
    return result


# input: '(123) 45 (678(42) 235) 56 [78 9]', ['(', '['], [')', ']'], ' '
# output: ['(123)', '45', '(678(42) 235)', '56', '[78 9]']
def split_sep_bks(data, sep, left = ['(', '[', '{'], right = [')', ']', '}']):
    sep_first = sep[0]
    sep_len = len(sep)
    result = []
    curr = ''
    to_continue = False
    idx = 0
    length = len(data)
    bk_len = len(left)
    bk_count = [0] * bk_len
    while idx < length:
        c = data[idx]
        if c in left:
            c_idx = left.index(c)
            bk_count[c_idx] += 1
            curr += c
            to_continue = True
            idx += 1
        elif c in right:
            c_idx = right.index(c)
            curr += c
            bk_count[c_idx] -= 1
            if all(elem == 0 for elem in bk_count):
                to_continue = False
            idx += 1
        elif c == sep_first and len(data[idx:]) >= sep_len and data[idx: idx + sep_len] == sep:
            if to_continue:
                curr += c
                idx += 1
            else:
                curr = curr.strip()
                if curr != '':
                    result.append(curr)
                curr = ''
                idx += sep_len
        else:
            curr += c
            idx += 1
    result.append(curr.strip())
    return result


def split_sep(data, sep):
    return split_sep_bk(data, sep, '[', ']')


# Extract the arguments of the first element from a tuple represented as a string
# input: '(cons(x, xs), cons(y, ys))'
# output: ['x', 'xs']
def extract_tuple_first_arg(t: str) -> List[str]:
    result = []
    first = ''
    if t:
        if t.startswith('('):
            ts = split_arg_list(t)
            first = ts[0].strip()
        else:
            first = t.strip()
    if first.endswith(')'):
        args = extract_content(first)
        result = split_sep_bks(args, ',')
    return result


# Remove the first element from a tuple represented as a string
# input: '(cons(x, xs), cons(y, ys))'
# output: 'cons(y, ys)'
def remove_tuple_first_element(t: str) -> str:
    result = ''
    if t.startswith('('):
        ts = split_sep_bks(extract_content(t), ',')
        result = '(' + ','.join(ts[1:]) + ')'
    return result


def generate_new_variable(tup_idx: int, arg_idx: int) -> str:
    tup_str = 'v_' + chr(ord('a') + tup_idx)
    result = tup_str + ('' if arg_idx == 0 else str(arg_idx))
    return result


def replace_expr_variable(expr: str, ov: str, nv: str) -> str:
    reg = '(?<=\W)' + ov + '(?=\W)'
    result = re.sub(reg, nv, expr)
    return result


# Split a arguments representation
# '(T,list[T])'
# ['T', 'list[T]']
def split_arg_list(expr: str, delimit='(') -> List[str]:
    if expr.startswith(delimit):
        expr = extract_content(expr, delimit)
    return split_sep_bks(expr, ',')


# Indent multiple lines
def block_indent(expr: str, indent_size='4') -> str:
    new_indent = '\n' + ' ' * indent_size
    return re.sub('\n', new_indent, expr)


# Replace multiple variables
def replace_multiple(expr, os, ns):
    result = expr
    n = len(os)
    for i in range(n):
        o = os[i]
        n = ns[i]
        result = re.sub(o, n, result)
    return result


def execute_command(cmd):
    out = subprocess.check_output(cmd, shell=True)
    return out.decode("utf-8").strip()


def write_file(file_path, data):
    with open(file_path, 'w+') as f:
        f.write(data)

def to_absolute_path(path, dir_path=''):
    if path.startswith('..'):
        path = re.sub('\.\./', os.path.dirname(dir_path) + '/', path)
    elif path.startswith('./'):
        path = re.sub('\./', dir_path + '/', path)
    elif path.startswith('~/'):
        path = os.path.expanduser(path)
    elif not path.startswith('/'):
        path = os.path.join(dir_path, path)
    return path


def convert_dot_to_png(name):
    cmd = 'dot -Tpng ' + name + '.dot > ' + name + '.png'
    execute_command(cmd)


def bytes_to_hex(bytes):
    res = ''
    for bs in bytes[::-1]:
        n = '{0:02x}'.format(bs)
        res += n
    return res


def bytes_to_int(bytes):
    # logger.debug(bytes)
    res = ''
    for bs in bytes:
        n = '{0:02x}'.format(bs)
        res += n
    return int(res, 16)


def dump_str_to_file(content, file_path):
    with open(file_path, 'w+') as f:
        f.write(content)
        f.write('\n')


def generate_inst_bin(line, syntax='intel'):
    res = ''
    try:
        line_str = '.intel_syntax noprefix\n' + line
        if syntax == 'att':
            line_str = '.att_syntax noprefix\n' + line
        dump_str_to_file(line_str.strip(), ASSEMBLY_FILE_NAME)
        cmd = 'gcc -c ' + ASSEMBLY_FILE_NAME + ' -o test.o'
        _ = execute_command(cmd)
        cmd = 'readelf -x .text test.o'
        out = execute_command(cmd)
        out_split = out.split('\n')
        for out_elem in out_split:
            if out_elem.startswith('  0x00'):
                res = ''.join(out_elem.strip().split('    ')[0].split(' ')[1:])
                break
    except:
        print('\'' + line + '\' is not a valid instruction for gcc (' + syntax + '-syntax format)')
    return res

    
def get_bytes_len(bytes_rep):
    return len(bytes_rep) // 2


def remove_multiple_spaces(line):
    return ' '.join(line.split())


def str_to_bytes(line):
    line = line.replace(' ', '')
    return int(line, 16).to_bytes(len(line)//2, byteorder='big')


def id_op(arg):
    return arg


def get_bin_rep(s):
    return str(s) if s<=1 else get_bin_rep(s>>1) + str(s&1)


def get_sub_bits(num, start_idx, end_idx):
    bin_rep = get_bin_rep(num)
    bin_rep = bin_rep[start_idx:end_idx]
    res = int(bin_rep, 2)
    return res


def generate_sym_expr(num):
    ''' Automatically generate a string using a given number '''
    curr = num % 26
    res = chr(ord('a') + curr)
    while num > 25:
        num = num // 26
        curr = num % 26
        res += chr(ord('a') + curr)
    return res


def check_branch_inst(inst):
    inst_name = inst.strip().split(' ', 1)[0]
    return inst_name in lib.JMP_INST or inst.endswith(' ret')

def check_branch_inst_wo_call(inst):
    inst_name = inst.strip().split(' ', 1)[0]
    return inst_name in lib.JMP_INST_WITHOUT_CALL or inst.endswith(' ret')

def check_not_single_branch_inst(inst):
    inst_name = inst.strip().split(' ', 1)[0]
    return inst_name in lib.CONDITIONAL_JMP_INST

def check_jmp_with_address(line):
    inst_name = line.strip().split(' ', 1)[0]
    return inst_name in lib.JMP_INST_WITH_ADDRESS


def gen_cjmp_idx_upperbound(inst_name, boundary):
    res = None
    jmp_condition = inst_name.split('j', 1)[1]
    if jmp_condition.startswith('n'):
        rest = jmp_condition.split('n')[1]
        if rest in OPPOSITE_FLAG_MAP:
            jmp_condition = OPPOSITE_FLAG_MAP[rest]
    if jmp_condition.startswith(('g', 'a')):
        if 'e' in jmp_condition:
            res = boundary
        else:
            res = boundary + 1
    return res


def gen_jt_idx_upperbound(trace_list, boundary):
    res = None
    idx = 0
    for idx, blk in enumerate(trace_list):
        inst = blk.inst
        if check_not_single_branch_inst(inst):
            res = gen_cjmp_idx_upperbound(inst.split(' ', 1)[0], boundary)
            break
    return idx, res


def _check_jt_assign_inst(inst_args):
    res = False
    inst_arg_s = inst_args.split(',')
    if len(inst_arg_s) == 2:
        inst_arg_0 = inst_arg_s[0].strip()
        inst_arg_1 = inst_arg_s[1].strip()
        if inst_arg_0 in lib.REG_NAMES and inst_arg_1.endswith(']') and 'rip' not in inst_arg_1:
            res = '*' in inst_arg_1 and '+' in inst_arg_1
    return res


def check_jump_table_assign_inst(trace_list, idx):
    res = False
    n_idx = 0
    for n_idx in range(idx+1, len(trace_list)):
        blk = trace_list[n_idx]
        inst = blk.inst
        if inst.startswith('mov'):
            res = _check_jt_assign_inst(inst.split(' ', 1)[1].strip())
            if res: break
    return n_idx, res


def get_mem_sym_length(sym_name):
    res = 128
    if sym_name.startswith('qword '): res = 64
    elif sym_name.startswith('dword '): res = 32
    elif sym_name.startswith('word '): res = 16
    elif sym_name.startswith('byte '):res = 8
    return res

def get_sym_length(sym_name, length=lib.DEFAULT_REG_LEN):
    res = length
    if sym_name in lib.REG64_NAMES: res = 64
    elif sym_name in lib.REG_INFO_DICT:
        _, _, res = lib.REG_INFO_DICT[sym_name]
    elif sym_name.endswith(']') or ' ptr ' in sym_name:
        res = get_mem_sym_length(sym_name)
    elif ':' in sym_name:     #rax:rdx
        regs = sym_name.split(':')
        left_len = get_sym_length(regs[0])
        right_len = get_sym_length(regs[1])
        res = left_len + right_len
    return res


def get_signed_integer(num, bits_len):
    mask = (2 ** bits_len) - 1
    if num & (1 << (bits_len - 1)):
        return num | ~mask
    else:
        return num & mask


def extract_inst_args(inst_split):
    inst_args = []
    if len(inst_split) > 1:
        inst_args = split_sep_bks(inst_split[1].strip(), ',', ['(', '{', '[', '<'], [')', '}', ']', '>'])
        inst_args = list(map(lambda x: x.strip(), inst_args))
    return inst_args


def parse_inst_args(inst_split):
    inst_args = []
    if len(inst_split) > 1:
        inst_args = inst_split[1].strip().split(',')
        inst_args = list(map(lambda x: x.strip(), inst_args))
    return inst_args


def read_glibc_elf_info(file_path):
    address_sym_table = {}
    with open(file_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            line_split = line.strip().split('->')
            address = imm_str_to_int(line_split[0].strip())
            syms = line_split[1].split('[', 1)[1].rsplit(']', 1)[0].strip()
            sym_list = syms.split(', ')
            sym_list = [sym.split('\'', 1)[1].rsplit('\'', 1)[0].strip() for sym in sym_list]
            address_sym_table[address] = sym_list
    return address_sym_table


#   line: '[ 1] .interp           PROGBITS         0000000000000238  00000238'
def read_glibc_data_base_addr(src_bin_path):
    section_headers = execute_command('readelf -S ' + src_bin_path)
    lines = section_headers.split('\n')
    data_base_addr = None
    for line in lines:
        if '.data' in line:
            line_split = remove_multiple_spaces(line.strip()).split(' ')
            section_name = line_split[-4].strip()
            if section_name == '.data':
                section_address = int(line_split[-2], 16)
                section_offset = int(line_split[-1], 16)
                data_base_addr = section_address - section_offset
    return data_base_addr

def insert_search(sorted_list, target):
    res = None
    length = len(sorted_list)
    left = 0
    right = length - 1
    while left <= right:
        mid = left + ((target- sorted_list[left]) * (right - left))//(sorted_list[right] - sorted_list[left])
        if mid < 0 or mid >= length: break
        curr = sorted_list[mid]
        if curr == target:
            res = mid
            break
        elif target < curr:
            right = mid - 1
        else:
            left = mid + 1
    return res


def get_executable_files(file_path):
    cmd = 'ls -d -1 "' + file_path + '/"* | xargs file | grep "ELF 64-bit LSB shared object"'
    out = execute_command(cmd)
    out_split = out.split('\n')
    files = []
    for file_info in out_split:
        file_path = file_info.split(':', 1)[0].strip()
        if file_path.strip():
            files.append(file_path)
    return files


def u_hex(num):
    res = hex(num)
    res = res.split('0x', 1)[1]
    return res

