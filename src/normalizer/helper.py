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
import os
import sys
import angr
import r2pipe

from ..common import lib
from ..common import utils
from ..common import global_var


UNEXPLORED_FUNCTION_LABELS = {'_init', '_fini', '__libc_csu_init', '__libc_csu_fini', 
'frame_dummy', 'register_tm_clones', 'deregister_tm_clones', '__do_global_dtors_aux'}


BYTE_LEN_REPS = {
    'byte': 'byte', 
    'dword': 'dword', 
    'fword': 'fword', 
    'qword': 'qword', 
    'word': 'word', 
    'tbyte': 'tbyte',
    'tword': 'tbyte', 
    'xword': 'tbyte',
    'xmmword': 'xmmword'
}


BYTE_REP_PTR_MAP = {
    'q': 'qword ptr',
    'd': 'dword ptr',
    'l': 'dword ptr',
    'w': 'word ptr',
    'b': 'byte ptr',
    't': 'tbyte ptr'
}

BYTELEN_REP_MAP = {
    64: 'qword ptr',
    32: 'dword ptr',
    16: 'word ptr',
    8: 'byte ptr'
}

remote_addr_pat = re.compile('0x2[0-9a-fA-F]{5}')


def disassemble_to_asm(exec_path, disasm_path, disasm_type='objdump'):
    if os.path.exists(disasm_path): return
    elif disasm_type == 'radare2':
        disassemble_radare2(exec_path, disasm_path)
    elif disasm_type == 'objdump':
        cmd = 'objdump -M intel -d ' + exec_path + ' > ' + disasm_path
        utils.execute_command(cmd)
    elif disasm_type == 'bap':
        cmd = 'bap -d asm ' + exec_path + ' > ' + disasm_path
        utils.execute_command(cmd)
    elif disasm_type == 'dyninst':
        dyninst_path = os.path.join(utils.PROJECT_DIR, 'lib/disassemble_dyninst')
        cmd = dyninst_path + ' ' + exec_path + ' > ' + disasm_path
        utils.execute_command(cmd)
    elif disasm_type == 'angr':
        disassemble_angr(exec_path, disasm_path)
    elif disasm_type == 'ghidra':
        disassemble_ghidra(exec_path, disasm_path)
    else:
        raise Exception('The assembly file has not been generated')


def disassemble_angr(exec_path, asm_path):
    proj = angr.Project(exec_path, auto_load_libs=False, load_options={'main_opts': {'base_addr': 0x000000}})
    cfg = proj.analyses.CFGFast()
    nodes = cfg.graph.nodes()
    sys.stdout = open(asm_path, 'w+')
    for node in nodes:
        if node and node.block:
            node.block.pp()
        print('\n')
    sys.stdout.close()


def disassemble_radare2(exec_path, asm_path):
    res = ''
    r = r2pipe.open(exec_path)
    r.cmd('e asm.lines=false')
    r.cmd('e asm.syntax = intel')
    s_info = r.cmd('iS')
    sec_size_table = parse_r2_section_info(s_info)
    for sec_name in (('.plt', '.plt.got', '.text')):
        if sec_name in sec_size_table:
            r.cmd('s section.' + sec_name)
            res += r.cmd('pD ' + str(sec_size_table[sec_name]))
    with open(asm_path, 'w+') as f:
        f.write(res)


def disassemble_ghidra(exec_path, asm_path):
    cmd = os.path.join(utils.PROJECT_DIR, 'lib/ghidra_9.0.4/support/analyzeHeadless') + ' '
    cmd += os.path.join(utils.PROJECT_DIR, 'lib/ghidra_9.0.4/') + ' ghidra.gpr -deleteProject'
    cmd += ' -import ' + exec_path
    cmd += ' -scriptPath ' + os.path.join(utils.PROJECT_DIR, 'src/disassembler/')
    cmd += ' -postScript ghidra_disasm.py'
    cmd += ' ' + str(global_var.elf_info.code_base_addr)
    res = utils.execute_command(cmd)
    lines = res.split('\n')
    with open(asm_path, 'w+') as f:
        code_start = False
        for line in lines:
            if code_start:
                if line.startswith('--- instructions ---'):
                    break
                else:
                    f.write(line + '\n')
            if line.startswith('--- instructions ---'):
                code_start = True

    
# [Sections]
# Nm Paddr       Size Vaddr      Memsz Perms Name
# ...
# 14 0x00001510 13070 0x00001510 13070 -r-x .text
# 15 0x00004820     9 0x00004820     9 -r-x .fini
def parse_r2_section_info(section_info):
    prev_name = ''
    prev_address = 0
    lines = section_info.split('\n')
    sec_size_table = {}
    sec_start = False
    for line in lines:
        line_split = utils.remove_multiple_spaces(line).split(' ')
        if len(line_split) == 7:
            if utils.imm_pat.match(line_split[1]):
                address = utils.imm_str_to_int(line_split[1])
                if sec_start:
                    sec_size_table[prev_name] = address - prev_address
                else:
                    sec_start = True
                prev_address = address
                prev_name = line_split[-1]
    return sec_size_table


def convert_to_hex(line):
    if re.match(r'^[0-9a-f]+$', line):
        return '0x' + line.strip()
    return line


def to_hex(num, bits):
    return hex((num + (1 << bits)) % (1 << bits))


def calculate_relative_address(line, address):
    if re.match(r'^0x[0-9a-f]+$|^[0-9a-f]+$', line):
        relative_address = int(line, 16) - address
        if relative_address >= 0:
            line = '0x{0:X}'.format(relative_address)
        else:
            line = str(to_hex(relative_address, 64))
    return line


def calculate_absolute_address(line, rip):
    if re.match(r'^0x[0-9a-f]+$|^-0x[0-9a-f]+$', line):
        absolute_address = int(line, 16) + rip
        if absolute_address >= 0:
            line = '0x{0:x}'.format(absolute_address)
        else:
            line = str(to_hex(absolute_address, 64))
    return line


def calculate_dyninst_jmp_address(line, address, rip):
    res = line
    if line.endswith(']') and 'rip' in line:
        res = utils.extract_content(line, '[')
        if remote_addr_pat.search(line):
            res = line
            # res = res.replace('rip', hex(rip))
        else:
            res = res.replace('rip', hex(address))
            res = hex(eval(res))
    return res

def check_section_start(line, disassembler='objdump'):
    result = False
    if disassembler == 'objdump':
        result = line.startswith('Disassembly of section')
    elif disassembler == 'radare2':
        result = re.match(r'^[ ]+;-- [0-9a-zA-Z._]+:', line)
    return result


def normalize_arg(address, name, arg):
    res = re.sub(r'[+-]0x0\b|\*1\b', '', arg)
    if utils.check_jmp_with_address(name):
        res = calculate_relative_address(res, address)
    return res


def remove_att_prefix(arg):
    res = arg
    if arg.startswith('%'):
        res = arg.split('%', 1)[1].strip()
    elif arg.startswith('*%'):
        res = arg.split('*%', 1)[1].strip()
    elif arg.startswith(('$0x', '$-0x')):
        res = arg.split('$', 1)[1].strip()
    return res


def reconstruct_att_memory_rep(inst_name, arg):
    res = '['
    arg_split = arg.split('(', 1)
    arg_split_1 = arg_split[1].strip().rsplit(')', 1)[0].split(',')
    arg_split_1_0 = arg_split_1[0].strip()
    res += remove_att_prefix(arg_split_1_0)
    if len(arg_split_1) > 1:
        if arg_split_1_0:
            res += '+'
        res += remove_att_prefix(arg_split_1[1])
        if len(arg_split_1) == 3:
            res += '*' + remove_att_prefix(arg_split_1[2])
    if arg_split[0].strip():
        res += '+' + remove_att_prefix(arg_split[0].strip())
    res += ']'
    return res

def rewrite_att_memory_rep(inst_name, arg):
    res = arg
    if arg.startswith('*'):
        arg = arg.split('*', 1)[1].strip()
    if '(' in arg:  #%cs:(%rax,%rax)
        if '%st' in arg:
            res = arg.split('%', 1)[1].strip()
        elif ':' in arg:
            arg_split = arg.split(':')
            res = remove_att_prefix(arg_split[0]) + ':'
            res += reconstruct_att_memory_rep(inst_name, arg_split[1].strip())
        else:
            res = reconstruct_att_memory_rep(inst_name, arg)
    elif ':' in arg:    #%fs:0x28
        arg_split = arg.split(':')
        res = remove_att_prefix(arg_split[0]) + ':' + remove_att_prefix(arg_split[1])
    else:
        res = remove_att_prefix(arg)
    if res.endswith(']'):
        res = res.replace('+-', '-')
    return res

def add_att_memory_bytelen_rep(inst_name, arg, word_ptr_rep):
    res = arg
    if inst_name != 'lea' and (arg.endswith(']') or 's:' in arg):
        res = word_ptr_rep + ' ' + arg
    return res

def rewrite_att_inst_name(name, inst):
    res = name
    word_ptr_rep = None
    if name.startswith('cmov'):
        inst_name, suffix = name[:-1], name[-1]
        res = inst_name
        word_ptr_rep = BYTE_REP_PTR_MAP[suffix]
    elif name.startswith('jmp'):
        res = 'jmp'
        word_ptr_rep = 'qword ptr'
    elif name.startswith(('j')):
        word_ptr_rep = 'qword ptr'
    elif name.startswith(('set')):
        word_ptr_rep = 'byte ptr'
    elif name in (('subss', 'movss', 'ucomiss')):
        word_ptr_rep = 'dword ptr'
    elif name in (('movsb', 'movsw', 'movsd', 'movsq', 'movsxd')):
        suffix = name[-1]
        word_ptr_rep = BYTE_REP_PTR_MAP[suffix]
    elif name in (('movdqu', 'movaps', 'movdqa', 'movups')):
        word_ptr_rep = 'xmmword ptr'
    elif name in (('movsl')):
        new_inst_name, suffix = name[:-1], name[-1]
        res = new_inst_name
        word_ptr_rep = BYTE_REP_PTR_MAP[suffix]
    elif name == 'movq' and 'xmm' in inst:
        pass
    elif name.startswith(('movs', 'movz')):   # movslq, movzbl, movsl
        inst_name, suffix = name[:-1], name[-1]
        inst_name, src_len_rep = inst_name[:-1], inst_name[-1]
        if src_len_rep == 'b' or (src_len_rep == 'w' and (suffix == 'l' or suffix == 'q')):
            res = inst_name + 'x'
        else:
            res = inst_name + 'xd'
        if src_len_rep in BYTE_REP_PTR_MAP:
            word_ptr_rep = BYTE_REP_PTR_MAP[src_len_rep]
        elif inst_name == 'movss':
            word_ptr_rep = 'dword ptr'
    elif name.startswith(('fld', 'fadd', 'fstp')) and name.endswith('s'):
        inst_name, suffix = name[:-1], name[-1]
        res = inst_name
        word_ptr_rep = 'dword ptr'
    elif name.endswith(('q', 'l', 'w', 'b', 't')):
        inst_name, suffix = name[:-1], name[-1]
        if inst_name in lib.INSTRUCTIONS:
            res = inst_name
            word_ptr_rep = BYTE_REP_PTR_MAP[suffix]
        elif inst_name.startswith(('movs', 'movz')):   # movslq, movzbl
            inst_name, src_len_rep = inst_name[:-1], inst_name[-1]
            if src_len_rep == 'b' or (src_len_rep == 'w' and (suffix == 'l' or suffix == 'q')):
                res = inst_name + 'x'
            else:
                res = inst_name + 'xd'
            word_ptr_rep = BYTE_REP_PTR_MAP[src_len_rep]
    return res, word_ptr_rep


def get_ida_ptr_rep_from_item_type(item_type):
    res = None
    if item_type in (('dd', 'dq', 'db', 'dw')):
        suffix = item_type[-1]
        res = BYTE_REP_PTR_MAP[suffix]
    return res


def generate_ida_ptr_rep(name, inst, length):
    word_ptr_rep = None
    if name.startswith('jmp'):
        word_ptr_rep = 'qword ptr'
    elif name == 'call':
        word_ptr_rep = 'qword ptr'
    elif name in ('mov', 'cmp'):
        if length:
            word_ptr_rep = BYTELEN_REP_MAP[length]
    elif name.startswith(('j')):
        word_ptr_rep = 'qword ptr'
    elif name.startswith(('set')):
        word_ptr_rep = 'byte ptr'
    elif name in (('subs', 'movs', 'ucomis')):
        word_ptr_rep = 'dword ptr'
    elif name in (('movdqu', 'movaps', 'movdqa', 'movups')):
        word_ptr_rep = 'xmmword ptr'
    elif name == 'movq' and 'xmm' in inst:
        pass
    elif name == 'movsxd':
        if length in (16, 32):
            word_ptr_rep = BYTELEN_REP_MAP[length]
        else:
            word_ptr_rep = 'dword ptr'
    elif name == 'movss':
        word_ptr_rep = 'dword ptr'
    return word_ptr_rep


def format_bap_lea_inst_arg(name, arg):
    res = arg
    if name == 'lea':
        if utils.imm_pat.match(arg):
            res = '[' + arg + ']'
    return res

def reconstruct_dyninst_memory_rep(arg):
    res = '['
    arg_split = arg.split('(', 1)
    arg_split_1 = arg_split[1].strip().rsplit(')', 1)[0].split(',')
    arg_split_1_0 = arg_split_1[0].strip()
    if arg_split_1_0.startswith('%') and arg_split_1_0.endswith(tuple(lib.SEG_REGS)):
        res = arg_split_1_0.split('%', 1)[1].strip() + ':['
        if arg_split[0].strip() != '':
            offset = remove_att_prefix(arg_split[0].strip())
            if utils.imm_pat.match(offset):
                offset = utils.imm_str_to_int(offset)
                offset = utils.get_signed_integer(offset, lib.C_INT_LEN)
                res += hex(offset)
            else:
                res += offset
    else:
        res += remove_att_prefix(arg_split_1_0)
        if len(arg_split_1) > 1:
            if arg_split_1_0:
                res += ' + '
            res += remove_att_prefix(arg_split_1[1])
            if len(arg_split_1) == 3:
                res += ' * ' + remove_att_prefix(arg_split_1[2])
        if arg_split[0].strip() != '':
            offset = remove_att_prefix(arg_split[0].strip())
            if utils.imm_pat.match(offset):
                offset = utils.imm_str_to_int(offset)
                offset = utils.get_signed_integer(offset, lib.C_INT_LEN)
                res += ' + ' + hex(offset)
            else:
                res += ' + ' + offset
    res += ']'
    return res

def modify_dyninst_operands(name, args):
    res = args
    if name == 'mul':
        if len(args) == 3:
            res = [args[1]]
    elif name == 'imul':
        if len(args) == 3:
            res = [args[0], args[2], args[1]]
    elif name in (('idiv', 'div')):
        if len(args) == 2:
            res = [args[1]]
    return res

def rewrite_dyninst_arg_format(name, arg):
    if arg.startswith('0x'):
        arg = hex(int(arg.split('0x', 1)[1].strip(), 16))
    return arg

def normalize_dyninst_inst_name(name):
    res = name
    if name == 'shl/sal':
        res = 'shl'
    return res

def rewrite_dyninst_memory_rep(arg):
    res = arg
    if '(' in arg:
        res = reconstruct_dyninst_memory_rep(arg)
    elif ':' in arg:
        arg_split = arg.split(':')
        res = remove_att_prefix(arg_split[0]) + ':' + remove_att_prefix(arg_split[1])
    else:
        res = remove_att_prefix(arg)
    if res.endswith(']'):
        res = res.replace('+ -', '- ')
    return res


def rewrite_absolute_address_to_relative(arg, rip):
    res = arg
    if arg.endswith(']') and 's:' not in arg:
        arg_split = arg.strip().split('[')
        arg_content = arg_split[1].split(']')[0].strip()
        if re.match(r'^0x[0-9a-f]+$|^-0x[0-9a-f]+$', arg_content):
            relative_address = int(arg_content, 16) - rip
            if relative_address >= 0:
                res = '[rip+0x{0:x}]'.format(relative_address)
            else:
                res = '[rip+' + str(to_hex(relative_address, 64)) + ']'
            if arg.startswith(('qword', 'dword', 'word', 'byte', 'tbyte', 'xmmword')):
                res = arg_split[0] + res
    elif re.match(r'^0x[0-9a-f]+$|^-0x[0-9a-f]+$', arg):
        res = hex(utils.imm_str_to_int(arg))
    return res


def switch_mem_arg_order(arg):
    res = arg
    if arg.endswith(']') and 's:' not in arg:
        arg_split = arg.strip().split('[')
        arg_content = arg_split[1].split(']')[0].strip()
        if arg_content.startswith('-') and utils.imm_start_pat.match(arg_content):
            arg_content_split = arg_content.split('+')
            if len(arg_content_split) > 1:
                new_arg_content = '+'.join(arg_content_split[1:]) + '+' + arg_content_split[0]
            else:
                new_arg_content = arg_content
            res = arg_split[0] + '[' + new_arg_content.replace('+-', '-').strip() + ']'
    return res


def convert_to_hex_rep(arg):
    res = arg
    if re.match(r'^[0-9a-f]+$|^-[0-9a-f]+$', arg):
        res = hex(int(arg, 16))
    return res

def norm_objdump_arg(name, arg):
    res = arg
    if name == 'fdivrp' and arg == 'st':
        res = 'st(0)'
    return res

def modify_st_rep(arg):
    res = arg
    if arg in lib.FLOATING_POINT_ST_REGS:
        res = 'st(' + arg[-1] + ')'
    return res

def add_ptr_suffix_arg(arg):
    res = arg
    if arg.endswith(']') and ' ptr ' not in arg:
        b_len_rep = arg.split(' ', 1)[0].strip()
        if b_len_rep in BYTE_LEN_REPS:
            res = re.sub(b_len_rep, BYTE_LEN_REPS[b_len_rep] + ' ptr', arg)
    return res

def add_or_remove_ptr_rep_arg(inst_name, arg):
    res = arg
    if inst_name.startswith('rep') and ('cmpsb' in inst_name or 'scasb' in inst_name) and ']' in arg:
        res = '[' + arg.rsplit('[', 1)[1].strip()
    else:
        res = add_ptr_suffix_arg(arg)
    return res

def normalize_arg_byte_len_rep(arg):
    res = arg
    if arg.endswith(']'):
        b_len_rep = arg.split(' ', 1)[0].strip()
        if b_len_rep in BYTE_LEN_REPS:
            res = re.sub(b_len_rep, BYTE_LEN_REPS[b_len_rep], arg)
    return res


def retrieve_bytelen_rep(name, args):
    word_ptr_rep = None
    if len(args) == 1:
        if args[0].endswith(']'):
            word_ptr_rep = 'qword ptr'
    elif name in (('movsx', 'movzx')):
        word_ptr_rep = 'byte ptr'
        # if args[0] in lib.REG_INFO_DICT:
        #     word_len = lib.REG_INFO_DICT[args[0]][2]
        #     if word_len == 16: word_ptr_rep = 'byte ptr'
        #     else:
        #         word_ptr_rep = 'word ptr'
        # elif args[0] in lib.REG64_NAMES:
        #     word_ptr_rep = 'word ptr'
    elif name in (('movsd', 'movsb', 'movsxd')):
        word_ptr_rep = BYTE_REP_PTR_MAP[name[-1]]
    elif utils.check_branch_inst(name):
        word_ptr_rep = 'qword ptr'
    elif name != 'lea':
        for arg in args:
            if arg in lib.REG_INFO_DICT:
                word_len = lib.REG_INFO_DICT[arg][2]
                word_ptr_rep = BYTELEN_REP_MAP[word_len]
                break
            elif arg in lib.REG64_NAMES:
                word_ptr_rep = BYTELEN_REP_MAP[64]
                break
    return word_ptr_rep


def add_jump_address_wordptr_rep(arg):
    res = arg
    if arg.endswith(']'):
        res = 'qword ptr ' + arg
    return res


# input1: 'mov    rax,QWORD PTR [rip+0x200a5a] '
# output1: 'mov    rax,qword ptr [rip+0x200a5a] '
def norm_ptr_rep(line):
    res = line
    if ' PTR ' in line or ' ptr ' in line:
        for byte_len_rep in BYTE_LEN_REPS:
            res = re.sub(byte_len_rep + ' PTR ', byte_len_rep.lower() + ' ptr ', res)
    else:
        for d_type in BYTE_LEN_REPS:
            d_type_rep = d_type + ' '
            d_type_lower_rep = d_type.lower() + ' '
            if d_type_rep in line:
                res = re.sub(d_type_rep, d_type_lower_rep + ' ptr ', res)
            elif ',' + d_type_lower_rep in line or ' ' + d_type_lower_rep in line or '\t' + d_type_lower_rep in line:
                res = re.sub(d_type_lower_rep, d_type_lower_rep + ' ptr ', res)
    return res


def eval_simple_formula(stack, op_stack):
    res = stack[0]
    for idx, op in enumerate(op_stack):
        if op == '+':
            res = res + stack[idx + 1]
        elif op == '-':
            res = res - stack[idx + 1]
    return res


def reconstruct_formula_expr(stack, op_stack, idx_list, imm_val):
    res = ''
    for idx, val in enumerate(stack):
        if idx not in idx_list:
            if idx > 0:
                res += op_stack[idx - 1] + val
            else:
                res += val
    if res:
        res += '+' + hex(imm_val)
    else:
        res = hex(imm_val)
    res = res.replace('+-', '-')
    return res


def calc_formula_expr(stack, op_stack, content):
    res = content
    imm_item_list = [(idx, utils.imm_str_to_int(val)) for idx, val in enumerate(stack) if utils.imm_pat.match(val) and (idx == 0 or op_stack[idx - 1] in (('+', '-')))]
    idx_list = []
    val_list = []
    oper_list = []
    for idx, val in imm_item_list:
        num_val = val
        if idx > 0:
            op = op_stack[idx - 1]
            if val_list:
                oper_list.append(op)
            else:
                num_val = val if op == '+' else -val
        idx_list.append(idx)
        val_list.append(num_val)
    if len(val_list) > 1:
        imm_val = eval_simple_formula(val_list, oper_list)
        res = reconstruct_formula_expr(stack, op_stack, idx_list, imm_val)
    return res


def simulate_eval_expr(content):
    stack = []
    op_stack = []
    line = utils.rm_unused_spaces(content)
    line_split = utils.simple_operator_pat.split(line)
    for lsi in line_split:
        lsi = lsi.strip()
        if utils.simple_operator_pat.match(lsi):
            op_stack.append(lsi)
        else:
            val = lsi
            stack.append(val)
    res = calc_formula_expr(stack, op_stack, content)
    return res
