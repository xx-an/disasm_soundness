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
import sys
from z3 import *
from ..common import lib
from ..common import utils
from . import sym_helper
from . import sym_register
from ..common import global_var


def get_sym_val(str_val, store, length):
    res = None
    if str_val in lib.REG_NAMES:
        res = sym_register.get_register_sym(store, str_val)
    elif utils.imm_pat.match(str_val):
        res = BitVecVal(utils.imm_str_to_int(str_val), length)
    elif str_val in lib.SEG_REGS:
        res = store[lib.SEG][str_val]
    else:
        res = BitVec(str_val, length)
    return res


def get_root_reg(src):
    res = None
    if src in lib.REG64_NAMES:
        res = src
    elif src in lib.REG_INFO_DICT:
        res = lib.REG_INFO_DICT[src][0]
    return res


def get_idx_sym_val(store, arg, src_sym, src_val, length):
    res = None
    if arg in lib.REG_NAMES:
        res = sym_register.get_register_sym(store, arg)
        if not sym_helper.is_bit_vec_num(res):
            m = sym_helper.check_pred_satisfiable([src_sym == src_val])
            if m is not False:
                for d in m.decls():
                    s_val = m[d]
                    s_len = s_val.size()
                    res = substitute(res, (BitVec(d.name(), s_len), s_val))
                res = simplify(res)
            # else:
            #     utils.logger.info('Failed to solve the equation ' + str(src_sym) + ' == ' + str(src_val))
    elif utils.imm_pat.match(arg):
        res = BitVecVal(utils.imm_str_to_int(arg), length)
    return res

def calc_mult(stack, op_stack):
    res = stack[0]
    for idx, op in enumerate(op_stack):
        if op == '*':
            res = stack[idx] * stack[idx + 1]
            stack[idx] = simplify(res)
            del stack[idx + 1]
            del op_stack[idx]


def eval_simple_formula(stack, op_stack):
    calc_mult(stack, op_stack)
    res = stack[0]
    for idx, op in enumerate(op_stack):
        if op == '+':
            res = res + stack[idx + 1]
        elif op == '-':
            res = res - stack[idx + 1]
        else:
            utils.logger.debug('There are unrecognized operator ' + op)
    return simplify(res)


# line: 'rax + rbx * 1 + 0'
# line: 'rbp - 0x14'
# line: 'rax'
def calc_effective_address(line, store, length):
    stack = []
    op_stack = []
    line = utils.rm_unused_spaces(line.strip())
    line_split = utils.simple_operator_pat.split(line)
    for lsi in line_split:
        if utils.simple_operator_pat.match(lsi):
            op_stack.append(lsi)
        else:
            val = get_sym_val(lsi, store, length)
            stack.append(val)
    res = eval_simple_formula(stack, op_stack)
    return res


# arg: DWORD PTR [rcx+rdx*4]
def get_jump_table_address(store, arg, src_sym, src_val, length=utils.MEM_ADDR_SIZE):
    arg = utils.extract_content(arg, '[')
    stack = []
    op_stack = []
    arg = utils.rm_unused_spaces(arg.strip())
    arg_split = utils.simple_operator_pat.split(arg)
    for ai in arg_split:
        if utils.simple_operator_pat.match(ai):
            op_stack.append(ai)
        else:
            val = get_idx_sym_val(store, ai, src_sym, src_val, length)
            stack.append(val)
    res = eval_simple_formula(stack, op_stack)
    return res


def get_effective_address(store, rip, src, length=utils.MEM_ADDR_SIZE):
    res = None
    if src.endswith(']'):
        res = utils.extract_content(src, '[')
        if utils.imm_pat.match(res):
            res = BitVecVal(utils.imm_str_to_int(res), length)
        elif 'rip' in res:  # 'rip+0x2009a6'
            res = res.replace('rip', hex(rip))
            res = eval(res)
            res = BitVecVal(utils.norm_num_w_length(res, length), length)
        else:  # 'rax + rbx * 1'
            res = calc_effective_address(res, store, length)
    elif 's:' in src:
        seg_name, new_src = src.split(':', 1)
        seg_addr = get_sym_val(seg_name.strip(), store, length)
        new_addr = get_effective_address(store, rip, new_src.strip(), length)
        res = simplify(seg_addr + new_addr)
    elif utils.imm_pat.match(src):
        res = BitVecVal(utils.imm_str_to_int(src), length)
    else:
        utils.logger.info('Cannot recognize the effective address of ' + src)
    return res


def addr_in_rodata_section(int_addr):
    return global_var.binary_info.rodata_start_addr <= int_addr < global_var.binary_info.rodata_end_addr


def addr_in_data_section(int_addr):
    return global_var.binary_info.data_start_addr <= int_addr < global_var.binary_info.data_end_addr


def addr_in_text_section(int_addr):
    return global_var.binary_info.text_start_addr <= int_addr < global_var.binary_info.text_end_addr


# def pollute_all_mem_content(store):
#     addr_list = list(store[lib.MEM].keys())
#     for addr in addr_list:
#         if not sym_helper.sym_is_int_or_bitvecnum(addr):
#             if sym_helper.sym_is_int_or_bitvecnum(store[lib.MEM][addr]):
#                 store[lib.MEM][addr] = sym_helper.gen_sym(store[lib.MEM][addr].size())
#         else:
#             int_addr = sym_helper.int_from_sym(addr)
#             if int_addr >= global_var.binary_info.data_start_addr and int_addr < utils.MAX_HEAP_ADDR:
#                 if sym_helper.sym_is_int_or_bitvecnum(store[lib.MEM][addr]):
#                     store[lib.MEM][addr] = sym_helper.gen_sym(store[lib.MEM][addr].size())


# def pollute_mem_w_sym_address(store):
#     for addr in store[lib.MEM]:
#         if not sym_helper.sym_is_int_or_bitvecnum(addr):
#             if sym_helper.sym_is_int_or_bitvecnum(store[lib.MEM][addr]):
#                 store[lib.MEM][addr] = sym_helper.gen_sym(store[lib.MEM][addr].size())


def set_mem_sym(store, address, sym, length):
    # If the memory address is not concrete
    if not sym_helper.sym_is_int_or_bitvecnum(address):
        store[lib.MEM][address] = sym
    else:
        byte_len = length // 8
        if address in store[lib.MEM]:
            prev_sym = store[lib.MEM][address]
            prev_len = prev_sym.size() // 8
            if byte_len < prev_len:
                curr_address = simplify(address + byte_len)
                store[lib.MEM][curr_address] = simplify(sym_helper.extract_bytes(prev_len, byte_len, prev_sym))
        store[lib.MEM][address] = sym
        for offset in range(-7, byte_len):
            if offset != 0:
                curr_address = simplify(address + offset)
                if curr_address in store[lib.MEM]:
                    prev_sym = store[lib.MEM][curr_address]
                    if prev_sym != None:
                        prev_len = prev_sym.size() // 8
                        if offset < 0 and prev_len > -offset:
                            store[lib.MEM][curr_address] = simplify(sym_helper.extract_bytes(-offset, 0, prev_sym))
                        elif offset > 0:
                            sym_helper.remove_memory_content(store, curr_address)
                            if prev_len - byte_len + offset > 0:
                                new_address = simplify(address + byte_len)
                                new_sym = simplify(sym_helper.extract_bytes(prev_len, byte_len - offset, prev_sym))
                                store[lib.MEM][new_address] = new_sym
                                break
        # pollute_mem_w_sym_address(store)

            
    
def get_mem_sym(store, address, length):
    byte_len = length // 8
    res = None
    start_address = None
    for offset in range(8):
        curr_address = simplify(address - offset)
        if curr_address in store[lib.MEM]:
            start_address = curr_address
            break
    if start_address is not None:
        sym = store[lib.MEM][start_address]
        sym_len = sym.size() // 8
        if sym_len > offset:
            right_bound = min(sym_len, byte_len + offset)
            first_sym = sym_helper.extract_bytes(right_bound, offset, sym)
            if right_bound - offset < byte_len:
                temp = [first_sym]
                tmp_len = right_bound - offset
                while tmp_len < byte_len:
                    next_address = simplify(address + tmp_len)
                    if next_address in store[lib.MEM]:
                        next_sym = store[lib.MEM][next_address]
                        next_len = next_sym.size() // 8
                        r_bound = min(next_len, byte_len - tmp_len)
                        curr = sym_helper.extract_bytes(r_bound, 0, next_sym)
                        temp.append(curr)
                        tmp_len += r_bound
                    else:
                        break
                if tmp_len == byte_len:
                    temp.reverse()
                    res = simplify(Concat(temp))
            else:
                res = simplify(first_sym)
    return res


def read_memory_val(store, address, length):
    res = None
    if sym_helper.is_bit_vec_num(address):
        val = None
        int_address = address.as_long()
        if addr_in_rodata_section(int_address):
            rodata_base_addr = global_var.binary_info.rodata_base_addr
            val = global_var.binary_content.read_bytes(int_address - rodata_base_addr, length // 8)
        elif addr_in_data_section(int_address):
            data_base_addr = global_var.binary_info.data_base_addr
            val = global_var.binary_content.read_bytes(int_address - data_base_addr, length // 8)
        elif addr_in_text_section(int_address):
            text_base_addr = global_var.binary_info.text_base_addr
            val = global_var.binary_content.read_bytes(int_address - text_base_addr, length // 8)
        if val != None:
            res = BitVecVal(val, length)
        else:
            res = BitVec(utils.MEM_DATA_SEC_SUFFIX + hex(int_address), length)
        store[lib.MEM][address] = res
    else:
        res = sym_helper.gen_mem_sym(length)
        store[lib.MEM][address] = res
    return res


def get_memory_val(store, address, length):
    res = get_mem_sym(store, address, length)
    if res == None:
        res = read_memory_val(store, address, length)
    return res
