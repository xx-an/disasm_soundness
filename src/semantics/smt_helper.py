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
from z3 import *
from ..common import utils
from ..common import lib
from ..symbolic import sym_helper
from ..symbolic import sym_engine


def _set_flag_val(store, flag_name, res):
    if res == True:
        store[lib.FLAGS][flag_name] = Bool(True)
    elif res == False:
        store[lib.FLAGS][flag_name] = Bool(False)
    else:
        store[lib.FLAGS][flag_name] = None


def _set_flag_neg_val(store, flag_name, res):
    if res == True:
        store[lib.FLAGS][flag_name] = Bool(False)
    elif res == False:
        store[lib.FLAGS][flag_name] = Bool(True)
    else:
        store[lib.FLAGS][flag_name] = None


def set_mul_OF_CF_flags(store, val):
    reset_all_flags(store)
    if val == False:
        set_OF_CF_flags(store, Bool(True))
    elif val == True:
        set_OF_CF_flags(store, Bool(False))


def set_OF_flag(store, rip, dest, src, res, op='+'):
    dest, src, _, _ = sym_engine.get_dest_src_sym(store, rip, dest, src)
    if op == '+':
        case1 = And(sym_helper.is_neg(dest), sym_helper.is_neg(src), sym_helper.is_pos(res))
        case2 = And(sym_helper.is_pos(dest), sym_helper.is_pos(src), sym_helper.is_neg(res))
        res = simplify(Or(case1, case2))
        _set_flag_val(store, 'OF', res)
    elif op == '-':
        case1 = And(sym_helper.is_neg(dest), sym_helper.is_pos(src), sym_helper.is_pos(res))
        case2 = And(sym_helper.is_pos(dest), sym_helper.is_neg(src), sym_helper.is_neg(res))
        res = simplify(Or(case1, case2))
        _set_flag_val(store, 'OF', res)
    else:
        store[lib.FLAGS]['OF'] = Bool(False)
    

def set_CF_flag(store, rip, dest, src, op='+'):
    if op == '+':
        _set_add_CF_flag(store, rip, dest, src)
    elif op == '-':
        _set_sub_CF_flag(store, rip, dest, src)
    else:
        store[lib.FLAGS]['CF'] = Bool(False)

def set_flag_direct(store, flag_name, value=None):
    store[lib.FLAGS][flag_name] = value

def get_flag_direct(store, flag_name):
    return store[lib.FLAGS][flag_name]

def _set_sub_CF_flag(store, rip, dest, src):
    sym_dest, sym_src, _, _ = sym_engine.get_dest_src_sym(store, rip, dest, src)
    res = sym_helper.is_less(sym_dest, sym_src)
    store[lib.FLAGS]['CF'] = res

def _set_add_CF_flag(store, rip, dest, src):
    sym_dest, sym_src, dest_len, _ = sym_engine.get_dest_src_sym(store, rip, dest, src)
    res = sym_helper.zero_ext(1, sym_src) + sym_helper.zero_ext(1, sym_dest)
    msb = sym_helper.most_significant_bit(res, dest_len + 1)
    store[lib.FLAGS]['CF'] = msb


def modify_status_flags(store, sym, dest_len):
    store[lib.FLAGS]['ZF'] = sym_helper.is_equal(sym, 0)
    store[lib.FLAGS]['SF'] = sym_helper.most_significant_bit(sym, dest_len)
    store[lib.FLAGS]['PF'] = sym_helper.bitwiseXNOR(sym_helper.extract(7, 0, sym), 8)


def set_OF_CF_flags(store, val):
    store[lib.FLAGS]['CF'] = val
    store[lib.FLAGS]['OF'] = val


def set_test_OF_CF_flags(store):
    set_OF_CF_flags(store, Bool(False))


def reset_all_flags(store):
    for flag in lib.RFlags:
        store[lib.FLAGS][flag] = None

def reset_all_flags_except_one(store, flag_name):
    for flag in lib.RFlags:
        if flag != flag_name:
            store[lib.FLAGS][flag] = None

def parse_condition(store, cond):
    logic_op = re.search(r'[<!=>]+', cond).group(0)
    lhs, rhs = cond.split(logic_op)
    lhs = store[lib.FLAGS][lhs]
    rhs = bool(utils.imm_str_to_int(rhs)) if utils.imm_pat.match(rhs) else store[lib.FLAGS][rhs]
    if lhs == None or rhs == None: return None
    return sym_helper.LOGIC_OP_FUNC_MAP[logic_op](lhs, rhs)


# expr: ZF==1 or SF<>OF
def parse_pred_expr(store, expr):
    or_conds = expr.split(' or ')
    and_or_conds = list(map(lambda x: x.split(' and '), or_conds))
    result = False
    for and_conds in and_or_conds:
        res = parse_condition(store, and_conds[0])
        if res == None: return None
        for ac in and_conds[1:]:
            curr = parse_condition(store, ac)
            if curr == None: return None
            res = And(res, curr)
        result = Or(result, res)
    return simplify(result)


def parse_predicate(store, inst, val, prefix='j'):
    cond = inst.split(' ', 1)[0].split(prefix, 1)[1]
    expr = lib.CONDITIONAL_FLAGS[cond]
    expr = parse_pred_expr(store, expr)
    if expr == None: return None
    elif not val: expr = simplify(Not(expr))
    return expr


def is_inst_aff_flag(store, rip, address, inst):
    inst_split = inst.strip().split(' ', 1)
    inst_name = inst_split[0]
    if inst_name in lib.INSTS_AFF_FLAGS_WO_CMP_TEST:
        return True
    elif inst_name in (('cmp', 'test')):
        inst_args = utils.parse_inst_args(inst_split)
        _add_aux_memory(store, rip, inst_args)
    return False


def add_aux_memory(store, rip, inst):
    inst_split = inst.strip().split(' ', 1)
    inst_name = inst_split[0]
    if inst_name in lib.INSTS_AFF_FLAGS_WO_CMP_TEST:
        inst_args = utils.parse_inst_args(inst_split)
        _add_aux_memory(store, rip, inst_args)


def _add_aux_memory(store, rip, inst_args):
    for arg in inst_args:
        if arg.endswith(']'):
            addr_rep_length = utils.get_addr_rep_length(arg)
            address = sym_engine.get_effective_address(store, rip, arg, addr_rep_length)
            if address in store[lib.MEM] and address not in store[lib.AUX_MEM]:
                sym_arg = store[lib.MEM][address]
                if sym_helper.is_bit_vec_num(sym_arg):
                    store[lib.AUX_MEM].add(address)
            break


def get_jump_address(store, rip, operand):
    length = utils.get_sym_length(operand)
    res = sym_engine.get_sym(store, rip, operand, length)
    if sym_helper.is_bit_vec_num(res):
        res = res.as_long()
    return res


# line: 'rax + rbx * 1 + 0'
# line: 'rbp - 0x14'
# line: 'rax'
def get_bottom_source(line, store, rip):
    line_split = re.split(r'(\W+)', line)
    res, is_reg_bottom = [], False
    for lsi in line_split:
        lsi = lsi.strip()
    for lsi in line_split:
        lsi = lsi.strip()
        if lsi in lib.REG_NAMES:
            val = sym_engine.get_sym(store, rip, lsi, utils.MEM_ADDR_SIZE)
            if not sym_helper.sym_is_int_or_bitvecnum(val):
                root_reg = get_root_reg(lsi)
                res.append(root_reg)
                is_reg_bottom = True
    if not is_reg_bottom:
        addr = sym_engine.get_effective_address(store, rip, line)
        res.append(str(addr))
    return res, is_reg_bottom

# line: 'rax + rbx * 1 + 0'
# line: 'rbp - 0x14'
# line: 'rax'
def get_mem_reg_source(line):
    line = utils.rm_unused_spaces(line)
    line_split = utils.simple_operator_pat.split(line)
    res = []
    for lsi in line_split:
        lsi = lsi.strip()
        if lsi in lib.REG_NAMES:
            res.append(lsi)
    return res


def get_root_reg(src):
    res = None
    if src in lib.REG64_NAMES:
        res = src
    elif src in lib.REG_INFO_DICT:
        res = lib.REG_INFO_DICT[src][0]
    return res


def check_source_is_sym(store, rip, src, syms):
    res = False
    if src in lib.REG_INFO_DICT:
        res = lib.REG_INFO_DICT[src][0] in syms
    elif src in lib.REG_NAMES:
        res = src in syms
    elif ':' in src:
        lhs, rhs = src.split(':')
        res = check_source_is_sym(store, rip, lhs, syms) or check_source_is_sym(store, rip, rhs, syms)
    elif src.endswith(']'):
        addr_rep_length = utils.get_addr_rep_length(src)
        addr = sym_engine.get_effective_address(store, rip, src, addr_rep_length)
        res = str(addr) in syms
    return res


def check_cmp_dest_is_sym(store, rip, dest, sym_names):
    res = False
    if len(sym_names) == 1:
        if dest in lib.REG_NAMES:
            res = check_source_is_sym(store, rip, dest, sym_names)
        elif dest.endswith(']'):
            new_srcs, is_reg_bottom = get_bottom_source(dest, store, rip)
            if is_reg_bottom:
                if len(new_srcs) == 1:
                    res = new_srcs[0] == sym_names[0]
            else:
                addr_rep_length = utils.get_addr_rep_length(dest)
                addr = sym_engine.get_effective_address(store, rip, dest, addr_rep_length)
                res = str(addr) == sym_names[0]
    return res


def remove_reg_from_sym_srcs(reg, src_names):
    src_reg = get_root_reg(reg)
    if src_reg in src_names:
        src_names.remove(src_reg)


def add_new_reg_src(sym_names, dest, src):
    src_names = sym_names
    remove_reg_from_sym_srcs(dest, src_names)
    src_names.append(get_root_reg(src))
    return list(set(src_names))


def add_src_to_syms(store, sym_names, src):
    src_names = sym_names
    sym_src = sym_engine.get_register_sym(store, src)
    if not sym_helper.sym_is_int_or_bitvecnum(sym_src):
        src_names.append(get_root_reg(src))
    return src_names


def sym_bin_op_na_flags(store, rip, op, dest, src):
    res = sym_engine.sym_bin_op(store, rip, op, dest, src)
    sym_engine.set_sym(store, rip, dest, res)
    return res


def get_sym_rsp(store, rip):
    sym_rsp = sym_engine.get_sym(store, rip, utils.ADDR_SIZE_SP_MAP[utils.MEM_ADDR_SIZE], utils.MEM_ADDR_SIZE)
    return sym_rsp

def push_val(store, rip, sym_val):
    operand_size = sym_val.size()
    sym_rsp = sym_bin_op_na_flags(store, rip, '-', utils.ADDR_SIZE_SP_MAP[utils.MEM_ADDR_SIZE], str(operand_size//8))
    sym_engine.set_mem_sym(store, sym_rsp, sym_val, sym_val.size())


def set_rsp_init(store, rip):
    if utils.MEM_ADDR_SIZE == 64:
        sym_engine.set_sym(store, rip, 'rsp', sym_helper.bit_vec_val_sym(utils.INIT_STACK_FRAME_POINTER))
    elif utils.MEM_ADDR_SIZE == 32:
        sym_engine.set_sym(store, rip, 'esp', sym_helper.bit_vec_val_sym(utils.INIT_STACK_FRAME_POINTER))
    
