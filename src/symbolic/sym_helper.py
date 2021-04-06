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

from z3 import *
from ..common import lib
from ..common import utils
from ..common import global_var

cnt = 0
mem_cnt = 0

def cnt_init():
    global cnt
    global mem_cnt
    cnt = 0
    mem_cnt = 0

def gen_sym(length=lib.DEFAULT_REG_LEN):
    global cnt
    if cnt == 23: cnt += 1
    expr = utils.generate_sym_expr(cnt)
    res = BitVec(expr, length)
    cnt += 1
    return res

def gen_mem_sym(length=lib.DEFAULT_REG_LEN):
    global mem_cnt
    expr = utils.generate_sym_expr(mem_cnt)
    res = BitVec('m#' + expr, length)
    mem_cnt += 1
    return res

def gen_seg_reg_sym(name, length=lib.DEFAULT_REG_LEN):
    res = BitVec('_' + name, length)
    return res

def gen_sym_x(length=lib.DEFAULT_REG_LEN):
    res = BitVec('x', length)
    return res
    
def bottom(length=lib.DEFAULT_REG_LEN):
    return BitVec('Bottom', length)

def gen_spec_sym(name, length=lib.DEFAULT_REG_LEN):
    return BitVec(name, length)

def is_bit_vec_num(sym):
    return isinstance(sym, BitVecNumRef)

def is_equal(x, y):
    return simplify(x == y)

def not_equal(x, y):
    return simplify(x != y)

def is_less(x, y):
    return simplify(x < y)

def is_greater(x, y):
    return simplify(x > y)

def is_less_equal(x, y):
    return simplify(x <= y)

def is_greater_equal(x, y):
    return simplify(x >= y)

def is_neg(x):
    return simplify(x < 0)

def is_pos(x):
    return simplify(x >= 0)


LOGIC_OP_FUNC_MAP = {
    '==': is_equal,
    '<>': not_equal,
    '!=': not_equal,
    '<': is_less,
    '>': is_greater,
    '<=': is_less_equal,
    '>=': is_greater_equal
}

def bit_ith(sym, idx):
    return simplify(Extract(idx, idx, sym))

def most_significant_bit(val, dest_len):
    msb = bit_ith(val, dest_len - 1)
    return is_equal(msb, 1)

def smost_significant_bit(val, dest_len):
    smsb = bit_ith(val, dest_len - 2)
    return is_equal(smsb, 1)

def least_significant_bit(val, dest_len):
    lsb = bit_ith(val, 0)
    return is_equal(lsb, 1)

def check_pred_satisfiable(predicates):
    s = Solver()
    for pred in predicates:
        s.add(pred)
    r = s.check()
    if r == sat:
        return s.model()
    else:
        return False

def bitwiseXNOR(sym, length):
    res = bit_ith(sym, 0)
    for i in range(1, length):
        curr = bit_ith(sym, i)
        res = simplify(~ (res ^ curr))
    return is_equal(res, 1)

def zero_ext(length, sym):
    return ZeroExt(length, sym)


def extract(high, low, sym):
    return simplify(Extract(high, low, sym))

def upper_half(sym):
    sym_len = sym.size()
    return simplify(Extract(sym_len - 1, sym_len // 2, sym))


def lower_half(sym):
    sym_len = sym.size()
    return simplify(Extract(sym_len // 2 - 1, 0, sym))

def truncate_to_size(dest, res):
    dest_len = utils.get_sym_length(dest)
    return simplify(Extract(dest_len - 1, 0, res))

def string_of_address(address):
    res = address
    if isinstance(address, int):
        res = hex(address)
    elif is_bit_vec_num(address):
        res = hex(address.as_long())
    elif not isinstance(address, str):
        res = str(address)
    return res

def sym_is_int_or_bitvecnum(address):
    return isinstance(address, (int, BitVecNumRef))


def int_from_sym(sym_val):
    res = sym_val.as_long()
    return res

def extract_bytes(high, low, sym):
    return Extract(high * 8 - 1, low * 8, sym)


def bit_vec_val_sym(val, length=lib.DEFAULT_REG_LEN):
    return BitVecVal(val, length)

def neg(sym):
    return simplify(-sym)

def not_op(sym):
    return simplify(~sym)

def update_sym_expr(expr, new_expr, rel='or'):
    res = expr
    if rel == 'or':
        res = simplify(Or(expr, new_expr))
    elif rel == 'and':
        res = simplify(And(expr, new_expr))
    elif rel == 'r':
        res = new_expr
    return res

def is_term_address(address):
    return is_equal(address, BitVec('x', lib.DEFAULT_REG_LEN))


def remove_memory_content(store, mem_address):
    del store[lib.MEM][mem_address]
    if mem_address in store[lib.AUX_MEM]:
        store[lib.AUX_MEM].remove(mem_address)


def is_z3_bv_var(arg):
    return isinstance(arg, BitVecRef)

def bvnum_eq(lhs, rhs):
    res = None
    if lhs.size() != rhs.size():
        res = False
    else:
        res = is_equal(lhs, rhs)
    return res


def bitvec_eq(v_old, v, address_inst_map):
    res = True
    if isinstance(v_old, BitVecNumRef) and isinstance(v, BitVecNumRef):
        res = bvnum_eq(v_old, v)
    elif isinstance(v_old, BitVecNumRef):
        res = False
    return res


def merge_sym(lhs, rhs, address_inst_map):
    res = rhs
    if isinstance(lhs, BitVecNumRef) and isinstance(rhs, BitVecNumRef):
        lhs_num = lhs.as_long()
        rhs_num = rhs.as_long()
        if rhs_num not in address_inst_map:
            if not bvnum_eq(lhs, rhs):
                if lhs_num >= global_var.elf_info.rodata_start_addr and lhs_num < global_var.elf_info.rodata_end_addr:
                    res = gen_sym(rhs.size())
                elif rhs_num < global_var.elf_info.rodata_start_addr or rhs_num >= global_var.elf_info.rodata_end_addr:
                    res = gen_sym(rhs.size())
    elif isinstance(rhs, BitVecNumRef):
        rhs_num = rhs.as_long()
        if rhs_num not in address_inst_map:
            res = gen_sym(rhs.size())
    return res


def is_bottom(sym_val, dest_len):
    return sym_val == bottom(dest_len)



