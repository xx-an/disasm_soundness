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
from . import sym_register
from . import sym_memory
from . import sym_helper

OPS_NEED_EXTENSION = {'<<', '>>', '>>>'}

def get_sym(store, rip, src, length=lib.DEFAULT_REG_LEN):
    res = None
    if src in lib.REG_NAMES:   # rax
        res = sym_register.get_register_sym(store, src)
    elif utils.imm_pat.match(src):    #0x123456
        val = utils.imm_str_to_int(src)
        res = BitVecVal(val, length)
    elif 's:' in src:       #fs:rax
        src_split = src.split(':')
        seg_reg = src_split[0].rsplit(' ', 1)[1].strip()
        seg_reg_val = sym_register.get_segment_reg_val(store, seg_reg)
        src = src_split[1].strip()
        val = None
        if src.endswith(']'):
            val = sym_memory.get_effective_address(store, rip, src)
        else:
            val = get_sym(store, rip, src)
        address = simplify(seg_reg_val + val)
        res = sym_memory.get_memory_val(store, address, length)
    elif src.endswith(']'): # byte ptr [rbx+rax*1]
        address = sym_memory.get_effective_address(store, rip, src)
        res = sym_memory.get_memory_val(store, address, length)
    elif ':' in src:     # rdx:rax
        regs = src.split(':')
        left = sym_register.get_register_sym(store, regs[0])
        right = sym_register.get_register_sym(store, regs[1])
        res = simplify(Concat(left, right))
    return res


def get_register_sym(store, src):
    return sym_register.get_register_sym(store, src)

def get_memory_val(store, address, length):
    return sym_memory.get_memory_val(store, address, length)

def set_sym(store, rip, dest, sym):
    if dest in lib.SEG_REGS:    # fs
        store[lib.SEG][dest] = simplify(sym)
    elif dest in lib.REG_NAMES:        # rax
        dest_len = utils.get_sym_length(dest)
        if sym.size() > dest_len:
            sym = simplify(Extract(dest_len - 1, 0, sym))
        sym_register.set_register_sym(store, dest, sym)
    elif 's:' in dest:       # fs:rax
        dest_len = utils.get_sym_length(dest)
        dest_split = dest.split(':')
        seg_reg = dest_split[0].rsplit(' ', 1)[1].strip()
        seg_reg_val = sym_register.get_segment_reg_val(store, seg_reg)
        dest_rest = dest_split[1].strip()
        val = None
        if dest_rest.endswith(']'):
            val = sym_memory.get_effective_address(store, rip, dest_rest)
        else:
            rest_len = utils.get_sym_length(dest_rest)
            val = get_sym(store, rip, dest_rest, rest_len)
        address = simplify(seg_reg_val + val)
        sym_memory.set_mem_sym(store, address, sym, dest_len)
    elif dest.endswith(']'):
        length = utils.get_sym_length(dest)
        address = sym_memory.get_effective_address(store, rip, dest)
        sym_memory.set_mem_sym(store, address, sym, length)
    elif ':' in dest:     # rax:rdx
        lreg, rreg = dest.split(':')
        reg_len = utils.get_sym_length(lreg)
        left = simplify(Extract(reg_len + reg_len - 1, reg_len, sym))
        right = simplify(Extract(reg_len - 1, 0, sym))
        sym_register.set_register_sym(store, lreg, left)
        sym_register.set_register_sym(store, rreg, right)
    

def get_effective_address(store, rip, operand):
    return sym_memory.get_effective_address(store, rip, operand)


def get_jump_table_address(store, arg, src_sym, src_val):
    return sym_memory.get_jump_table_address(store, arg, src_sym, src_val)


def read_memory_val(store, address, length=lib.DEFAULT_REG_LEN):
    return sym_memory.read_memory_val(store, address, length)


def set_mem_sym(store, address, sym, length=lib.DEFAULT_REG_LEN):
    return sym_memory.set_mem_sym(store, address, sym, length)


def get_mem_sym(store, address, length=lib.DEFAULT_REG_LEN):
    return sym_memory.get_mem_sym(store, address, length)


def sym_bin_op(store, rip, op, dest, src):
    func = SYM_BIN_OP_MAP[op]
    sym_dest, sym_src, dest_len, src_len = get_dest_src_sym(store, rip, dest, src)
    if op in OPS_NEED_EXTENSION and dest_len != src_len:
        sym_src = extension_sym(sym_src, dest_len, src_len)
    res = func(sym_dest, sym_src, dest_len)
    res = simplify(res)
    return res


SYM_BIN_OP_MAP = {
    '+': lambda x, y, l: x + y,
    '-': lambda x, y, l: x - y,
    '&': lambda x, y, l: x & y,
    '|': lambda x, y, l: x | y,
    '^': lambda x, y, l: x ^ y,
    '>>': lambda x, y, l: x >> y,
    '<<': lambda x, y, l: x << y,
    '>>>': lambda x, y, l: LShR(x, y),
    'smul': lambda x, y, l: SignExt(l, x) * SignExt(l, y),
    'umul': lambda x, y, l: ZeroExt(l, x) * ZeroExt(l, y),
    'sdiv': lambda x, y, l: Extract(l // 2 - 1, 0, x / SignExt(l // 2, y)),
    'smod': lambda x, y, l: Extract(l // 2 - 1, 0, SRem(x, SignExt(l // 2, y))),
    'udiv': lambda x, y, l: Extract(l // 2 - 1, 0, UDiv(x, ZeroExt(l // 2, y))),
    'umod': lambda x, y, l: Extract(l // 2 - 1, 0, URem(x, ZeroExt(l // 2, y))),
}


def extension(store, rip, src, dest_len, sign=False):
    src_len = utils.get_sym_length(src)
    sym_src = get_sym(store, rip, src, src_len)
    res = extension_sym(sym_src, dest_len, src_len, sign)
    return res


def extension_sym(sym, dest_len, src_len, sign=False):
    if sym_helper.is_bottom(sym, src_len):
        return sym_helper.bottom(dest_len)
    len_diff = dest_len - src_len
    if sign:
        res = SignExt(len_diff, sym)
    else:
        res = ZeroExt(len_diff, sym)
    return simplify(res)


def undefined(store, rip, *args):
    if len(args) > 0:
        dest = args[0]
        dest_len = utils.get_sym_length(dest)
        set_sym(store, rip, dest, sym_helper.bottom(dest_len))


def get_dest_src_sym(store, rip, dest, src):
    dest_len = utils.get_sym_length(dest)
    src_len = utils.get_sym_length(src, dest_len)
    sym_src = get_sym(store, rip, src, src_len)
    sym_dest = get_sym(store, rip, dest, dest_len)
    return sym_dest, sym_src, dest_len, src_len

