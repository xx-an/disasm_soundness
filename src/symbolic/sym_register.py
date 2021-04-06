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
from ..common import utils
from ..common import lib
from . import sym_helper


def bitwise_sub(sym, start_idx, length):
    res = None
    if length == 8 and start_idx != 0:
        res = Extract(15, 8, sym)
    else:
        res = Extract(length - 1, 0, sym)
    return simplify(res)


def get_register_sym(store, name):
    sym = None
    if name in lib.REG_INFO_DICT:
        p_name, start_idx, length = lib.REG_INFO_DICT[name]
        p_sym = store[lib.REG][p_name]
        if p_sym == sym_helper.bottom(): 
            sym = sym_helper.bottom(length)
        else:
            sym = bitwise_sub(p_sym, start_idx, length)
    elif name in lib.REG64_NAMES:
        sym = store[lib.REG][name]
    else:
        sym = sym_helper.bottom(lib.DEFAULT_REG_LEN)
    return simplify(sym)


def bitwise_extend_parent(p_sym, sym, start_idx, length):
    res = None
    if sym == sym_helper.bottom(length): res = sym_helper.bottom()
    elif length == 32:
        res = ZeroExt(32, sym)
    elif length == 8 and start_idx != 0:
        res = Concat(Extract(63, 16, p_sym), sym, Extract(7, 0, p_sym))
    else:
        res = Concat(Extract(63, length, p_sym), sym)
    return simplify(res)


def set_register_sym(store, name, sym):
    if name in lib.REG_INFO_DICT:
        p_name, start_idx, length = lib.REG_INFO_DICT[name]
        p_sym = store[lib.REG][p_name]
        store[lib.REG][p_name] = bitwise_extend_parent(p_sym, sym, start_idx, length)
    elif name in lib.REG64_NAMES:
        store[lib.REG][name] = simplify(sym)


def get_segment_reg_val(store, segment_reg):
    res = 0
    if segment_reg in lib.SEG_REGS:
        res = store[lib.SEG][segment_reg]
    return res

