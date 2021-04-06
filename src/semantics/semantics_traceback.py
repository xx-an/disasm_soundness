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

from ..common import lib
from ..common import utils
from ..symbolic import sym_engine
from ..symbolic import sym_helper
from . import smt_helper
from . import semantics

rip = 0
need_stop, boundary, still_tb = False, None, True


def sym_bin_on_src(store, sym_names, src):
    src_names = sym_names
    src_len = utils.get_sym_length(src)
    sym_src = sym_engine.get_sym(store, rip, src, src_len)
    if not sym_helper.sym_is_int_or_bitvecnum(sym_src):
        if ':' in src:
            lhs, rhs = src.split(':')
            src_names = smt_helper.add_src_to_syms(store, sym_names, lhs)
            src_names = smt_helper.add_src_to_syms(store, src_names, rhs)
        elif src.endswith(']'):
            new_srcs, is_reg_bottom = smt_helper.get_bottom_source(src, store)
            if is_reg_bottom:
                src_names = src_names + new_srcs
            else:
                addr = sym_engine.get_effective_address(store, rip, src)
                src_names = src_names + [str(addr)]
            # src_names = src_names + new_srcs
        else:
            src_names.append(smt_helper.get_root_reg(src))
    else:
        if ':' in src:
            lhs, rhs = src.split(':')
            smt_helper.remove_reg_from_sym_srcs(lhs, src_names)
            smt_helper.remove_reg_from_sym_srcs(rhs, src_names)
        elif src.endswith(']'):
            new_srcs = smt_helper.get_mem_reg_source(src)
            src_names = list(set(src_names) - set(new_srcs))
        else:
            smt_helper.remove_reg_from_sym_srcs(src, src_names)
    return list(set(src_names))


def sym_bin_op(store, sym_names, dest, src1, src2=None):
    src_names = sym_names
    if smt_helper.check_source_is_sym(store, rip, dest, sym_names):
        src2 = dest if src2 == None else src2
        src_names = sym_bin_on_src(store, sym_names, src1)
        src_names = sym_bin_on_src(store, src_names, src2)
    return list(set(src_names))


def mov(store, sym_names, dest, src):
    src_names = sym_names
    if smt_helper.check_source_is_sym(store, rip, dest, sym_names):
        if src in lib.REG_NAMES:
            src_names = smt_helper.add_new_reg_src(sym_names, dest, src)
        elif src.endswith(']'):
            smt_helper.remove_reg_from_sym_srcs(dest, src_names)
            new_srcs, is_reg_bottom = smt_helper.get_bottom_source(src, store)
            if is_reg_bottom:
                src_names = src_names + new_srcs
            else:
                addr = sym_engine.get_effective_address(store, rip, src)
                src_names = src_names + [str(addr)]
    return list(set(src_names))


def lea(store, sym_names, dest, src):
    global still_tb
    src_names = sym_names
    if dest in src_names:
        src_names.remove(dest)
        new_srcs, still_tb = smt_helper.get_bottom_source(src, store)
        src_names = src_names + new_srcs
    return list(set(src_names))


def pop(store, sym_names, dest):
    global still_tb
    src_names = sym_names
    if dest in src_names:
        still_tb = False
    return src_names


def xchg(store, sym_names, dest, src):
    src_names = sym_names
    if smt_helper.check_source_is_sym(store, rip, dest, sym_names):
        src_names = smt_helper.add_new_reg_src(sym_names, dest, src)
    return src_names


def mul_op(store, sym_names, src):
    src_names = sym_names
    bits_len = utils.get_sym_length(src)
    a_reg, _, dest = lib.AUX_REG_INFO[bits_len]
    src_names = sym_bin_op(store, sym_names, dest, a_reg, src)
    return src_names


def imul(store, sym_names, dest, src1=None, src2=None):
    src_names = sym_names
    if src1 != None:
        if src2 == None:
            src_names = sym_bin_op(store, sym_names, dest, src1)
        else:
            src_names = sym_bin_op(store, sym_names, src1, src2)
    else:
        src_names = mul_op(store, sym_names, dest)
    return src_names


def div_op(store, sym_names, src):
    bits_len = utils.get_sym_length(src)
    qreg, rreg, dest = lib.AUX_REG_INFO[bits_len]
    src_names = sym_bin_op(store, sym_names, qreg + ':' +rreg, dest, src)
    return src_names


def cmpxchg(store, sym_names, dest, src):
    src_names = sym_names
    bits_len = utils.get_sym_length(dest)
    a_reg = lib.AUX_REG_INFO[bits_len][0]
    sym_lhs = sym_engine.get_sym(store, rip, a_reg, bits_len)
    sym_rhs = sym_engine.get_sym(store, rip, dest, bits_len)
    eq = sym_helper.is_equal(sym_lhs, sym_rhs)
    if eq == True:
        src_names = mov(store, sym_names, dest, src)
    else:
        src_names = mov(store, sym_names, a_reg, dest)
    return src_names
    

def cmov(store, sym_names, inst, dest, src):
    src_names = sym_names
    res = smt_helper.parse_predicate(store, inst, True, 'cmov')
    if res == False: pass
    else: src_names = mov(store, sym_names, dest, src)
    return src_names


def cmp_op(store, sym_names, dest, src):
    src_names = sym_names
    global need_stop, boundary, still_tb
    if smt_helper.check_source_is_sym(store, rip, src, sym_names):
        dest, src = src, dest
    if smt_helper.check_cmp_dest_is_sym(store, rip, dest, sym_names):
        sym_src = sym_engine.get_sym(store, rip, src)
        if sym_helper.sym_is_int_or_bitvecnum(sym_src):
            src_names = [dest]
            need_stop = True
            boundary = sym_helper.int_from_sym(sym_src)
        else:
            still_tb = False
    else:
        still_tb = False
    return src_names

INSTRUCTION_SEMANTICS_MAP = {
    'mov': mov,
    'lea': lea,
    'pop': pop,
    'add': sym_bin_op,
    'sub': sym_bin_op,
    'xor': sym_bin_op,
    'and': sym_bin_op,
    'or': sym_bin_op,
    'sar': sym_bin_op,
    'shr': sym_bin_op,
    'sal': sym_bin_op,
    'shl': sym_bin_op,
    'xchg': xchg,
    'cmp': cmp_op,
    'imul': imul,
    'mul': mul_op,
    'idiv': div_op,
    'div': div_op,
    'cmpxchg': cmpxchg,
    'movzx': mov,
    'movsx': mov,
    'movsxd': mov,
    'adc': sym_bin_op,
    'sbb': sym_bin_op
}


def parse_sym_src(store, curr_rip, inst, sym_names):
    global rip, need_stop, boundary, still_tb
    rip = curr_rip
    need_stop, boundary, still_tb = False, None, True
    if inst.startswith('lock '):
        inst = inst.split(' ', 1)[1]
    inst_split = inst.strip().split(' ', 1)
    inst_name = inst_split[0]
    src_names = sym_names
    if inst_name in INSTRUCTION_SEMANTICS_MAP:
        inst_op = INSTRUCTION_SEMANTICS_MAP[inst_name]
        inst_args = utils.parse_inst_args(inst_split)
        src_names = inst_op(store, sym_names, *inst_args)
    elif inst_name in ('nop', 'hlt'): pass
    elif inst_name.startswith('cmov'):
        inst_args = utils.parse_inst_args(inst_split)
        src_names = cmov(store, sym_names, inst, *inst_args)
    elif inst_name.startswith('rep'):
        inst = inst_split[1].strip()
        src_names, need_stop, boundary, still_tb = parse_sym_src(store, curr_rip, inst, sym_names)
    return src_names, need_stop, boundary, still_tb

