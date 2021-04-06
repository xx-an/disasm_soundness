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
from ..symbolic import sym_engine
from ..symbolic import sym_helper
from . import smt_helper
from . import ext_func_helper

rip = 0

def sym_bin_op(op):
    return lambda store, dest, src: sym_bin_oprt(store, op, dest, src)

def sym_bin_oprt(store, op, dest, src):
    dest_len = utils.get_sym_length(dest)
    res = sym_bin_op_na_flags(store, op, dest, src)
    smt_helper.modify_status_flags(store, res, dest_len)
    smt_helper.set_CF_flag(store, rip, dest, src, op)
    smt_helper.set_OF_flag(store, rip, dest, src, res, op)
    
    
def sym_bin_op_na_flags(store, op, dest, src):
    res = sym_engine.sym_bin_op(store, rip, op, dest, src)
    sym_engine.set_sym(store, rip, dest, res)
    return res


def mov(store, dest, src):
    dest_len = utils.get_sym_length(dest)
    sym_src = sym_engine.get_sym(store, rip, src, dest_len)
    sym_engine.set_sym(store, rip, dest, sym_src)
    

def lea(store, dest, src):
    address = sym_engine.get_effective_address(store, rip, src)
    sym_engine.set_sym(store, rip, dest, address)
    

def pop(store, dest):
    sym_rsp = sym_engine.get_sym(store, rip, 'rsp')
    res = sym_engine.get_mem_sym(store, sym_rsp)
    if res is None: 
        res = sym_helper.gen_sym()
    # else:
    #     sym_helper.remove_memory_content(store, sym_rsp)
    sym_engine.set_sym(store, rip, dest, res)
    sym_bin_op_na_flags(store, '+', 'rsp', '8')
    

def push(store, src):
    sym_src = sym_engine.get_sym(store, rip, src)
    sym_rsp = sym_bin_op_na_flags(store, '-', 'rsp', '8')
    sym_engine.set_mem_sym(store, sym_rsp, sym_src)

def push_val(store, sym_val):
    sym_rsp = sym_bin_op_na_flags(store, '-', 'rsp', '8')
    sym_engine.set_mem_sym(store, sym_rsp, sym_val)

def call(store, dest):
    push(store, hex(rip))


def ret(store):
    sym_rsp = sym_engine.get_sym(store, rip, 'rsp')
    res = sym_engine.get_mem_sym(store, sym_rsp)
    if res is not None: 
        sym_helper.remove_memory_content(store, sym_rsp)
    sym_bin_op_na_flags(store, '+', 'rsp', '8')
    if res != None and sym_helper.sym_is_int_or_bitvecnum(res):
        res = res.as_long()
    return res


def xchg(store, dest, src):
    if dest == src: return
    sym_dest, sym_src, _, _ = sym_engine.get_dest_src_sym(store, rip, dest, src)
    sym_engine.set_sym(store, rip, dest, sym_src)
    sym_engine.set_sym(store, rip, src, sym_dest)


def leave(store):
    mov(store, 'rsp', 'rbp')
    pop(store, 'rbp')


def cdqe(length):
    return lambda store: cdqe_op(store, length)

def cdqe_op(store, length):
    src = lib.AUX_REG_INFO[length][0]
    dest = lib.AUX_REG_INFO[length * 2][0]
    res = sym_engine.extension(store, rip, src, length * 2, True)
    sym_engine.set_sym(store, rip, dest, res)
    

def mov_with_extension(signed=False):
    return lambda store, dest, src: mov_ext(store, dest, src, signed)

def mov_ext(store, dest, src, signed):
    src_len = utils.get_sym_length(src)
    sym_src = sym_engine.get_sym(store, rip, src, src_len)
    dest_len = utils.get_sym_length(dest)
    mov_op(store, dest, dest_len, sym_src, src_len, signed)
    
def mov_op(store, dest, dest_len, sym_src, src_len, signed):
    sym = sym_engine.extension_sym(sym_src, dest_len, src_len, signed)
    sym_engine.set_sym(store, rip, dest, sym)


def mul(store, src):
    bits_len = utils.get_sym_length(src)
    a_reg, _, dest = lib.AUX_REG_INFO[bits_len]
    res = sym_engine.sym_bin_op(store, rip, 'umul', a_reg, src)
    sym_engine.set_sym(store, rip, dest, res)
    eq = sym_helper.is_equal(sym_helper.upper_half(res), 0)
    smt_helper.set_mul_OF_CF_flags(store, eq)
    


def imul(store, src, src1=None, src2=None):
    bits_len = utils.get_sym_length(src)
    if src1 != None:
        if src2 == None:
            tmp = sym_engine.sym_bin_op(store, rip, 'smul', src, src1)
        else:
            tmp = sym_engine.sym_bin_op(store, rip, 'smul', src1, src2)
        res = sym_helper.extract(bits_len - 1, 0, tmp)
        sym_engine.set_sym(store, rip, src, res)
        dest = src
    else:
        a_reg, _, dest = lib.AUX_REG_INFO[bits_len]
        tmp = sym_engine.sym_bin_op(store, rip, 'smul', a_reg, src)
        res = sym_helper.extract(bits_len - 1, 0, tmp)
        sym_engine.set_sym(store, rip, dest, tmp)
    eq = sym_helper.is_equal(simplify(SignExt(bits_len, res)), tmp)
    smt_helper.set_mul_OF_CF_flags(store, eq)
    


def div(signed=True):
    return lambda store, src: div_op(store, src, signed)

def div_op(store, src, signed):
    bits_len = utils.get_sym_length(src)
    qreg, rreg, dest = lib.AUX_REG_INFO[bits_len]
    div_op_name, rem_op_name = ('sdiv', 'smod') if signed else ('udiv', 'umod')
    quotient = sym_engine.sym_bin_op(store, rip, div_op_name, dest, src)
    remainder = sym_engine.sym_bin_op(store, rip, rem_op_name, dest, src)
    sym_engine.set_sym(store, rip, qreg, quotient)
    sym_engine.set_sym(store, rip, rreg, remainder)
    smt_helper.reset_all_flags(store)


def cmpxchg(store, dest, src):
    bits_len = utils.get_sym_length(dest)
    a_reg = lib.AUX_REG_INFO[bits_len][0]
    sym_lhs = sym_engine.get_sym(store, rip, a_reg, bits_len)
    sym_rhs = sym_engine.get_sym(store, rip, dest, bits_len)
    eq = sym_helper.is_equal(sym_lhs, sym_rhs)
    if eq == True:
        smt_helper.set_flag_direct(store, 'ZF', Bool(True))
        mov(store, dest, src)
    elif eq == False:
        smt_helper.set_flag_direct(store, 'ZF', Bool(False))
        mov(store, a_reg, dest)
    else:
        smt_helper.set_flag_direct(store, 'ZF', None)
        sym_engine.set_sym(store, rip, dest, sym_helper.gen_sym(bits_len))
        sym_engine.set_sym(store, rip, a_reg, sym_helper.gen_sym(bits_len))
    

def cmov(store, curr_rip, inst, pred):
    inst_split = inst.strip().split(' ', 1)
    inst_args = utils.parse_inst_args(inst_split)
    dest = inst_args[0]
    if pred:
        mov(store, dest, inst_args[1])
   

def set_op(store, inst, dest):
    dest_len = utils.get_sym_length(dest)
    res = smt_helper.parse_predicate(store, inst, True, 'set')
    if res == False:
        sym_engine.set_sym(store, rip, dest, sym_helper.bit_vec_val_sym(0, dest_len))
    elif res == True:
        sym_engine.set_sym(store, rip, dest, sym_helper.bit_vec_val_sym(1, dest_len))
    else: 
        sym_engine.set_sym(store, rip, dest, sym_helper.gen_sym(dest_len))


def rep(store, inst_name, inst):
    sym_rcx = sym_engine.get_sym(store, rip, 'rcx')
    rcx_is_0 = sym_helper.is_equal(sym_rcx, 0)
    while rcx_is_0 == False:
        res = parse_semantics(store, rip, inst)
        if res == -1: break
        sym_rcx = sym_bin_op_na_flags(store, '-', 'rcx', '1')
        rcx_is_0 = sym_helper.is_equal(sym_rcx, 0)
        if rcx_is_0 == True: break
        sym_zf = smt_helper.get_flag_direct(store, 'ZF')
        if inst_name in ('repz', 'repe') and sym_zf == False: break
        elif inst_name in ('repnz', 'repne') and sym_zf == True: break


def cmp_op(store, dest, src):
    sym_dest, sym_src, dest_len, _ = sym_engine.get_dest_src_sym(store, rip, dest, src)
    res = sym_engine.sym_bin_op(store, rip, '-', dest, src)
    if isinstance(res, BitVecNumRef):
        if not isinstance(sym_dest, BitVecNumRef) and not isinstance(sym_src, BitVecNumRef):
            tmp = res.as_long()
            if tmp != 0:
                res = sym_helper.gen_sym()
                sym_engine.set_sym(store, rip, src, sym_helper.gen_sym())
    smt_helper.modify_status_flags(store, res, dest_len)
    smt_helper.set_CF_flag(store, rip, dest, src, '-')
    smt_helper.set_OF_flag(store, rip, dest, src, res, '-')
    

def sym_bin_op_cf(op='+'):
    return lambda store, dest, src: sym_bin_op_with_cf(store, op, dest, src)

def sym_bin_op_with_cf(store, op, dest, src):
    dest_len = utils.get_sym_length(dest)
    sym_bin_oprt(store, op, dest, src)
    carry_val = smt_helper.get_flag_direct(store, 'CF')
    if carry_val == True:
        sym_bin_oprt(store, op, dest, '1')
    elif carry_val == False:
        pass
    else:
        sym_engine.set_sym(store, rip, dest, sym_helper.gen_sym(dest_len))


def test(store, dest, src):
    res = sym_engine.sym_bin_op(store, rip, '&', dest, src)
    dest_len = utils.get_sym_length(dest)
    smt_helper.modify_status_flags(store, res, dest_len)
    smt_helper.set_test_OF_CF_flags(store)


def neg(store, dest):
    dest_len = utils.get_sym_length(dest)
    sym_dest = sym_engine.get_sym(store, rip, dest, dest_len)
    eq = sym_helper.is_equal(sym_dest, 0)
    smt_helper._set_flag_neg_val(store, 'CF', eq)
    sym_engine.set_sym(store, rip, dest, sym_helper.neg(sym_dest))


def not_op(store, dest):
    dest_len = utils.get_sym_length(dest)
    sym_dest = sym_engine.get_sym(store, rip, dest, dest_len)
    sym_engine.set_sym(store, rip, dest, sym_helper.not_op(sym_dest))


def inc_dec(op):
    return lambda store, dest: inc_dec_op(store, op, dest)

def inc_dec_op(store, op, dest):
    dest_len = utils.get_sym_length(dest)
    res = sym_engine.sym_bin_op(store, rip, op, dest, '1')
    sym_engine.set_sym(store, rip, dest, res)
    smt_helper.modify_status_flags(store, res, dest_len)
    smt_helper.set_OF_flag(store, rip, dest, '1', res, op)


def rotate(to_left=True):
    return lambda store, dest, src: rotate_op(store, dest, src, to_left)

def rotate_op(store, dest, src, to_left):
    dest_len = utils.get_sym_length(dest)
    count = sym_engine.get_sym(store, rip, src, 8)
    if sym_helper.is_bit_vec_num(count):
        count = sym_helper.int_from_sym(count)
        mask = 0x3f if dest_len == 64 else 0x1f
        temp = (count & mask) % dest_len
        sym_dest = sym_engine.get_sym(store, rip, dest, dest_len)
        while temp != 0:
            if to_left:
                tmp = sym_helper.most_significant_bit(sym_dest, dest_len)
                sym_dest = sym_dest << 1
                if tmp == True:
                    sym_dest = sym_dest + 1
            else:
                tmp = sym_helper.least_significant_bit(sym_dest, dest_len)
                sym_dest = sym_dest >> 1
                if tmp == True: 
                    sym_dest = sym_dest + (1 << dest_len)
            sym_dest = simplify(sym_dest)
            temp -= 1
        sym_engine.set_sym(store, rip, dest, sym_dest)
        if count & mask != 0:
            if to_left:
                cf_val = sym_helper.least_significant_bit(sym_dest, dest_len)
            else:
                cf_val = sym_helper.most_significant_bit(sym_dest, dest_len)
            smt_helper._set_flag_val(store, 'CF', cf_val)
        if count & mask == 1:
            if to_left:
                of_val = simplify(Xor(sym_helper.most_significant_bit(sym_dest, dest_len), cf_val))
            else:
                of_val = simplify(Xor(sym_helper.most_significant_bit(sym_dest, dest_len), sym_helper.smost_significant_bit(sym_dest, dest_len)))
            smt_helper._set_flag_val(store, 'OF', of_val)
        else:
            smt_helper.set_flag_direct(store, 'OF')
    else:
        sym_engine.set_sym(store, rip, dest, sym_helper.gen_sym(dest_len))


def cdq(length):
    return lambda store: cdq_op(store, length)

def cdq_op(store, length):
    src, _, dest = lib.AUX_REG_INFO[length]
    res = sym_engine.extension(store, rip, src, length * 2, True)
    sym_engine.set_sym(store, rip, dest, res)
    

def bt(store, bit_base, bit_offset):
    sym_base = sym_engine.get_sym(store, rip, bit_base)
    sym_offset = sym_engine.get_sym(store, rip, bit_offset)
    offset_size = utils.get_sym_length(bit_offset)
    smt_helper.reset_all_flags_except_one(store, 'ZF')
    if sym_helper.is_bit_vec_num(sym_offset):
        offset = sym_offset.as_long()
        offset = offset % offset_size
        bit_selected = sym_helper.bit_ith(sym_base, offset)
        res = sym_helper.is_equal(bit_selected, 1)
        smt_helper._set_flag_val(store, 'CF', res)


def parse_semantics(store, curr_rip, inst):
    global rip
    rip = curr_rip
    # print(inst)
    if inst.startswith('lock '):
        inst = inst.split(' ', 1)[1]
    inst_split = inst.strip().split(' ', 1)
    inst_name = inst_split[0]
    if inst_name in INSTRUCTION_SEMANTICS_MAP:
        inst_op = INSTRUCTION_SEMANTICS_MAP[inst_name]
        inst_args = utils.parse_inst_args(inst_split)
        inst_op(store, *inst_args)
    elif inst_name in ('nop', 'hlt'): pass
    elif inst_name.startswith('set'):
        inst_args = utils.parse_inst_args(inst_split)
        set_op(store, inst, *inst_args)
    elif inst_name.startswith('rep'):
        inst = inst_split[1].strip()
        rep(store, inst_name, inst)
    elif inst_name.startswith('cmp'):
        smt_helper.reset_all_flags(store)
        return -1
    else:
        inst_args = utils.parse_inst_args(inst_split)
        sym_engine.undefined(store, rip, *inst_args)
        smt_helper.reset_all_flags(store)
        return -1
    return 0


INSTRUCTION_SEMANTICS_MAP = {
    'mov': mov,
    'lea': lea,
    'push': push,
    'pop': pop,
    'add': sym_bin_op('+'),
    'sub': sym_bin_op('-'),
    'xor': sym_bin_op('^'),
    'and': sym_bin_op('&'),
    'or': sym_bin_op('|'),
    'sar': sym_bin_op('>>'),
    'shr': sym_bin_op('>>>'),
    'sal': sym_bin_op('<<'),
    'shl': sym_bin_op('<<'),
    'xchg': xchg,
    'neg': neg,
    'not': not_op,
    'test': test,
    'cmp': cmp_op,
    'imul': imul,
    'mul': mul,
    'idiv': div(True),
    'div': div(False),
    'cmpxchg': cmpxchg,
    'movzx': mov_with_extension(False),
    'movsx': mov_with_extension(True),
    'movsxd': mov_with_extension(True),
    'cbw': cdqe(8),
    'cwde': cdqe(16),
    'cdqe': cdqe(32),
    'leave': leave,
    'inc': inc_dec('+'),
    'dec': inc_dec('-'),
    'adc': sym_bin_op_cf('+'),
    'sbb': sym_bin_op_cf('-'),
    'cwd': cdq(16),
    'cdq': cdq(32),
    'cqo': cdq(64),
    'ror': rotate(False),
    'rol': rotate(True),
    'bt': bt,
    'call': call
}


def start_init(store, _start_address):
    dests = lib.REG64_NAMES
    # dests = 'rax, rcx, rdx, r8, r9, r10, r11, rsi, rdi, rsp'
    # ext_func_helper.set_reg_val(store, rip, 'rbx')
    # ext_func_helper.set_reg_val(store, rip, 'r12', _start_address)
    # ext_func_helper.set_reg_val(store, rip, 'r14')
    # ext_func_helper.set_reg_val(store, rip, 'r15')
    ext_func_helper.set_regs_sym(store, rip, dests)
    sym_engine.set_sym(store, rip, 'rsp', sym_helper.bit_vec_val_sym(utils.INIT_STACK_FRAME_POINTER))
    ext_func_helper.set_segment_regs_sym(store, rip)
    utils.logger.debug('The following registers are set to symbolic value: ' + str(dests))
    ext_func_helper.clear_flags(store)
    sym_src = sym_helper.gen_sym()
    sym_rsp = sym_engine.get_sym(store, rip, 'rsp')
    # sym_engine.set_sym(store, rip, 'r13', sym_rsp)
    sym_engine.set_mem_sym(store, sym_rsp, sym_src)


def ext__libc_start_main(store, main_address):
    dests = ext_func_helper.regs_str_to_list('rcx, rdx, rsi, rdi, r8, r9, r10, r11')
    ext_func_helper.set_reg_val(store, rip, 'rax', main_address)
    ext_func_helper.set_regs_sym(store, rip, dests)
    sym_engine.set_sym(store, rip, 'rbp', sym_engine.get_sym(store, main_address, 'rcx'))
    ext_func_helper.clear_flags(store)
    sym_x = sym_helper.gen_sym_x()
    push_val(store, sym_x)


def ext_alloc_mem_call(store, rip, heap_addr, ext_func_name):
    mem_size = sym_engine.get_sym(store, rip, 'rdi')
    sym_engine.set_sym(store, rip, 'rax', sym_helper.bit_vec_val_sym(heap_addr))
    if sym_helper.sym_is_int_or_bitvecnum(mem_size):
        mem_size = mem_size.as_long()
        heap_addr += mem_size
    else:
        mem_size = utils.MAX_MALLOC_SIZE
        heap_addr += mem_size
    utils.MAX_HEAP_ADDR = max(utils.MAX_HEAP_ADDR, heap_addr)
    dests = ext_func_helper.regs_str_to_list('rcx, rdx, rsi, rdi, r8, r9, r10, r11')
    ext_func_helper.set_regs_sym(store, rip, dests)
    ext_func_helper.clear_flags(store)
    return heap_addr

def ext_rand_call(store):
    ext_func_call(store, 'rand')
    rax_val = sym_engine.get_sym(store, rip, 'rax')
    new_pred = simplify(rax_val >= 0)
    return new_pred


def ext_func_call(store, ext_func_name):
    dests = ext_func_helper.regs_str_to_list('rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11')
    ext_func_helper.set_regs_sym(store, rip, dests)
    ext_func_helper.clear_flags(store)


