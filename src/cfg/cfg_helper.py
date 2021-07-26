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
from ..symbolic import sym_helper
from ..symbolic import sym_engine
from .sym_store import Sym_Store
from ..semantics import semantics


def gen_cjmp_idx_upperbound(inst_name, boundary):
    res = None
    jmp_condition = inst_name.split('j', 1)[1]
    if jmp_condition.startswith('n'):
        rest = jmp_condition.split('n')[1]
        if rest in utils.OPPOSITE_FLAG_MAP:
            jmp_condition = utils.OPPOSITE_FLAG_MAP[rest]
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
        if utils.check_not_single_branch_inst(inst):
            res = gen_cjmp_idx_upperbound(inst.split(' ', 1)[0], boundary)
            break
    return idx, res


def get_prev_address(address, address_inst_map):
    p_address = None
    for idx in range(1, utils.MAX_INST_ADDR_GAP):
        tmp = address - idx
        if tmp in address_inst_map:
            p_address = tmp
            break
    return p_address


def get_next_address(address, address_next_map, address_sym_table):
    next_address = address_next_map[address]
    if next_address in address_sym_table: return -1
    return next_address


def check_jt_assign_inst(inst_args):
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
            res = check_jt_assign_inst(inst.split(' ', 1)[1].strip())
            if res: break
    return n_idx, res


def get_distinct_jt_entries(blk, src_sym, jt_idx_upperbound, block_set):
    res = []
    inst = blk.inst
    inst_arg_split = inst.split(' ', 1)[1].strip().split(',')
    inst_dest = inst_arg_split[0]
    inst_src = inst_arg_split[1].strip()
    src_len = utils.get_sym_length(inst_src)
    parent_blk = block_set[blk.parent_no]
    p_store = parent_blk.sym_store.store
    for idx in range(jt_idx_upperbound):
        mem_address = sym_engine.get_jump_table_address(p_store, inst_src, src_sym, idx)
        mem_val = sym_engine.read_memory_val(p_store, mem_address, src_len)
        if not sym_helper.is_bit_vec_num(mem_val):
            return None, inst_dest, src_len
        if mem_val not in res:
            res.append(mem_val)
    return res, inst_dest, src_len


def reconstruct_jt_sym_stores(blk, distinct_entries, inst_dest, src_len):
    inst = blk.inst
    rip, store = blk.sym_store.rip, blk.sym_store.store
    dest_len = utils.get_sym_length(inst_dest)
    sym_store_list = []
    inst_name = inst.split(' ', 1)[0]
    for mem_val in distinct_entries:
        new_sym_store = Sym_Store(store, rip)
        if inst_name == 'mov':
            sym_engine.set_sym(new_sym_store.store, rip, inst_dest, mem_val)
        elif 's' in inst_name:
            semantics.mov_op(new_sym_store.store, inst_dest, dest_len, mem_val, src_len, True)
        elif 'z' in inst_name:
            semantics.mov_op(new_sym_store.store, inst_dest, dest_len, mem_val, src_len, False)
        sym_store_list.append(new_sym_store)
    return sym_store_list


def reconstruct_jt_target_addresses(trace_list, blk_idx, sym_store_list, address_jt_entries_map):
    for blk in trace_list[blk_idx + 1:]:
        address, inst, rip = blk.address, blk.inst, blk.sym_store.rip
        inst_split = inst.split(' ', 1)
        inst_name = inst_split[0]
        if utils.check_jmp_with_address(inst_name):
            inst_dest = inst_split[1].strip()
            target_addresses = []
            for sym_store in sym_store_list:
                target_addr = sym_engine.get_sym(sym_store.store, rip, inst_dest)
                target_addresses.append(target_addr)
            address_jt_entries_map[address] = (inst_dest, target_addresses)
            return inst_dest, target_addresses
        else:
            for sym_store in sym_store_list:
                sym_store.rip = rip
                sym_store.parse_semantics(inst)
    return None, None


def backtrack_to_start(block, address, block_set):
    trace_list = [address]
    parent_no = block.parent_no
    while parent_no:
        parent_blk = block_set[parent_no]
        p_address = parent_blk.address
        trace_list.append(p_address)
        parent_no = parent_blk.parent_no
    return trace_list


def pp_trace_list(trace_list, address_inst_map):
    utils.logger.debug(', '.join([hex(address) + ': ' + address_inst_map[address] for address in trace_list[::-1]]))
    # for address in trace_list:
    #     inst = address_inst_map[address]
    #     utils.logger.debug(hex(address) + ': ' + inst)
    #     utils.logger.debug(curr.sym_store.pp_store())