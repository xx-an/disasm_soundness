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

import os
import sys
from collections import deque
from ..common import utils
from ..common import lib
from .block import Block
from .constraint import Constraint
from .sym_store import Sym_Store
from ..semantics import semantics
from ..semantics import semantics_traceback
from ..semantics import smt_helper
from ..symbolic import sym_helper
from ..symbolic import sym_engine

class CFG(object):
    def __init__(self, address_sym_table, address_inst_map, address_next_map, start_address, main_address, disasm_type):
        self.block_set = {}
        self.block_stack = []
        self.address_block_map = {}
        self.address_sym_table = address_sym_table
        self.start_address = start_address
        self.address_inst_map = address_inst_map
        self.address_next_map = address_next_map
        self.disasm_type = disasm_type
        self.dummy_block = Block(None, None, '', None, None)
        self.main_address = main_address
        self.address_except_set = set()
        self.ret_call_address_map = {}
        self.address_jt_entries_map = {}
        self.indirect_inst_set = set()
        sym_store = Sym_Store(None, None, None, None)
        constraint = None
        self.retrieve_all_branch_inst()
        sym_helper.cnt_init()
        semantics.start_init(sym_store.store, start_address)
        self.build_cfg(start_address, sym_store, constraint)

    
    def build_cfg(self, start_address, sym_store, constraint):
        start_inst = self.address_inst_map[start_address]
        self.add_new_block(None, start_address, start_inst, sym_store, constraint)
        while self.block_stack:
            curr = self.block_stack.pop()
            utils.logger.info('%s: %s' % (hex(curr.address), curr.inst))
            # utils.logger.info(curr.sym_store.pp_store())
            address, inst, sym_store, constraint = curr.address, curr.inst, curr.sym_store, curr.constraint
            if utils.check_branch_inst(inst):
                self.construct_branch(curr, address, inst, sym_store, constraint)
            else:
                self.add_fall_through_block(curr, address, inst, sym_store, constraint)
            

    def construct_conditional_branches(self, block, address, inst, new_address, sym_store, constraint):
        res = smt_helper.parse_predicate(sym_store.store, inst, True)
        if res == False:
            self.add_fall_through_block(block, address, inst, sym_store, constraint)
        elif res == True:
            self.jump_to_block(block, address, inst, new_address, sym_store, constraint)
        else:
            jmp_constraint = self.add_new_constraint(sym_store.store, constraint, inst, True)
            self.jump_to_block(block, address, inst, new_address, sym_store, jmp_constraint)
            fall_through_constraint = self.add_new_constraint(sym_store.store, constraint, inst, False)
            self.add_fall_through_block(block, address, inst, sym_store, fall_through_constraint)
            

    def construct_branch(self, block, address, inst, sym_store, constraint):
        if inst == 'ret' or inst.endswith(' ret'):
            self.indirect_inst_set.add(address)
            self.build_ret_branch(block, address, inst, sym_store, constraint)
        else:
            jump_address_str = inst.split(' ', 1)[1].strip()
            new_address = smt_helper.get_jump_address(sym_store.store, sym_store.rip, jump_address_str)
            if not utils.imm_pat.match(jump_address_str):
                self.indirect_inst_set.add(address)
            if new_address in self.address_inst_map:
                utils.logger.info(hex(address) + ': jump address is ' + sym_helper.string_of_address(new_address))
                if utils.check_not_single_branch_inst(inst):    # je xxx
                    self.construct_conditional_branches(block, address, inst, new_address, sym_store, constraint)
                else:
                    if new_address in self.address_block_map and new_address in self.address_sym_table and new_address in self.ret_call_address_map.values():
                        if self._explored_func_block(sym_store, new_address):
                            func_name = self.address_sym_table[new_address][0]
                            self.external_branch(func_name, block, address, inst, sym_store, constraint)
                        else:
                            self.jump_to_block(block, address, inst, new_address, sym_store, constraint)
                    else:
                        self.jump_to_block(block, address, inst, new_address, sym_store, constraint)
            elif new_address in self.address_sym_table:
                ext_func_name = self.address_sym_table[new_address][0]
                self.external_branch(ext_func_name, block, address, inst, sym_store, constraint)
            elif sym_helper.sym_is_int_or_bitvecnum(new_address):
                ext_func_name = 'undefined'
                self.external_branch(ext_func_name, block, address, inst, sym_store, constraint)
                utils.logger.debug('Jump to an undefined external address ' + str(new_address) + ' at address ' + hex(address))
            elif str(new_address).startswith(utils.MEM_DATA_SEC_SUFFIX):
                ext_func_name = str(new_address)
                self.external_branch(ext_func_name, block, address, inst, sym_store, constraint)
                utils.logger.debug('Jump to an undefined external address ' + str(new_address) + ' at address ' + hex(address))
            else:
                self.handle_unresolved_indirect_jumps(block, address, inst, constraint, new_address)
                

    def handle_unresolved_indirect_jumps(self, block, address, inst, constraint, new_address):
        if inst.startswith('jmp ') and not inst.endswith(']'):
            trace_list = []
            res = self.trace_back(block, [inst.split(' ', 1)[1].strip()], trace_list)
            if res == -1:
                if constraint is not None:
                    res = self._check_path_reachability(constraint)
                    if res == False:
                        return
                utils.logger.info('Cannot resolve the jump address ' + sym_helper.string_of_address(new_address) + ' of ' + inst + ' at address ' + hex(address))
                # sys.exit('Cannot resolve the jump address ' + sym_helper.string_of_address(new_address) + ' of ' + inst + ' at address ' + hex(address))
        else:
            if constraint is not None:
                res = self._check_path_reachability(constraint)
                if res == False: 
                    utils.logger.info('The path is infeasible at the jump address ' + sym_helper.string_of_address(new_address) + ' of ' + inst + ' at address ' + hex(address) + '\n')
                    return
            utils.logger.info('Cannot resolve the jump address ' + sym_helper.string_of_address(new_address) + ' of ' + inst + ' at address ' + hex(address))
            # sys.exit('Cannot resolve the jump address ' + sym_helper.string_of_address(new_address) + ' of ' + inst + ' at address ' + hex(address))
                

    def external_branch(self, ext_func_name, block, address, inst, sym_store, constraint):
        utils.logger.debug('Execute the function: ' + ext_func_name + '\n')
        rip, store = sym_store.rip, sym_store.store
        if ext_func_name.startswith('__libc_start_main'):
            semantics.call(store, rip)
            next_address = self.main_address
            utils.logger.info(hex(address) + ': jump address is ' + sym_helper.string_of_address(next_address))
            semantics.ext__libc_start_main(store, self.main_address)
            self.jump_to_block(block, address, inst, next_address, sym_store, constraint)
        elif ext_func_name == 'pthread_create':
            store, rip, heap_addr = sym_store.store, sym_store.rip, sym_store.heap_addr
            jmp_sym_store = Sym_Store(store, rip, heap_addr)
            sym_rdi = sym_engine.get_sym(store, rip, 'rdi')
            if sym_helper.sym_is_int_or_bitvecnum(sym_rdi):
                semantics.ret(jmp_sym_store.store)
                rdi_val = sym_helper.int_from_sym(sym_rdi)
                if rdi_val in self.address_inst_map:
                    utils.logger.info(hex(address) + ': jump address is ' + sym_helper.string_of_address(rdi_val))
                    self.jump_to_block(block, address, inst, rdi_val, jmp_sym_store, constraint)
            fall_through_sym_store = Sym_Store(store, rip, heap_addr)
            semantics.ext_func_call(fall_through_sym_store.store, ext_func_name)
            self.build_ret_branch(block, address, inst, fall_through_sym_store, constraint)
        elif ext_func_name in (('malloc', 'calloc', 'realloc')):
            new_heap_addr = semantics.ext_alloc_mem_call(store, rip, sym_store.heap_addr, ext_func_name)
            sym_store.heap_addr = new_heap_addr
            self.build_ret_branch(block, address, inst, sym_store, constraint)
        else:
            semantics.ext_func_call(store, ext_func_name)
            ext_name = ext_func_name.split('@', 1)[0].strip()
            if ext_name not in lib.TERMINATION_FUNCTIONS:
                self.build_ret_branch(block, address, inst, sym_store, constraint)


    def build_ret_branch(self, block, address, inst, sym_store, constraint):
        new_address = semantics.ret(sym_store.store)
        if new_address != None:
            if sym_helper.sym_is_int_or_bitvecnum(new_address):
                utils.logger.info(hex(address) + ': the return address is {}'.format(hex(new_address)))
                if new_address in self.address_inst_map:
                    if new_address not in self.ret_call_address_map:
                        call_target = self._get_prev_inst_target(new_address)
                        if call_target:
                            self.ret_call_address_map[new_address] = call_target
                    self.jump_to_block(block, address, inst, new_address, sym_store, constraint)
                else:
                    self.jump_to_dummy(block)
            elif sym_helper.is_term_address(new_address):
                self.jump_to_dummy(block)
                utils.logger.info('The symbolic execution has been successfully terminated\n')
            else:
                if constraint is not None:
                    res = self._check_path_reachability(constraint)
                    if res == False: return
                # utils.logger.info('Cannot resolve the return address of ' + inst + ' at address ' + hex(address))
                # sys.exit('Cannot resolve the return address of ' + inst + ' at address ' + hex(address))
            

    def trace_back(self, blk, sym_names, trace_list):
        utils.logger.info('trace back')
        for _ in range(utils.MAX_TRACEBACK_COUNT):
            if blk.address in self.address_jt_entries_map:
                inst_dest, target_addresses = self.address_jt_entries_map[blk.address]
                self._reconstruct_jump_targets(blk, inst_dest, target_addresses)
                return 0
            if blk.parent_no in self.block_set:
                p_store = self.block_set[blk.parent_no].sym_store.store
            else:
                if blk.inst.startswith('cmp'):
                    p_store = blk.sym_store.store
                else:
                    return -1
            src_names, need_stop, boundary, still_tb = semantics_traceback.parse_sym_src(p_store, blk.sym_store.rip, blk.inst, sym_names)
            utils.logger.info(hex(blk.address) + ': ' + blk.inst)
            # utils.logger.info(src_names)
            # utils.logger.info(blk.sym_store.pp_store())
            if need_stop and len(src_names) == 1:
                trace_list = trace_list[::-1]
                src_name = src_names[0]
                src_len = utils.get_sym_length(src_name)
                rip = blk.sym_store.rip
                src_sym = sym_engine.get_sym(blk.sym_store.store, rip, src_name, src_len)
                cjmp_blk_idx, jt_idx_upperbound = utils.gen_jt_idx_upperbound(trace_list, boundary)
                if not jt_idx_upperbound: break
                jt_assign_blk_idx, is_jt_assign_inst = utils.check_jump_table_assign_inst(trace_list, cjmp_blk_idx)
                if not is_jt_assign_inst: break
                jt_assign_blk = trace_list[jt_assign_blk_idx]
                distinct_entries, inst_dest, src_len = self._get_distinct_jt_entries(jt_assign_blk, src_sym, jt_idx_upperbound)
                if not distinct_entries: break
                sym_store_list = self._reconstruct_jt_branches(jt_assign_blk, distinct_entries, inst_dest, src_len)
                dest, target_addresses = self._reconstruct_jump_target_addresses(trace_list, jt_assign_blk_idx, sym_store_list)
                if not target_addresses: break
                utils.logger.info(hex(trace_list[-1].address) + ': jump addresses resolved using jump table [' + ', '.join(map(lambda x: hex(sym_helper.int_from_sym(x)), target_addresses)) + ']')
                self._reconstruct_jump_targets(trace_list[-1], dest, target_addresses)
                return 0
            elif still_tb:
                trace_list.append(blk)
                blk = self.block_set[blk.parent_no]
                sym_names = src_names
            else: 
                utils.logger.info('\n')
                break
        return -1


    def add_fall_through_block(self, block, address, inst, sym_store, constraint):
        new_address = self._get_next_address(address)
        if new_address != -1:
            self.jump_to_block(block, address, inst, new_address, sym_store, constraint)


    def jump_to_block(self, block, address, inst, new_address, sym_store, constraint):
        new_inst = self.address_inst_map[new_address]
        _exist, new_sym_store = self.check_block_exist(block, address, inst, sym_store, constraint, new_address, new_inst)
        if not _exist:
            if new_sym_store:
                self._add_new_block(block, new_address, new_inst, new_sym_store, constraint)
            else:
                self.add_new_block(block, new_address, new_inst, sym_store, constraint)
            

    def jump_to_dummy(self, block):
        block.add_to_children_list(self.dummy_block.block_no)
        

    def _add_block_based_on_predicate(self, parent_blk, address, inst, sym_store, constraint, rip, pred):
        sym_store = Sym_Store(sym_store.store, rip, sym_store.heap_addr)
        semantics.cmov(sym_store.store, rip, inst, pred)
        self._add_new_block(parent_blk, address, inst, sym_store, constraint)

    def add_new_block(self, parent_blk, address, inst, sym_store, constraint):
        rip = self._get_next_address(address)
        if inst.startswith('cmov'):
            prefix = 'cmov'
            res = smt_helper.parse_predicate(sym_store.store, inst, True, prefix)
            if res == True:
                self._add_block_based_on_predicate(parent_blk, address, inst, sym_store, constraint, rip, True)
            elif res == False:
                self._add_block_based_on_predicate(parent_blk, address, inst, sym_store, constraint, rip, False)
            else:
                self._add_block_based_on_predicate(parent_blk, address, inst, sym_store, constraint, rip, True)
                self._add_block_based_on_predicate(parent_blk, address, inst, sym_store, constraint, rip, False)
        else:
            sym_store = Sym_Store(sym_store.store, rip, sym_store.heap_addr, inst)
            self._add_new_block(parent_blk, address, inst, sym_store, constraint)


    def _add_new_block(self, parent_blk, address, inst, sym_store, constraint):
        parent_no = parent_blk.block_no if parent_blk is not None else None
        block = Block(parent_no, address, inst.strip(), sym_store, constraint)
        self.block_set[block.block_no] = block
        if address in self.address_block_map:
            _, blk = self.address_block_map[address]
            self.address_block_map[address][1] = block
            if blk.block_no in self.block_set:
                del self.block_set[blk.block_no]
        else:
            self.address_block_map[address] = [1, block]
        if parent_blk:
            parent_blk.add_to_children_list(block.block_no)
        if smt_helper.is_inst_aff_flag(sym_store.store, sym_store.rip, address, inst):
            self.aff_flag_inst = (inst, sym_store)
        self.block_stack.append(block)


    def add_new_constraint(self, store, constraint, inst, val, suffix='j'):
        pred_expr = smt_helper.parse_predicate(store, inst, val, suffix)
        new_constraint = self._update_new_constraint(pred_expr, constraint)
        return new_constraint


    def _update_new_constraint(self, pred_expr, constraint):
        new_constraint = constraint
        if pred_expr != None:
            new_constraint = Constraint(constraint, pred_expr)
        return new_constraint


    def _get_distinct_jt_entries(self, blk, src_sym, jt_idx_upperbound):
        res = []
        inst = blk.inst
        inst_arg_split = inst.split(' ', 1)[1].strip().split(',')
        inst_dest = inst_arg_split[0]
        inst_src = inst_arg_split[1].strip()
        src_len = utils.get_sym_length(inst_src)
        parent_blk = self.block_set[blk.parent_no]
        p_store = parent_blk.sym_store.store
        for idx in range(jt_idx_upperbound):
            mem_address = sym_engine.get_jump_table_address(p_store, inst_src, src_sym, idx)
            mem_val = sym_engine.read_memory_val(p_store, mem_address, src_len)
            if not sym_helper.is_bit_vec_num(mem_val):
                return None, inst_dest, src_len
            if mem_val not in res:
                res.append(mem_val)
        return res, inst_dest, src_len
        

    def _reconstruct_jt_branches(self, blk, distinct_entries, inst_dest, src_len):
        inst = blk.inst
        rip, store, heap_addr = blk.sym_store.rip, blk.sym_store.store, blk.sym_store.heap_addr
        dest_len = utils.get_sym_length(inst_dest)
        sym_store_list = []
        inst_name = inst.split(' ', 1)[0]
        for mem_val in distinct_entries:
            new_sym_store = Sym_Store(store, rip, heap_addr)
            if inst_name == 'mov':
                sym_engine.set_sym(new_sym_store.store, rip, inst_dest, mem_val)
            elif 's' in inst_name:
                semantics.mov_op(new_sym_store.store, inst_dest, dest_len, mem_val, src_len, True)
            elif 'z' in inst_name:
                semantics.mov_op(new_sym_store.store, inst_dest, dest_len, mem_val, src_len, False)
            sym_store_list.append(new_sym_store)
        return sym_store_list


    def _reconstruct_jump_target_addresses(self, trace_list, blk_idx, sym_store_list):
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
                self.address_jt_entries_map[address] = (inst_dest, target_addresses)
                return inst_dest, target_addresses
            else:
                for sym_store in sym_store_list:
                    sym_store.rip = rip
                    sym_store.parse_semantics(inst)
        return None, None


    def _reconstruct_jump_targets(self, blk, inst_dest, target_addresses):
        address, inst = blk.address, blk.inst
        rip, store, heap_addr, constraint = blk.sym_store.rip, blk.sym_store.store, blk.sym_store.heap_addr, blk.constraint
        for target_addr in target_addresses:
            if self.disasm_type == 'bap' and target_addr not in self.address_inst_map:
                continue
            new_sym_store = Sym_Store(store, rip, heap_addr)
            sym_engine.set_sym(new_sym_store.store, rip, inst_dest, target_addr)
            self._add_new_block(blk, address, inst, new_sym_store, constraint)


    def remove_unreachable_tb_blocks(self, blk):
        address_list = []
        while blk:
            address = blk.address
            address_list.append(address)
            utils.logger.info('tb: ' + hex(address) + ' ' + blk.inst)
            if blk.parent_no in self.block_set:
                parent_blk = self.block_set[blk.parent_no]
                p_address = self._get_prev_address(address)
                if p_address != parent_blk.address:
                    if utils.check_not_single_branch_inst(parent_blk.inst):
                        break
            else:
                break
            blk = parent_blk
        for address in address_list:
            self.address_block_map[address][0] = 0


    def _check_path_reachability(self, constraint):
        res = True
        asserts, pred = constraint.get_asserts_and_query()
        asserts.append(pred)
        res = sym_helper.check_pred_satisfiable(asserts)
        return res


    def _get_prev_address(self, address):
        p_address = None
        for idx in range(1, utils.MAX_INST_ADDR_GAP):
            tmp = address - idx
            if tmp in self.address_inst_map:
                p_address = tmp
                break
        return p_address


    def _get_prev_inst_target(self, address):
        target = None
        p_address = self._get_prev_address(address)
        if p_address:
            p_inst = self.address_inst_map[p_address]
            if p_inst.startswith('call'):
                blk = self.address_block_map[p_address][1]
                jmp_target = smt_helper.get_jump_address(blk.sym_store.store, address, p_inst.split(' ', 1)[1].strip())
                if sym_helper.sym_is_int_or_bitvecnum(jmp_target):
                    target = jmp_target
        return target


    def _get_next_address(self, address):
        next_address = self.address_next_map[address]
        if next_address in self.address_sym_table: return -1
        return next_address


    def retrieve_all_branch_inst(self):
        for address, inst in self.address_inst_map.items():
            if utils.check_branch_inst(inst) or inst.startswith('cmov'):
                self.address_except_set.add(address)


    def _explored_func_block(self, sym_store, new_address):
        cnt, blk = self.address_block_map[new_address]
        if cnt > utils.MAX_VISIT_COUNT: return True
        elif cnt == 0: return False
        prev_sym_store = blk.sym_store
        new_inst = self.address_inst_map[new_address]
        new_sym_store = Sym_Store(sym_store.store, prev_sym_store.rip, sym_store.heap_addr, new_inst)
        res = new_sym_store.state_ith_eq(prev_sym_store, self.address_inst_map) and new_sym_store.aux_mem_eq(prev_sym_store, self.address_inst_map, lib.AUX_MEM)
        return res


    def check_block_exist(self, block, address, inst, sym_store, constraint, new_address, new_inst):
        if new_address not in self.address_except_set:
            _exist, res = self._exist_block(address, sym_store, new_address, new_inst)
            if _exist:
                block.add_to_children_list(res.block_no)
                return True, None
            else:
                return False, res
        elif utils.check_not_single_branch_inst(new_inst):
            inst, sym_store = self.aff_flag_inst
            smt_helper.add_aux_memory(sym_store.store, sym_store.rip, inst)
        return False, None
        

    def _exist_block(self, address, sym_store, new_address, new_inst):
        if new_address in self.address_block_map:
            cnt, blk = self.address_block_map[new_address]
            if cnt == 0:
                return False, None
            elif cnt > utils.MAX_VISIT_COUNT:
                utils.logger.info('Instruction ' + new_inst + ' at address ' + hex(new_address) + ' is visited for ' + str(cnt) + ' times\n')
                return True, blk
            prev_sym_store = blk.sym_store
            rip = prev_sym_store.rip
            new_sym_store = Sym_Store(sym_store.store, rip, sym_store.heap_addr, new_inst)
            new_sym_store.merge_store(prev_sym_store, self.address_inst_map)
            # if not new_sym_store.state_ith_eq(prev_sym_store) or not new_sym_store.aux_mem_eq(prev_sym_store, lib.AUX_MEM):
            #     new_sym_store.merge_store(prev_sym_store, self.address_inst_map)
            #     return False, new_sym_store
            if new_sym_store.state_equal(prev_sym_store, self.address_inst_map): 
                utils.logger.info('Block exists: ' + new_inst + ' at address ' + hex(new_address) + ' is visited for ' + str(cnt) + ' times\n')
                # utils.logger.info(prev_sym_store.pp_store())
                # utils.logger.info(sym_store.pp_store())
                # utils.logger.info(new_sym_store.pp_store())
                return True, blk
            else:
                self.address_block_map[new_address][0] = cnt + 1
                # new_sym_store.merge_store(prev_sym_store, self.address_inst_map)
                return False, new_sym_store
        return False, None


    def draw_cfg(self, start_block):
        block_set = []
        res = 'digraph cfg {\n'
        res += '    node [shape=record];\n'
        block_set.append(start_block)
        visited_block = []
        while block_set:
            block = self.block_stack.pop()
            if block not in visited_block:
                res += block.draw()
                res += block.draw_edge()
                children_list = block.children_blk_list
                for blk_no in children_list:
                    block_set.append(self.block_set[blk_no])
                visited_block.append(block)
        res += '}'
        with open('cfg.dot', 'w+') as f:
            f.write(res)
        utils.convert_dot_to_png('cfg')


    def reachable_addresses(self):
        res = set(self.address_block_map.keys())
        inst_addresses = sorted(list(self.address_inst_map.keys()))
        for address in inst_addresses:
            if address not in res:
                utils.aux_logger.info(hex(address) + ': ' + self.address_inst_map[address])
        return res
            
