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
from ..common import lib
from ..common import utils
from ..common.inst_element import Inst_Elem
from . import helper
from .normalizer import Disasm

section_name_address_pattern = re.compile('^[0-9a-f]+ <[A-Za-z_@.0-9]+>:')
label_pattern = re.compile('^[A-Za-z_@.0-9]+:[A-Za-z_@.0-9 /]*$')
address_inst_pattern = re.compile('^000000[0-9a-f]+         ')

letter_num_neg_pat = re.compile(r'\w+')
sym_pat = re.compile(r'\W+')
imm_pat = re.compile('^0x[0-9a-fA-F]+$|^[0-9]+$|^-[0-9]+$|^-0x[0-9a-fA-F]+$|^[0-9a-fA-F]+$|^-[0-9a-fA-F]+$')

class Disasm_Hopper(Disasm):
    def __init__(self, disasm_path):
        self.disasm_path = disasm_path
        self.address_inst_map = {}
        self.address_next_map = {}
        self.label_address_map = {}
        self.variable_value_map = {}
        self.valid_address_no = 0
        self.read_asm_info()


    def get_address_inst_map(self):
        return self.address_inst_map


    def read_asm_info(self):
        with open(self.disasm_path, 'r') as f:
            lines = f.readlines()
            label_name = None
            valid_section = False
            variable_start = False
            label_addr_assigned = False
            for line in lines:
                line = line.strip()
                # if to_parsed_section:
                if variable_start:
                    if line:
                        self._read_variable_value(line)
                    else:
                        variable_start = False
                elif line == '; Variables:':
                    variable_start = True
                elif line.startswith('; Section '):
                    section_name = line.split('Section', 1)[1].strip()
                    if section_name in (('.text', '.plt', '.plt.got')):
                        valid_section = True
                    else:
                        valid_section = False
                elif label_pattern.search(line):
                    label_name = line.rsplit(':')[0].strip()
                    label_addr_assigned = False
                elif address_inst_pattern.search(line):
                    address, inst = self._parse_line(line)
                    if address:
                        if label_name:
                            if not label_addr_assigned:
                                label_addr_assigned = True
                                self.label_address_map[label_name] = address
                    if valid_section:
                        if inst:
                            inst = self._replace_inst_var_arg(address, inst)
                            self.address_inst_map[address] = inst
                            self.valid_address_no += 1
        inst_addresses = sorted(list(self.address_inst_map.keys()))
        inst_num = len(inst_addresses)
        for idx, address in enumerate(inst_addresses):
            n_idx = idx + 1
            if n_idx < inst_num:
                rip = inst_addresses[n_idx]
            inst = self.address_inst_map[address]
            inst = self._format_inst(address, inst, rip)
            # print(hex(address) + ':' + inst)
            self.address_inst_map[address] = inst
            self.address_next_map[address] = rip


    # line: ;    var_20: int64_t, -32
    def _read_variable_value(self, line):
        if line.startswith(';') and ': ' in line:
            var_str = line.split(';', 1)[1].strip()
            var_split = var_str.split(':', 1)
            var_name = var_split[0].strip()
            var_value = var_split[1].strip().rsplit(',', 1)[-1].strip()
            var_value = int(var_value)
            self.variable_value_map[var_name] = var_value


    def _parse_line(self, line):
        address, inst = None, None
        if line:
            line_split = line.split(' ', 1)
            if len(line_split) == 2:
                address = int(line_split[0], 16)
                inst_str = line_split[1].strip().split(';', 1)[0].strip()
                if not inst_str.startswith(('extern function code', 'db ', 'align ')):
                    inst = inst_str
        return address, inst


    def _replace_inst_var_arg(self, address, inst, rip=None):
        inst_elem = Inst_Elem(inst)
        return inst_elem.normalize(address, self._replace_symbol_with_value, utils.id_op, 1)

    def _format_inst(self, address, inst, rip):
        inst_elem = Inst_Elem(inst)
        return inst_elem.normalize(address, self._format_arg, utils.id_op, rip)


    def _replace_symbol(self, symbol, count):
        res = symbol
        if not (utils.imm_start_pat.match(symbol) or symbol in lib.REG_NAMES):
            if count == 1:
                if symbol in self.variable_value_map:
                    res = hex(self.variable_value_map[symbol])
            else:
                if symbol in self.label_address_map:
                    res = hex(self.label_address_map[symbol])
                elif symbol in self.variable_value_map:
                    res = hex(self.variable_value_map[symbol])
                elif symbol.startswith('loc_'):
                    remaining = symbol.split('loc_', 1)[1].strip()
                    if imm_pat.match(remaining):
                        res = hex(int(remaining, 16))
                elif symbol.startswith('switch_table_'):
                    remaining = symbol.split('switch_table_', 1)[1].strip()
                    if imm_pat.match(remaining):
                        res = hex(int(remaining, 16))
                # else:
                #     print(symbol)
        return res
        
    def _replace_to_times_elements(self, content, count):
        res = content
        c_split = content.split('*')
        for i, c in enumerate(c_split):
            c_split[i] = self._replace_symbol(c, count)
        res = '*'.join(c_split)
        return res

    def _replace_each_symbol(self, content, count):
        res = content
        if '+' in content:
            c_split = content.split('+')
            for idx, elem in enumerate(c_split):
                if '*' in elem:
                    c_split[idx] = self._replace_to_times_elements(elem, count)
                else:
                    c_split[idx] = self._replace_symbol(elem, count)
            res = '+'.join(c_split)
        elif '-' in content:
            c_split = content.split('-')
            for idx, elem in enumerate(c_split):
                if '*' in elem:
                    c_split[idx] = self._replace_to_times_elements(elem, count)
                else:
                    c_split[idx] = self._replace_symbol(elem, count)
            res = '-'.join(c_split)
        elif '*' in content:
            res = self._replace_to_times_elements(content, count)
        else:
            res = self._replace_symbol(content, count)
        return res

    def _replace_symbol_with_value(self, address, inst_name, arg, count):
        res = arg
        if arg.endswith(']'):
            arg_split = arg.split('[', 1)
            prefix = arg_split[0].strip()
            mem_addr = arg_split[1].strip().rsplit(']', 1)[0].strip()
            mem_addr = self._replace_each_symbol(mem_addr, count)
            res = prefix + ' [' + mem_addr + ']'
        else:
            res = self._replace_each_symbol(arg, count)
        return res

    def _move_segment_rep(self, arg):
        res = arg
        if arg.endswith(']') and ':' in arg:
            arg_split = arg.split('[', 1)
            prefix = arg_split[0].strip()
            mem_addr = arg_split[1].strip().rsplit(']', 1)[0].strip()
            if ':' in mem_addr:
                mem_addr_split = mem_addr.split(':', 1)
                res = prefix + ' ' + mem_addr_split[0] + ':[' + mem_addr_split[1] + ']'
        return res

    def _remove_ptr_rep_from_lea(self, inst_name, arg):
        res = arg
        if inst_name == 'lea' and ' ptr ' in arg:
            res = arg.split('ptr ', 1)[1].strip()
        return res


    def _eval_simple_formula(self, stack, op_stack):
        res = stack[0]
        for idx, op in enumerate(op_stack):
            if op == '+':
                res = res + stack[idx + 1]
            elif op == '-':
                res = res - stack[idx + 1]
        return res

    def _reconstruct_expr(self, stack, op_stack, idx_list, imm_val):
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


    def _cal_expr(self, stack, op_stack, content):
        res = content
        imm_item_list = [(idx, utils.imm_str_to_int(val)) for idx, val in enumerate(stack) if utils.imm_pat.match(val) and (idx == 0 or op_stack[idx - 1] in (('+', '-')))]
        idx_list = []
        val_list = []
        oper_list = []
        for idx, val in imm_item_list:
            n_val = val
            if idx > 0:
                op = op_stack[idx - 1]
                if val_list:
                    oper_list.append(op)
                else:
                    n_val = val if op == '+' else -val
            idx_list.append(idx)
            val_list.append(n_val)
        if len(val_list) > 1:
            imm_val = self._eval_simple_formula(val_list, oper_list)
            res = self._reconstruct_expr(stack, op_stack, idx_list, imm_val)
        return res


    def _eval_expr(self, content):
        stack = []
        op_stack = []
        line = content.strip()
        line_split = re.split(r'(\W+)', line)
        for lsi in line_split:
            lsi = lsi.strip()
            if re.match(r'\w+|-\w+', lsi):
                val = lsi
                stack.append(val)
            else:
                op_stack.append(lsi)
        res = self._cal_expr(stack, op_stack, content)
        return res


    def _exec_eval(self, arg):
        res = arg
        if arg.endswith(']'):
            arg_split = arg.split('[', 1)
            prefix = arg_split[0]
            mem_addr = arg_split[1].strip().rsplit(']', 1)[0].strip()
            mem_addr = self._eval_expr(mem_addr)
            res = prefix + '[' + mem_addr + ']'
        else:
            res = self._eval_expr(arg)
        return res



    def _format_arg(self, address, inst_name, arg, rip):
        res = self._replace_symbol_with_value(address, inst_name, arg, 2)
        res = helper.add_or_remove_ptr_rep_arg(inst_name, res)
        res = res.replace('+-', '-')
        res = self._move_segment_rep(res)
        res = self._remove_ptr_rep_from_lea(inst_name, res)
        res = self._exec_eval(res)
        res = helper.rewrite_absolute_address_to_relative(res, rip)
        res = helper.modify_st_rep(res)
        res = res.lower()
        return res



