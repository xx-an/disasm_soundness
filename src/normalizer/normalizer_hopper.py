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
from ..common import lib
from ..common import utils
from ..common.inst_element import Inst_Elem
from . import helper
from .normalizer import Disasm

label_pattern = re.compile('^[A-Za-z_@.0-9]+:[A-Za-z_@.0-9 /]*$')
address_inst_pattern = re.compile('^00[0-9a-f]+         ')

imm_pat = re.compile('^0x[0-9a-fA-F]+$|^[0-9]+$|^-[0-9]+$|^-0x[0-9a-fA-F]+$|^[0-9a-fA-F]+$|^-[0-9a-fA-F]+$')
variable_expr_pat = re.compile(r'^[0-9a-zA-Z_@.]+:')

minus_expr_suffix_pat = re.compile(r'[0-9a-zA-Z_][ ]*-')

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
            code_section = False
            data_section = False
            variable_start = False
            label_addr_assigned = False
            variable_name = None
            for line in lines:
                line = line.strip()
                if line.startswith('; Section '):
                    section_name = line.split('Section', 1)[1].strip()
                    if section_name in lib.CODE_SEGMENTS:
                        code_section = True
                    elif section_name not in ('.init', '.fini'):
                        data_section = True
                    else:
                        code_section = False
                        data_section = False
                elif code_section:
                    if variable_start:
                        if line:
                            self._read_variable_value(line)
                        else:
                            variable_start = False
                    elif line == '; Variables:':
                        variable_start = True
                    elif address_inst_pattern.search(line):
                        address, inst = self._parse_line(line)
                        if address:
                            if label_name:
                                if not label_addr_assigned:
                                    label_addr_assigned = True
                                    self.label_address_map[label_name] = address
                            if inst:
                                inst = self._replace_inst_var_arg(address, inst)
                                self.address_inst_map[address] = inst
                                self.valid_address_no += 1
                    elif label_pattern.search(line):
                        label_name = line.rsplit(':')[0].strip()
                        label_addr_assigned = False
                elif data_section:
                    if variable_start:
                        address = self._read_line_address(line)
                        self.variable_value_map[variable_name] = address
                        variable_start = False
                    elif variable_expr_pat.match(line):
                        variable_name = line.strip().split(':', 1)[0].strip()
                        variable_start = True
        inst_addresses = sorted(list(self.address_inst_map.keys()))
        inst_num = len(inst_addresses)
        for idx, address in enumerate(inst_addresses):
            n_idx = idx + 1
            if n_idx < inst_num:
                rip = inst_addresses[n_idx]
            inst = self.address_inst_map[address]
            inst = self._format_inst(address, inst, rip)
            # print(hex(address) + ':' + inst)
            self.address_inst_map[address] = inst.strip()
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

    def _read_line_address(self, line):
        line_split = line.strip().split(' ', 1)
        address_str = line_split[0]
        address = int(address_str, 16)
        return address


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
                elif symbol.startswith('sub_'):
                    remaining = symbol.split('sub_', 1)[1].strip()
                    if imm_pat.match(remaining):
                        res = hex(int(remaining, 16))
                elif symbol.startswith('switch_table_'):
                    remaining = symbol.split('switch_table_', 1)[1].strip()
                    if imm_pat.match(remaining):
                        res = hex(int(remaining, 16))
                # else:
                #     print(symbol)
        return res
        
    def _reconstruct_w_replaced_val(self, stack, op_stack):
        res = ''
        for idx, val in enumerate(stack):
            if idx > 0:
                res += op_stack[idx - 1] + val
            else:
                res += val
        res = res.replace('+-', '-')
        return res


    def _replace_each_symbol(self, stack, op_stack, count):
        res = ''
        for idx, lsi in enumerate(stack):
            if not(lsi in lib.REG_NAMES or utils.imm_pat.match(lsi)):
                stack[idx] = self._replace_symbol(lsi, count)
        res = self._reconstruct_w_replaced_val(stack, op_stack)
        return res


    def _replace_each_expr(self, content, count):
        stack = []
        op_stack = []
        line = utils.rm_unused_spaces(content)
        line_split = utils.simple_operator_pat.split(line)
        for lsi in line_split:
            if utils.simple_operator_pat.match(lsi):
                op_stack.append(lsi)
            else:
                stack.append(lsi)
        res = self._replace_each_symbol(stack, op_stack, count)
        return res


    def _replace_symbol_with_value(self, address, inst_name, arg, count):
        res = arg
        if arg.endswith(']'):
            arg_split = arg.split('[', 1)
            prefix = arg_split[0].strip()
            mem_addr = arg_split[1].strip().rsplit(']', 1)[0].strip()
            mem_addr = self._replace_each_expr(mem_addr, count)
            res = prefix + ' [' + mem_addr + ']'
        elif '+' in arg or minus_expr_suffix_pat.search(arg):
            res = self._replace_each_expr(arg, count)
        else:
            res = self._replace_symbol(arg, count)
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

    def _exec_eval(self, arg):
        res = arg
        if arg.endswith(']'):
            arg_split = arg.split('[', 1)
            prefix = arg_split[0]
            mem_addr = arg_split[1].strip().rsplit(']', 1)[0].strip()
            mem_addr = helper.simulate_eval_expr(mem_addr)
            res = prefix + '[' + mem_addr + ']'
        else:
            res = helper.simulate_eval_expr(arg)
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
        res = helper.remove_hopper_brackets_from_seg_mem_rep(res)
        res = res.lower()
        return res



