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
import sys
from ..common import lib
from ..common import utils
from ..common.inst_element import Inst_Elem
from . import helper
from .normalizer import Disasm

address_inst_pattern = re.compile('^[.a-zA-Z]+:[0-9a-zA-Z]{16}[ ]{17}[a-zA-Z]')

imm_pat = re.compile('^0x[0-9a-fA-F]+$|^[0-9]+$|^-[0-9]+$|^-0x[0-9a-fA-F]+$|^[0-9a-fA-F]+$|^-[0-9a-fA-F]+$')

variable_expr_pat = re.compile(r'^[.a-zA-Z_0-9]+:[0-9a-zA-Z]{16} [a-zA-Z0-9_]+')
ida_immediate_pat = re.compile(r'^[0-9A-F]+h')

subtract_hex_pat = re.compile(r'-[0-9a-fA-F]+h')

class Disasm_IDAPro(Disasm):
    def __init__(self, disasm_path):
        self.disasm_path = disasm_path
        self.address_inst_map = {}
        self.address_next_map = {}
        self._variable_offset_map = {}
        self._variable_value_map = {}
        self._variable_ptr_rep_map = {}
        self.valid_address_no = 0
        self._curr_ptr_rep = None
        self._global_data_name = set([])
        self._added_ptr_rep_map = {}
        self._ida_struct_table = lib.init_ida_struct_info()
        self._variable_w_ida_struct_type = {}
        self._address_line_map = {}
        self._ida_struct_types = list(self._ida_struct_table.keys())
        self.read_asm_info()
        

    def get_address_inst_map(self):
        return self.address_inst_map


    def read_asm_info(self):
        with open(self.disasm_path, 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip()
                if self._is_located_at_data_segments(line):
                    if variable_expr_pat.search(line):
                        var_name = self._retrieve_variable_name(line)
                        self._global_data_name.add(var_name)
            for line in lines:
                line = line.strip()
                if variable_expr_pat.search(line):
                    self._read_variable_value(line)
                elif self._is_located_at_code_segments(line):
                    if address_inst_pattern.search(line):
                        address, inst = self._parse_line(line)
                        if inst and not inst.startswith(('align', 'assume', 'public')):
                            inst = self._replace_inst_var_arg(address, inst, line)
                            self.address_inst_map[address] = inst
                            self._address_line_map[address] = line
                            self.valid_address_no += 1
        inst_addresses = sorted(list(self.address_inst_map.keys()))
        inst_num = len(inst_addresses)
        for idx, address in enumerate(inst_addresses):
            n_idx = idx + 1
            if n_idx < inst_num:
                rip = inst_addresses[n_idx]
            inst = self.address_inst_map[address]
            line = self._address_line_map[address]
            inst = self._format_inst(address, inst, rip)
            self.address_inst_map[address] = inst
            self.address_next_map[address] = rip


    # line: .text:0000000000002050 var_E0          = dword ptr -0E0h
    def _read_variable_value(self, line):
        line = utils.remove_multiple_spaces(line).strip()
        line = line.split(';', 1)[0].strip()
        line_split = line.split(' ', 1)
        address_str = line_split[0].rsplit(':', 1)[1].strip()
        address = int(address_str, 16)
        var_str = line_split[1].strip()
        var_split = var_str.split(' ', 1)
        var_name = var_split[0]
        if var_name == 'LOAD':
            pass
        elif ' db ' in var_str or ' dq ' in var_str or ' dw ' in var_str or ' dd ' in var_str or ' dt ' in var_str:
            var_suffix = var_split[1].strip().split(' ', 1)[0].strip()
            suffix = var_suffix[-1]
            self._variable_offset_map[var_name] = address
            self._variable_value_map[var_name] = address
            self._variable_ptr_rep_map[var_name] = helper.BYTE_REP_PTR_MAP[suffix]
        elif ' = ' in var_str:
            self._parse_variable_val_in_assignment_expr(line, var_split, var_name, address)
        elif var_name.startswith('xmmword_'):
            self._variable_offset_map[var_name] = address
            var_name_split = var_name.rsplit(':', 1)[0].strip().rsplit('_', 1)
            if len(var_name_split) == 2:
                var_value = var_name_split[1].strip()
                var_value = int(var_value, 16)
                self._variable_value_map[var_name] = var_value
                self._variable_ptr_rep_map[var_name] = 'xmmword ptr'
        elif ' proc ' in var_str or 'xmmword' in var_str:
            self._variable_offset_map[var_name] = address
            self._variable_value_map[var_name] = address
        elif  var_name.endswith(':'):
            var_name = var_name.rsplit(':', 1)[0].strip()
            self._variable_offset_map[var_name] = address
            self._variable_value_map[var_name] = address
        else:
            for ida_struct_type in self._ida_struct_types:
                if ' ' + ida_struct_type + ' ' in var_str:
                    self._variable_offset_map[var_name] = address
                    self._variable_value_map[var_name] = address
                    self._variable_w_ida_struct_type[var_name] = ida_struct_type
                    break


    def _parse_line(self, line):
        address, inst = None, None
        if line:
            line = utils.remove_multiple_spaces(line)
            line_split0 = line.split(';', 1)[0]
            line_split = line_split0.split(' ', 1)
            if len(line_split) == 2:
                address_str = line_split[0].rsplit(':', 1)[1].strip()
                address = int(address_str, 16)
                inst = line_split[1].strip()
        return address, inst


    def _replace_inst_var_arg(self, address, inst, line):
        inst_elem = Inst_Elem(inst)
        return inst_elem.normalize(address, self._replace_symbol_with_value, self._preprocess_format_inst, 1)

    def _preprocess_format_inst(self, inst):
        res = inst
        if ' short ' in inst:
            res = inst.replace(' short ', ' ')
        elif inst.startswith('lea') and not inst.endswith(']'):
            inst_split = inst.rsplit(',', 1)
            res = inst_split[0].strip() + ', ' + '[' + inst_split[1] + ']'
        return res


    def _format_inst(self, address, inst, rip):
        inst_elem = Inst_Elem(inst)
        inst_args = list(map(lambda x: self._format_arg(address, inst_elem.inst_name, x, rip), inst_elem.inst_args))
        result = self._postprocess_format_inst(address, inst, inst_elem.inst_name, inst_args)
        return result


    def _replace_symbol(self, symbol):
        symbol = symbol.strip()
        res = symbol
        if '.' in symbol:
            res = self._replace_ida_struct_item_symbol(symbol)
        elif ida_immediate_pat.match(symbol):
            res = utils.convert_imm_endh_to_hex(symbol)
        elif symbol in self._variable_value_map:
            res = hex(self._variable_value_map[symbol])
            if symbol in self._variable_ptr_rep_map:
                self._curr_ptr_rep = self._variable_ptr_rep_map[symbol]
        elif symbol.startswith('loc_'):
            remaining = symbol.split('loc_', 1)[1].strip()
            if imm_pat.match(remaining):
                res = hex(int(remaining, 16))
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


    def _replace_each_symbol(self, stack, op_stack):
        res = ''
        for idx, lsi in enumerate(stack):
            if not (lsi in lib.REG_NAMES or utils.imm_pat.match(lsi)):
                stack[idx] = self._replace_symbol(lsi)
        res = self._reconstruct_w_replaced_val(stack, op_stack)
        return res


    def _replace_each_expr(self, content):
        stack = []
        op_stack = []
        line = utils.rm_unused_spaces(content)
        line_split = utils.simple_operator_pat.split(line)
        for lsi in line_split:
            if utils.simple_operator_pat.match(lsi):
                op_stack.append(lsi)
            else:
                stack.append(lsi)
        res = self._replace_each_symbol(stack, op_stack)
        return res


    def _replace_symbol_with_value(self, address, inst_name, arg, count):
        res = arg
        self._curr_ptr_rep = None
        if arg.endswith(']'):
            arg_split = arg.split('[', 1)
            prefix = arg_split[0].strip()
            mem_addr_str = arg_split[1].strip().rsplit(']', 1)[0].strip()
            mem_addr = self._replace_each_expr(mem_addr_str)
            if 'ptr' in prefix:
                res = prefix + ' [' + mem_addr + ']'
            elif 's:' in prefix:
                prefix_split = prefix.split(':', 1)
                seg_reg = prefix_split[0]
                if len(prefix_split) == 2:
                    prefix_suffix = prefix_split[1].strip()
                    if utils.imm_pat.match(prefix_suffix):
                        res = '[' + mem_addr + '+' + prefix_suffix + ']'
                    else:
                        if prefix_suffix.startswith('(') and prefix_suffix.endswith(')'):
                            res = '[' + mem_addr + '+' + utils.extract_content(prefix_suffix) + ']'
                        else:
                            res = '[' + mem_addr + '+' + prefix_suffix + ']'
                else:
                    res = '[' + mem_addr + ']'
            elif self._curr_ptr_rep:
                self._added_ptr_rep_map[address] = True
                res = self._curr_ptr_rep + ' [' + mem_addr + ']'
            else:
                res = '[' + mem_addr + ']'
        elif arg in self._global_data_name:
            if count == 2:
                res = hex(self._variable_value_map[arg])
        else:
            res = self._replace_symbol(arg)
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


    def _exec_eval(self, arg):
        res = arg
        if arg.endswith(']'):
            arg_split = arg.split('[', 1)
            prefix = arg_split[0]
            mem_addr = arg_split[1].strip().rsplit(']', 1)[0].strip()
            mem_addr = helper.simulate_eval_expr(mem_addr)
            if '(' not in prefix:
                res = prefix + '[' + mem_addr + ']'
            else:
                res = '[' + mem_addr + ']'
        elif arg.startswith('(') and arg.endswith(')'):
            content = self._handle_offset_operation(arg)
            res = helper.simulate_eval_expr(content)
        else:
            res = helper.simulate_eval_expr(arg)
        return res
        

    def _remove_unused_seg_reg(self, arg):
        res = arg
        if 's:' in arg and not arg.endswith(']'):
            arg_split = arg.strip().split(':')
            prefix = arg_split[0].strip()
            remaining = arg_split[1].strip()
            if ida_immediate_pat.match(remaining):
                res = prefix + ':' + utils.convert_imm_endh_to_hex(remaining)
            else:
                if ' ptr ' in prefix:
                    prefix_split = prefix.rsplit(' ', 1)
                    ptr_rep = prefix_split[0].strip()
                    res = ptr_rep + ' [' + remaining + ']'
                else:
                    res = '[' + remaining + ']'
        return res


    def _replace_remaining_hex_w_suffix_h(self, inst):
        res = inst
        m = subtract_hex_pat.search(inst)
        if m:
            hex_str = m.group(0)
            new_hex_rep = utils.convert_imm_endh_to_hex(hex_str)
            res = inst.replace(hex_str, new_hex_rep)
        return res


    def _postprocess_format_inst(self, address, inst, inst_name, inst_args):
        length = None
        for idx, arg in enumerate(inst_args):
            if arg in lib.REG_NAMES:
                length = utils.get_sym_length(arg)
                break
        for idx, arg in enumerate(inst_args):
            if arg.endswith(']') or 's:' in arg:
                self._handle_ida_ptr_rep(address, inst, length, inst_name, inst_args, idx, arg)
        inst = inst_name + ' ' + ','.join(inst_args)
        inst = inst.strip()
        if inst in ('retn', 'retf') or inst.endswith((' retn', ' retf')):
            inst = inst[:-1]
        inst = self._replace_remaining_hex_w_suffix_h(inst)
        return inst


    def _format_arg(self, address, inst_name, arg, rip):
        res = self._remove_unused_seg_reg(arg)
        res = self._replace_symbol_with_value(address, inst_name, res, 2)
        res = res.replace('+-', '-')
        res = self._move_segment_rep(res)
        res = self._exec_eval(res)
        res = helper.rewrite_absolute_address_to_relative(res, rip)
        res = helper.modify_st_rep(res)
        res = self._remove_lea_ptr_rep(inst_name, res)
        res = res.lower()
        return res


    def _remove_lea_ptr_rep(self, inst_name, arg):
        res = arg
        if inst_name == 'lea':
            if arg.endswith(']'):
                res = '[' + arg.split('[', 1)[1].strip()
        return res


    def _handle_ida_ptr_rep(self, address, inst, length, inst_name, inst_args, idx, arg):
        if ' ptr ' not in arg or address in self._added_ptr_rep_map:
            ptr_rep = helper.generate_ida_ptr_rep(inst_name, inst, length)
            if ptr_rep is None:
                if address not in self._added_ptr_rep_map:
                    if (arg.endswith(']') and ' ptr ' not in arg) or 's:' in arg:
                        if length:
                            ptr_rep = helper.BYTELEN_REP_MAP[length]
                        elif inst_name in (('movsx', 'movzx')):
                            ptr_rep = 'word ptr'
                        else:
                            ptr_rep = 'dword ptr'
                        inst_args[idx] = ptr_rep + ' ' + arg
            else:
                if 's:' in arg:
                    inst_args[idx] = ptr_rep + ' ' + arg
                else:
                    inst_args[idx] = ptr_rep + ' [' + arg.split('[', 1)[1].strip()
      

    def _replace_ida_struct_item_symbol(self, symbol):
        res = symbol
        symbol_split = symbol.split('.', 1)
        symbol_name = symbol_split[0].strip()
        if symbol_name in self._variable_w_ida_struct_type:
            symbol_type = self._variable_w_ida_struct_type[symbol_name]
            item_entry = symbol_split[1].strip()
            if symbol_name in self._variable_value_map:
                if symbol_type in self._ida_struct_table:
                    offset, item_type = self._retrieve_ida_type_offset_type(symbol_type, item_entry)
                    res = hex(self._variable_value_map[symbol_name] + offset)
                    ptr_rep = helper.get_ida_ptr_rep_from_item_type(item_type)
                    if ptr_rep:
                        self._curr_ptr_rep = ptr_rep
                else:
                    sys.exit('We have not recorded the specific information for ida type ' + symbol_type)
        return res


    def _parse_variable_val_in_assignment_expr(self, line, var_split, var_name, address):
        self._variable_offset_map[var_name] = address
        var_value = var_split[1].split('=', 1)[1].strip()
        var_value_split = var_value.rsplit(' ', 1)
        ptr_rep = var_value_split[0].strip()
        type_spec = ptr_rep.split('ptr', 1)[0].strip()
        if type_spec not in helper.BYTE_LEN_REPS:
            if type_spec in self._ida_struct_table:
                self._variable_w_ida_struct_type[var_name] = type_spec
            else:
                print(line)
                sys.exit('We have not recorded the specific information for ida type ' + type_spec)
        else:
            self._variable_ptr_rep_map[var_name] = ptr_rep
        var_value = var_value_split[-1].strip()
        if var_value.endswith('h'):
            var_value = int(var_value.rsplit('h', 1)[0].strip(), 16)
            self._variable_value_map[var_name] = var_value
        elif utils.imm_pat.match(var_value):
            var_value = int(var_value)
            self._variable_value_map[var_name] = var_value


    def _is_located_at_code_segments(self, line):
        return line.startswith(lib.CODE_SEGMENTS)


    def _is_located_at_data_segments(self, line):
        return line.startswith(lib.DATA_SEGMENTS)


    def _retrieve_variable_name(self, line):
        line = utils.remove_multiple_spaces(line).strip()
        var_name = line.split(' ', 2)[1].strip()
        return var_name

    
    def _handle_offset_operation(self, arg):
        content = utils.extract_content(arg)
        if 'offset ' in content:
            original = None
            new_var = None
            content_split = re.split(r'(\W+)', content)
            for idx, ci in enumerate(content_split):
                if ci == 'offset':
                    if len(content) > idx + 2:
                        variable = content_split[idx + 2]
                        original = 'offset ' + variable
                        if variable in self._variable_offset_map:
                            new_var = hex(self._variable_offset_map[variable])
                    break
            if new_var:
                content = content.replace(original, new_var)
        return content


    def _retrieve_ida_type_offset_type(self, symbol_type, item_entry):
        if '.' in item_entry:
            new_symbol_type, new_item_entry = item_entry.split('.', 1)
            offset, item_type = self._ida_struct_table[symbol_type][new_symbol_type]
            new_offset, item_type = self._retrieve_ida_type_offset_type(item_type, new_item_entry)
            return offset + new_offset, item_type
        else:
            offset, item_type = self._ida_struct_table[symbol_type][item_entry]
            return offset, item_type
