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
from . import helper
from ..common import utils
from ..common.inst_element import Inst_Elem
from .disasm import Disasm

class Disasm_Dyninst(Disasm):
    def __init__(self, asm_path):
        self.asm_path = asm_path
        self.address_inst_map = {}
        self.address_next_map = {}
        self.read_asm_info()
        self.valid_address_no = len(self.address_inst_map)

        
    def get_address_inst_map(self):
        return self.address_inst_map


    def read_asm_info(self):
        with open(self.asm_path, 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip()
                if line and not line.startswith('"'):
                    address, inst, bin_len = self._parse_line(line)
                    if inst.startswith('rep'):
                        inst_split = inst.split(' ', 1)
                        inst = inst_split[0] + ' ' + self._format_inst(address, inst_split[1], bin_len)
                    else:
                        inst = self._format_inst(address, inst, bin_len)
                    self.address_inst_map[address] = inst
                    self.address_next_map[address] = address + bin_len


    # line: '88a(4): mov 0xfffffff8(%rbp),%rax'
    def _parse_line(self, line):
        line_split = utils.remove_multiple_spaces(line).split(': ', 1)
        address_binlen_split = line_split[0].strip().split('(')
        address = int(address_binlen_split[0], 16)
        bin_len = int(address_binlen_split[1].split(')')[0], 16)
        inst = line_split[1].strip()
        return address, inst.lower(), bin_len


    def _format_inst(self, address, inst, bin_len):
        inst_elem = Inst_Elem(inst)
        inst_elem.reverse_arg_order()
        inst_elem.inst_args = list(map(lambda x: helper.rewrite_dyninst_memory_rep(x), inst_elem.inst_args))
        byte_len_rep = helper.retrieve_bytelen_rep(inst_elem.inst_name, inst_elem.inst_args)
        if byte_len_rep:
            inst_elem.inst_args = list(map(lambda x: helper.add_att_memory_bytelen_rep(inst_elem.inst_name, x, byte_len_rep), inst_elem.inst_args))
        inst_elem.inst_args = helper.modify_dyninst_operands(inst_elem.inst_name, inst_elem.inst_args)
        inst_elem.inst_args = list(map(lambda x: helper.rewrite_dyninst_arg_format(inst_elem.inst_name, x), inst_elem.inst_args))
        if utils.check_jmp_with_address(inst_elem.inst_name):
            rip = address + bin_len
            inst_elem.inst_args[0] = helper.calculate_dyninst_jmp_address(inst_elem.inst_args[0], address, rip)
        #     inst_elem.inst_args[0] = helper.add_jump_address_wordptr_rep(inst_elem.inst_args[0])
        #     rip = address + bin_rep_len
        #     inst_elem.inst_args[0] = helper.calculate_absolute_address(inst_elem.inst_args[0], rip)
        inst_elem.inst_name = helper.normalize_dyninst_inst_name(inst_elem.inst_name)
        inst = inst_elem.normalize(address, self._format_arg, self._rewrite_inst)
        if inst.startswith('ret '): inst = 'ret'
        return inst

    def _format_arg(self, address, inst_name, arg):
        return arg

    def _rewrite_inst(self, inst):
        inst = inst.replace(' + ', '+').replace(' - ', '-').replace(' * ', '*')
        if inst == 'cdq rax':
            inst = 'cqo'
        elif inst == 'cdq eax':
            inst = 'cdq'
        return inst



