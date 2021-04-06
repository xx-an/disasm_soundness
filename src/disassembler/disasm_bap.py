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

address_inst_pattern = re.compile('^[ ]+[0-9a-f]+:[0-9a-f\t ]+')
address_pattern = re.compile('^[0-9a-f]+|^-[0-9a-f]+')

class Disasm_Bap(Disasm):
    def __init__(self, asm_path):
        self.asm_path = asm_path
        self.address_inst_map = {}
        self.address_next_map = {}
        self.valid_address_no = 0
        self.read_asm_info()


    def get_address_inst_map(self):
        return self.address_inst_map


    def read_asm_info(self):
        valid_section = False
        with open(self.asm_path, 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip()
                if line.startswith('Disassembly of section '):
                    section_name = self._parse_section_name(line)
                    if section_name in helper.INVALID_SECTION_LABELS:
                        valid_section = False
                    else:
                        valid_section = True
                elif line and address_pattern.match(line) and '<' not in line and '  ' in line and ':' in line:
                    address, inst, bin_len = self._parse_line(line)
                    if inst:
                        self.address_next_map[address] = address + bin_len
                        if inst.startswith('rep'):
                            inst_split = inst.split(' ', 1)
                            inst = inst_split[0] + ' ' + self._format_inst(address, inst_split[1], bin_len)
                        else:
                            inst = self._format_inst(address, inst, bin_len)
                        if inst.startswith(('shr ', 'sar ', 'shl ', 'sal ', 'rol ', 'ror ')) and ',' not in inst:
                            inst = inst + ', 1'
                        self.address_inst_map[address] = inst
                        if valid_section:
                            self.valid_address_no += 1
        

    # line: '4ec: "520: ff 25 d2 0a 20 00                            jmpq *0x200ad2(%rip)'
    def _parse_line(self, line):
        line_split = line.split(':', 1)
        address = int(line_split[0], 16)
        inst = line_split[1].strip()
        bin_len = 0
        inst_split = inst.split('  ', 1)
        if len(inst_split) == 2:
            bin_rep = inst_split[0].strip()
            bin_len = len(bin_rep.split(' '))
            inst = inst_split[1].strip()
        return address, inst, bin_len


    def _parse_section_name(self, line):
        line_split = line.strip().rsplit(' ', 1)
        section_name = line_split[-1].strip()
        return section_name

    def _format_inst(self, address, inst, bin_len):
        # print(inst)
        inst_elem = Inst_Elem(inst)
        inst_elem.reverse_arg_order()
        inst_elem.inst_args = list(map(lambda x: helper.rewrite_att_memory_rep(inst_elem.inst_name, x), inst_elem.inst_args))
        inst_elem.inst_name, byte_len_rep = helper.rewrite_att_inst_name(inst_elem.inst_name, inst)
        if byte_len_rep:
            inst_elem.inst_args = list(map(lambda x: helper.add_att_memory_bytelen_rep(inst_elem.inst_name, x, byte_len_rep), inst_elem.inst_args))
        if utils.check_jmp_with_address(inst_elem.inst_name):
            rip = address + bin_len
            inst_elem.inst_args[0] = helper.calculate_absolute_address(inst_elem.inst_args[0], rip)
        inst_elem.inst_args = list(map(lambda x: helper.format_bap_lea_inst_arg(inst_elem.inst_name, x), inst_elem.inst_args))
        inst = inst_elem.normalize(address, self._format_arg, utils.id_op)
        # print(hex(address) + ': ' + inst)
        return inst

    def _format_arg(self, address, inst_name, arg):
        return arg

    def _rewrite_inst(self, inst):
        return inst



