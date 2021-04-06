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
from ..common import utils
from ..common.inst_element import Inst_Elem
from . import helper
from .disasm import Disasm

label_address_pattern = re.compile('^[0-9a-f]+ <[A-Za-z_@.0-9]+>:')
address_inst_pattern = re.compile('^[0-9a-f]+:[0-9a-f\t ]+')


class Disasm_Objdump(Disasm):
    def __init__(self, disasm_path):
        self.disasm_path = disasm_path
        self.address_inst_map = {}
        self.address_next_map = {}
        self.valid_address_no = 0
        self.read_asm_info()


    def get_address_inst_map(self):
        return self.address_inst_map


    def read_asm_info(self):
        with open(self.disasm_path, 'r') as f:
            lines = f.readlines()
            valid_section = False
            for line in lines:
                if label_address_pattern.search(line):
                    label = self._parse_address_label(line)
                    if label in helper.INVALID_SECTION_LABELS or label.endswith(('@plt', '.plt')):
                        valid_section = False
                    else:
                        valid_section = True
                elif address_inst_pattern.search(line):
                    address, inst, bin_len = self._parse_line(line)
                    if inst:
                        inst = self._format_inst(address, inst)
                        self.address_inst_map[address] = inst
                        if valid_section:
                            self.valid_address_no += 1
        inst_addresses = sorted(list(self.address_inst_map.keys()))
        inst_num = len(inst_addresses)
        for idx, address in enumerate(inst_addresses):
            n_idx = idx + 1
            if n_idx < inst_num:
                rip = inst_addresses[n_idx]
            else:
                rip = address + bin_len
            self.address_next_map[address] = rip


    def _parse_line(self, line):
        address, inst = None, None
        line_split = line.split('\t', 2)
        bin_len = 0
        if len(line_split) == 3:
            address_str = line_split[0].split(':')[0].strip()
            address = int(address_str, 16)
            bin_len = len(line_split[1].strip().split(' '))
            inst = line_split[2].split('#')[0].split('<')[0].strip()
        return address, inst, bin_len


    def _parse_address_label(self, line):
        line_split = line.strip().split(' ', 1)
        label = line_split[1].split('<')[1].split('>')[0].strip()
        return label


    def _format_inst(self, address, inst):
        inst_elem = Inst_Elem(inst)
        return inst_elem.normalize(address, self._format_arg)


    def _format_arg(self, address, inst_name, arg):
        res = arg.lower()
        res = helper.convert_to_hex_rep(res)
        res = helper.norm_objdump_arg(inst_name, res)
        return res



