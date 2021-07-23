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
from ..common import utils
from ..common.inst_element import Inst_Elem
from ..normalizer import helper


label_address_pattern = re.compile('^[0-9a-f]+ <[A-Za-z_@.0-9]+>:')
address_inst_pattern = re.compile('^[0-9a-f]+:[0-9a-f\t ]+')

class Disasm_Objdump(object):
    def __init__(self, disasm_path):
        self.disasm_path = disasm_path
        self.address_inst_map = {}
        self.address_label_map = {}
        self.valid_address_no = 0
        self.read_asm_info()
        self.inst_addresses = sorted(list(self.address_inst_map.keys()))

    def get_address_inst_map(self):
        return self.address_inst_map

    def read_asm_info(self):
        with open(self.disasm_path, 'r') as f:
            lines = f.readlines()
            valid_section = False
            for line in lines:
                if label_address_pattern.search(line):
                    address, label = self._parse_address_label(line)
                    self.address_label_map[address] = label
                    if label in helper.UNEXPLORED_FUNCTION_LABELS or label.endswith(('@plt', '.plt')):
                        valid_section = False
                    else:
                        valid_section = True
                elif address_inst_pattern.search(line):
                    address, inst = self._parse_line(line)
                    if inst:
                        inst = self.format_inst(address, inst)
                        self.address_inst_map[address] = inst
                        if valid_section:
                            self.valid_address_no += 1
                        else:
                            self.invalid_address_list.append(address)
        inst_addresses = sorted(list(self.address_inst_map.keys()))
        inst_num = len(inst_addresses)
        for idx, address in enumerate(inst_addresses):
            n_idx = idx + 1
            if n_idx < inst_num:
                rip = inst_addresses[n_idx]
            else:
                rip = -1
            self.address_inst_map[address] = inst
            self.address_next_map[address] = rip


    def _parse_line(self, line):
        address, inst = None, None
        line_split = line.split('\t', 2)
        if len(line_split) == 3:
            address_str = line_split[0].split(':')[0].strip()
            address = int(address_str, 16)
            inst = line_split[2].split('#')[0].split('<')[0].strip()
        return address, inst

    def _parse_line_address(self, line):
        address_str = re.match(r'^[ ]+[0-9a-f]+(?=:)', line)
        address = int(address_str.group(0).strip(), 16)
        return address

    def _parse_line_inst(self, line):
        inst = ''
        inst_str = re.findall(r' \t[^<#\n\t]+', line)
        if inst_str:
            inst = inst_str[-1].strip()
            inst = re.sub(r'\s+', ' ', inst).strip()
        return inst

    def _parse_address_label(self, line):
        line_split = line.strip().split(' ', 1)
        address = int(line_split[0].strip(), 16)
        label = line_split[1].split('<')[1].split('>')[0].strip()
        return address, label

    def _parse_line_bin_length(self, line):
        res = ''
        res_str = re.findall(r'\t[0-9a-f ]+', line)
        if res_str:
            res = res_str[0].replace(' ', '')
        return len(res) // 2

    def format_inst(self, address, inst):
        inst_elem = Inst_Elem(inst)
        return inst_elem.normalize(address, self._format_arg)

    def _format_arg(self, address, inst_name, arg):
        res = helper.norm_ptr_rep(arg)
        if utils.check_jmp_with_address(inst_name):
            res = helper.convert_to_hex(res)
        return res
