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

class Disasm_Angr(Disasm):
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
                if line:
                    address, inst = self._parse_line(line)
                    if inst:
                        inst = self.format_inst(address, inst)
                        self.address_inst_map[address] = inst
        inst_addresses = sorted(list(self.address_inst_map.keys()))
        inst_num = len(inst_addresses)
        for idx, address in enumerate(inst_addresses):
            n_idx = idx + 1
            rip = inst_addresses[n_idx] if n_idx < inst_num else None
            self.address_next_map[address] = rip


    # line: '0x5f0:	cmp	byte ptr [rip + 0x200a19], 0'
    def _parse_line(self, line):
        line_split = utils.remove_multiple_spaces(line).split(' ', 1)
        address = int(line_split[0].split(':')[0], 16)
        inst = line_split[1]
        return address, inst


    def format_inst(self, address, inst):
        inst_elem = Inst_Elem(inst)
        inst = inst_elem.normalize(address, self._format_arg, self._rewrite_inst)
        return inst


    def _format_arg(self, address, inst_name, arg):
        res = helper.convert_to_hex_rep(arg)
        res = helper.normalize_arg_byte_len_rep(res)
        return res

    def _rewrite_inst(self, inst):
        res = inst.replace(' + ', '+').replace(' - ', '-')
        return res


