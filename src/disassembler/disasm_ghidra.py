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

LEN_REP_REG_MAP = {
    'q': 'rax',
    'd': 'eax',
    'w': 'ax',
    'b': 'al'
}

class Disasm_Ghidra(Disasm):
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
                    address, inst, bin_len = self._parse_line(line)
                    if inst:
                        self.address_inst_map[address] = inst
                        self.address_next_map[address] = address + bin_len


    # 00001240(4): SUB RSP,0x8
    def _parse_line(self, line):
        line_split = line.split(':', 1)
        address_binlen_split = line_split[0].split('(')
        address = int(address_binlen_split[0].strip(), 16)
        bin_len = int(address_binlen_split[1].split(')')[0].strip())
        inst = self._format_inst(address, line_split[1].strip(), bin_len)
        return address, inst, bin_len


    def _format_inst(self, address, inst, bin_len):
        inst = inst.lower()
        inst_elem = Inst_Elem(inst)
        rip = address + bin_len
        inst = inst_elem.normalize(address, self._format_arg, self._rewrite_inst, rip)
        return inst


    def _format_arg(self, address, inst_name, arg, rip):
        res = helper.convert_to_hex_rep(arg)
        res = helper.normalize_arg_byte_len_rep(res)
        if res.endswith(']'):
            res = res.replace('+ -', '- ')
        res = helper.rewrite_absolute_address_to_relative(res, rip)
        res = helper.switch_mem_arg_order(res)
        if '.rep' in inst_name:
            # inst_name_1 = inst_name.split('.', 1)[0]
            # byte_len_rep = helper.BYTE_REP_PTR_MAP[inst_name_1[-1]]
            res = ' [' + res + ']'
        res = helper.modify_st_rep(res)
        return res


    def _rewrite_inst(self, inst):
        res = inst.replace(' + ', '+').replace(' - ', '-')
        if '.rep' in res:
            inst_name, inst_args = res.split(' ', 1)
            inst_name_1, inst_name_0 = inst_name.split('.')
            if ',' not in inst_args and inst_name_1.startswith('stos'):
                inst_args = inst_args + ',' + LEN_REP_REG_MAP[inst_name_1[-1]]
            elif ',' not in inst_args and inst_name_1.startswith('scas'):
                inst_args = LEN_REP_REG_MAP[inst_name_1[-1]] + ',' + inst_args
            elif ',' in inst_args:
                inst_args_split = inst_args.split(',', 1)
                inst_args = inst_args_split[1] + ',' + inst_args_split[0]
            res = inst_name_0 + ' ' + inst_name_1 + ' ' + inst_args
        return res

