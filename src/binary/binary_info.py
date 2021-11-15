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
import re
import sys
from ..common import utils
from ..symbolic import sym_helper


class Binary_Info(object):
    def __init__(self, src_path):
        self.src_path = src_path
        self.section_address_map = {}
        self.sym_table = {}
        self.sym_type_table = {}
        self.sym_name_count = {}
        self.address_sym_table = {}
        self.data_start_addr = sys.maxsize
        self.data_base_addr = None
        self.rodata_start_addr = sys.maxsize
        self.rodata_base_addr = None
        self.rodata_end_addr = -sys.maxsize - 1
        self.read_binary_info()


    def read_binary_info(self):
        elf_header = utils.execute_command('objdump -f ' + self.src_path)
        self._parse_entry_address(elf_header)
        section_headers = utils.execute_command('objdump -h ' + self.src_path)
        self._parse_section_headers(section_headers)
        sym_table = utils.execute_command('objdump -t ' + self.src_path)
        self._parse_sym_table(sym_table)
        relocation = utils.execute_command('objdump -R ' + self.src_path)
        self._parse_relocation(relocation)
        self._reverse_sym_table()


    def get_entry_address(self):
        return self.entry_address


    #   Entry point address:               0x530
    def _parse_entry_address(self, binary_header):
        lines = binary_header.split('\n')
        for line in lines:
            line = line.strip()
            if line and line.startswith('start address '):
                self.entry_address = int(line.rsplit(' ', 1)[1], 16)


    #     0 .interp       0000001c  0000000000000238  0000000000000238  00000238  2**0
    def _parse_section_headers(self, section_headers):
        lines = section_headers.split('\n')
        for line in lines:
            line = line.strip()
            if line and utils.imm_start_pat.match(line):
                line = utils.remove_multiple_spaces(line)
                line_split = line.split(' ')
                section_name = line_split[1]
                section_size = int(line_split[2], 16)
                section_address = int(line_split[3], 16)
                section_offset = int(line_split[4], 16)
                self.sym_table[section_name] = section_address
                self.section_address_map[section_name] = section_address
                if section_name == '.data':
                    self.data_start_addr = section_address
                    self.data_base_addr = section_address - section_offset
                    self.data_end_addr = section_address + section_size + 1
                elif section_name == '.rodata':
                    self.rodata_start_addr = section_address
                    self.rodata_base_addr = section_address - section_offset
                    self.rodata_end_addr = section_address + section_size + 1
                elif section_name == '.text':
                    self.code_base_addr = section_address - section_offset



    # section_name: '.note.gnu.build-i'
    # output: '.note.gnu.build-id'
    def _correctify_section_name(self, section_name):
        res = section_name
        if len(section_name) == 17:
            for sect_name in self.section_list:
                if sect_name.startswith(section_name):
                    res = sect_name
                    break
        return res


    # line: '58: 000000000000063a    23 FUNC    GLOBAL DEFAULT   14 main'
    def _parse_sym_table(self, sym_list_str):
        lines = sym_list_str.split('\n')
        for line in lines:
            line = line.strip()
            if line and utils.imm_start_pat.match(line) and '*ABS*' not in line:
                line_split = utils.remove_multiple_spaces(line).split(' ')
                sym_val = int(line_split[0], 16)
                if sym_val >= self.data_start_addr:
                    sym_val = sym_helper.gen_spec_sym(utils.MEM_DATA_SEC_SUFFIX + hex(sym_val))
                sym_name = self._correctify_sym_name(line_split[-1])
                if sym_name not in self.section_address_map:
                    if sym_name not in self.sym_table:
                        self.sym_table[sym_name] = sym_val
                        self.sym_name_count[sym_name] = 1
                    else:
                        new_sym_name = sym_name + '_' + str(self.sym_name_count[sym_name])
                        self.sym_table[new_sym_name] = sym_val
                        self.sym_name_count[sym_name] += 1
        self.main_address = self.sym_table['main'] if 'main' in self.sym_table else None


    def _correctify_sym_name(self, sym_name):
        res = sym_name
        if '@' in sym_name:
            res = sym_name.split('@', 1)[0]
        return res


    # line: '000000200fe0  000300000006 R_X86_64_GLOB_DAT 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0'
    def _parse_relocation(self, relocation):
        lines = relocation.split('\n')
        for line in lines:
            line = line.strip()
            if line and '*ABS*' not in line and utils.imm_start_pat.match(line):
                line = utils.remove_multiple_spaces(line)
                line_split = line.split(' ')
                self._parse_reloc(line_split)



    # line: '000000200fe0  000300000006 R_X86_64_GLOB_DAT 0000000000000000 __libc_start_main@GLIBC_2.2.5'
    def _parse_reloc(self, line_split):
        sym_name = line_split[-1]
        sym_addr = sym_helper.gen_spec_sym('mem@' + hex(int(line_split[0], 16)))
        if 'GLIBC' in sym_name:
            sym_name = sym_name.split('@', 1)[0]
        if sym_name in self.sym_table:
            self.sym_table[sym_name] = sym_addr


    def _reverse_sym_table(self):
        for sym in self.sym_table:
            address = self.sym_table[sym]
            if address is not None:
                if address in self.address_sym_table:
                    self.address_sym_table[address].append(sym)
                else:
                    self.address_sym_table[address] = [sym]
