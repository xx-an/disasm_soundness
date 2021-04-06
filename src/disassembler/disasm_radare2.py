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
import r2pipe
import sys
from . import helper
from ..common import utils
from ..common.inst_element import Inst_Elem
from .disasm import Disasm

SYM_NAME_PAT = re.compile(r'sym\.[0-9a-zA-Z._]+|obj\.[0-9a-zA-Z._]+|reloc\.[0-9a-zA-Z._]+|loc\.[0-9a-zA-Z._]+|entry\.[0-9a-zA-Z._]+|str\.[0-9a-zA-Z._:]+')
INST_REP_PAT = re.compile(r'^0x[0-9a-f]+      [0-9a-f]+')
SYM_REP_PAT = re.compile(r'^[0-9]+ ')


class Disasm_Radare2(Disasm):
    def __init__(self, asm_path, exec_path):
        self.asm_path = asm_path
        self.exec_path = exec_path
        self.sym_table = {}
        self.sym_name_count = {}
        self.address_inst_map = {}
        self.address_next_map = {}
        self.valid_address_no = 0
        self.parse_sym_table()
        self.read_asm_info()


    def parse_sym_table(self):
        r2_info = r2pipe.open(self.exec_path)
        sym_info = r2_info.cmd('is')
        sym_lines = sym_info.split('\n')
        for line in sym_lines:
            line = line.strip()
            if line and SYM_REP_PAT.match(line):
                s_info_split = utils.remove_multiple_spaces(line).split(' ')
                sym_name = s_info_split[-1]
                if utils.imm_pat.match(s_info_split[2]):
                    sym_address_str = hex(utils.imm_str_to_int(s_info_split[2]))
                if sym_name in self.sym_table:
                    new_sym_name = sym_name + '_' + str(self.sym_name_count[sym_name])
                    self.sym_table[new_sym_name] = sym_address_str
                    self.sym_name_count[sym_name] += 1
                else:
                    self.sym_table[sym_name] = sym_address_str
                    self.sym_name_count[sym_name] = 1



    def get_address_inst_map(self):
        return self.address_inst_map

    def read_asm_info(self):
        with open(self.asm_path, 'r') as f:
            lines = f.readlines()
            code_valid = False
            address, inst = None, ''
            prev_inst_str = ''
            for line in lines:
                line = line.strip()
                if line.startswith(';-- section.'):
                    code_valid = self._parse_section_valid(line)
                elif code_valid:
                    if INST_REP_PAT.match(line):
                        if prev_inst_str:
                            address, inst, bin_len = self._parse_line(prev_inst_str)
                            self.address_inst_map[address] = inst
                        prev_inst_str = line
                    elif line.startswith(';-'):
                        pass
                    else:
                        prev_inst_str = prev_inst_str + ' ' + line
            address, inst, bin_len = self._parse_line(prev_inst_str)
            self.address_inst_map[address] = inst
        inst_addresses = list(self.address_inst_map.keys())
        inst_num = len(inst_addresses)
        for idx, (address, inst) in enumerate(self.address_inst_map.items()):
            n_idx = idx + 1
            if n_idx < inst_num:
                rip = inst_addresses[n_idx]
            else:
                rip = address + bin_len
            if inst.startswith('rep'):
                inst_split = inst.split(' ', 1)
                inst = inst_split[0] + ' ' + self._format_inst(address, inst_split[1].strip(), rip)
            else:
                inst = self._format_inst(address, inst, rip)
            self.valid_address_no += 1
            self.address_inst_map[address] = inst
            self.address_next_map[address] = rip


    # line: ';-- section..text:'
    def _parse_section_valid(self, line):
        section_name = line.split(';-- section.')[1].split(':')[0]
        if section_name in (('.text', '.plt', '.plt.got')):
            return True
        else:
            return False


    # line1: '0x5f0:	cmp	byte ptr [rip + 0x200a19], 0'
    # line2: '0x0000054d      488d3de60000.  lea rdi, main                           ; sym.main'
    # line3: '0x00000546      488d0d130100.  lea rcx, sym.__libc_csu_init            ; 0x660'
    # line4: '0x00000634      ff15a6092000   call qword [reloc.__libc_start_main]    ; [0x200fe0:8]=0'
    def _parse_line(self, line):
        line_split = utils.remove_multiple_spaces(line).split(' ', 2)
        address = int(line_split[0], 16)
        inst = line_split[2].strip()
        inst_raw = inst
        inst_raw_split = inst_raw.split('; ')
        inst = inst_raw_split[0].strip()
        if 'sym.' in inst or 'obj.' in inst or 'reloc.' in inst or 'loc.' in inst: # call sym.imp.printf
            sym_name = SYM_NAME_PAT.search(inst).group(0)
            sym_name = sym_name.split('.', 1)[1].strip()
            res = self._replace_unknown_content(inst_raw_split, address, inst)
            if not res:
                if sym_name in self.sym_table:
                    sym_addr_str = self.sym_table[sym_name]
                    inst = self._replace_inst_sym(address, inst, sym_addr_str)
                else:
                    print(hex(address) + ': ' + inst)
                    sys.exit('Cannot find the address pointing to the string')
            else:
                inst = res      
        elif 'str.' in inst or 'entry.' in inst:
            res = self._replace_unknown_content(inst_raw_split, address, inst)
            if not res:
                print(hex(address) + ': ' + inst)
                sys.exit('Cannot find the address pointing to the string')
            inst = res
        elif 'main' in inst:
            sym_addr_str = self.sym_table['main']
            inst = self._replace_inst_sym(address, inst, sym_addr_str)
        elif 'entry0' in inst:
            sym_addr_str = self.sym_table['_start']
            inst = self._replace_inst_sym(address, inst, sym_addr_str)
        return address, inst, len(line_split[1]) // 2


    def _replace_unknown_content(self, inst_raw_split, address, inst):
        res = ''
        sym_address_str = ''
        for arg in inst_raw_split[1:]:
            arg = arg.strip()
            if utils.imm_pat.match(arg):
                sym_address_str = arg
                break
            else:
                tmp = arg.split(' ', 1)[0].strip()
                if utils.imm_pat.match(tmp):
                    sym_address_str = arg
                    break
                elif ':' in tmp and '[' in tmp and '=' in tmp:
                    tmp = tmp.split('[', 1)[1].split(':', 1)[0].strip()
                    if utils.imm_pat.match(tmp):
                        sym_address_str = tmp
                        break
        if sym_address_str:
            res = self._replace_inst_sym(address, inst, sym_address_str)
        return res
        

    def _replace_inst_sym(self, address, inst, sym_address_str):
        inst_elem = Inst_Elem(inst)
        inst = inst_elem.normalize(address, self._replace_inst_arg, utils.id_op, sym_address_str)
        return inst


    def _replace_inst_arg(self, address, inst_name, arg, sym_address_str):
        if 'sym.' in arg or 'obj.' in arg or 'reloc.' in arg or 'loc.' in arg or 'entry.' in arg or 'str.' in arg:
            if inst_name == 'lea': 
                if '[' not in arg:
                    arg = '[' + sym_address_str + ']'
                else:
                    sym_name = SYM_NAME_PAT.search(arg).group(0)
                    arg = arg.replace(sym_name, sym_address_str)
            else:
                sym_name = SYM_NAME_PAT.search(arg).group(0)
                arg = arg.replace(sym_name, sym_address_str)
            # elif arg.startswith(('qword', 'dword', 'word', 'byte')):
            #     arg = arg.split(' ', 1)[0].strip() + ' [' + sym_address_str + ']'
            # else:
            #     arg = sym_address_str
        elif arg == 'main' or arg == 'entry0':
            if inst_name == 'lea':
                arg = '[' + sym_address_str + ']'
            elif arg.startswith(('qword', 'dword', 'word', 'byte')):
                arg = arg.split(' ', 1)[0].strip() + ' [' + sym_address_str + ']'
            else:
                arg = sym_address_str
        return arg


    def _format_inst(self, address, inst, rip):
        inst_elem = Inst_Elem(inst)
        res = inst_elem.normalize(address, self._format_arg, self._rewrite_inst, rip)
        return res


    def _format_arg(self, address, inst_name, arg, rip):
        res = helper.convert_to_hex_rep(arg)
        res = helper.add_or_remove_ptr_rep_arg(inst_name, res)
        res = helper.rewrite_absolute_address_to_relative(res, rip)
        return res

    def _rewrite_inst(self, inst):
        res = inst.replace(' + ', '+').replace(' - ', '-')
        return res
        



