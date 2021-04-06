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

address_inst_pattern = re.compile('^[ ]+[0-9a-f]+:[0-9a-f\t ]+')

def parse_line_inst(line):
    inst = ''
    inst_str = re.findall(r' \t[^<#\n\t]+', line)
    if inst_str:
        inst = inst_str[-1].strip()
        inst = re.sub(r'\s+', ' ', inst).strip()
    return inst

def instr_count_single(file_path, inst_count_map):
    with open(file_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if address_inst_pattern.search(line):
                inst = parse_line_inst(line)
                inst_name = inst.split(' ', 1)[0].strip()
                if not inst_name.endswith(('sd', 'pd', 'ps', 'ss')) and not inst_name.startswith(('j', 'cmov', 'set')):
                    if inst_name in inst_count_map:
                        inst_count_map[inst_name] += 1
                    else:
                        inst_count_map[inst_name] = 1

def instr_count_lib(files, inst_count_map):
    for file_path in files:
        instr_count_single(file_path, inst_count_map)


def print_inst_count_map(inst_count_map):
    print(len(inst_count_map))
    print([x[0] for x in sorted(inst_count_map.items(), key = lambda kv: (kv[1], kv[0]), reverse=True)])

if __name__=='__main__':
    lib_name = 'coreutils'
    dir_path = os.path.join(utils.PROJECT_DIR, os.path.join('benchmark', lib_name + '-objdump'))
    files = utils.get_sub_files(dir_path)
    inst_count_map = {}
    instr_count_lib(files, inst_count_map)
    print_inst_count_map(inst_count_map)
    