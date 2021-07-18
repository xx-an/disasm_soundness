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
from ..common import utils

def find_unchecked(a):
    res = []
    a_n = a.split('\n')
    for i in a_n:
        i = i.strip()
        if i:
            if '\t' not in i:
                x = i
                res.append(x)
    print(res)

def detect_ida_unhandled_struct(file_path):
    with open(file_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            line = line.split(';', 1)[0].strip()
            if ' = ' in line:
                if ' ptr ' not in line:
                    print(line)


def detect_all_ida_types(file_path, type_list):
    with open(file_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            line = line.split(';', 1)[0].strip()
            if ' = ' in line:
                if ' ptr ' in line:
                    ida_type = line.split('=', 1)[1].strip().split(' ptr ', 1)[0].strip()
                    if ida_type not in type_list:
                        type_list.append(ida_type)

def detect_all_ida_unhandled_struct(dir_path):
    type_list = []
    print(dir_path)
    disasm_files = [os.path.join(dp, f) for dp, _, filenames in os.walk(dir_path) for f in filenames if f.endswith('.idapro')]
    for disasm_path in disasm_files:
        # detect_ida_unhandled_struct(disasm_path)
        detect_all_ida_types(disasm_path, type_list)
    print(type_list)

if __name__=='__main__':
    dir_path = os.path.join(utils.PROJECT_DIR, os.path.join('benchmark', 'coreutils-idapro'))
    detect_all_ida_unhandled_struct(dir_path)
    # a = ''
    # find_unchecked(a)

