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

'''
$ python -m src.dsv_check.detect_exception
'''

import os
import re
import argparse
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


def detect_all_unchecked_diassembled_files(dir_path):
    result = []
    output_files = [os.path.join(dp, f) for dp, _, filenames in os.walk(dir_path) for f in filenames if f.endswith('.output')]
    output_files.sort()
    for output_path in output_files:
        file_name = utils.get_file_name(output_path)
        cmd = 'head ' + output_path
        res = utils.execute_command(cmd)
        if '# of incorrectly disassembled' not in res:
            result.append(file_name)
    print(result)
        

def detect_all_incorrectly_disassembled_insts(dir_path):
    print(dir_path)
    output_files = [os.path.join(dp, f) for dp, _, filenames in os.walk(dir_path) for f in filenames if f.endswith('.output')]
    for output_path in output_files:
        file_name = utils.get_file_name(output_path)
        cmd = 'head ' + output_path
        res = utils.execute_command(cmd)
        res = res.strip().split('\n')
        no_of_incorrect = res[7].strip().split(':', 1)[1].strip()
        if no_of_incorrect != '0':
            print(file_name)

    
def print_correctly_disassembled_inst_ratio(dir_path):
    print(disasm_type)
    output_files = [os.path.join(dp, f) for dp, _, filenames in os.walk(dir_path) for f in filenames if f.endswith('.output')]
    output_files.sort()
    for output_path in output_files:
        file_name = utils.get_file_name(output_path)
        cmd = 'head ' + output_path
        res = utils.execute_command(cmd)
        res = res.strip().split('\n')
        no_of_white = int(res[1].strip().split(':', 1)[1].strip())
        no_of_incorrect = int(res[7].strip().split(':', 1)[1].strip())
        ratio = round((no_of_white - no_of_incorrect) / no_of_white, 3)
        print(ratio)


def modify_output_files(dir_path):
    output_files = [os.path.join(dp, f) for dp, _, filenames in os.walk(dir_path) for f in filenames if f.endswith('.output')]
    output_files.sort()
    for output_path in output_files:
        new_content = ''
        with open(output_path, 'r') as f:
            idx = 0
            lines = f.readlines()
            tmp = ''
            for line in lines:
                if idx == 0:
                    tmp = line
                elif idx == 7:
                    new_content += tmp
                    new_content += line
                else:
                    new_content += line
                idx += 1
        # print(new_content)
        with open(output_path, 'w') as f:
            f.write(new_content)


if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Disassembly Soundness Verification')
    parser.add_argument('-t', '--disasm_type', default='objdump', type=str, help='Disassembler')
    args = parser.parse_args()
    disasm_type = args.disasm_type
    dir_path = os.path.join(utils.PROJECT_DIR, os.path.join('benchmark', 'coreutils-' + disasm_type))
    # detect_all_ida_unhandled_struct(dir_path)
    # a = ''
    # find_unchecked(a)
    # detect_all_incorrectly_disassembled_insts(dir_path)
    print_correctly_disassembled_inst_ratio(dir_path)
    # detect_all_unchecked_diassembled_files(dir_path)

