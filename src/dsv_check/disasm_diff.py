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
import argparse
from ..common import utils

def check_diff(log_path, objdump_log_path):
    with open(log_path, 'r') as lf:
        with open(objdump_log_path, 'r') as of:
            lf_lines = lf.readlines()
            of_lines = of.readlines()
            idx = 0
            for line in lf_lines:
                line = line.strip()
                of_line = of_lines[idx].strip()
                if line and ':' in line:
                    if utils.imm_start_pat.match(line):
                        address_str, inst = line.split(':', 1)
                        # print(line)
                        # print(of_line)
                        of_address_str, of_inst = of_line.split(':', 1)
                        address = int(address_str.strip(), 16)
                        of_address = int(of_address_str.strip(), 16)
                        inst = inst.replace(' + ', '+').replace(' - ', '-')
                        of_inst = of_inst.strip().replace('*1+','+').replace('*1]',']').replace('+0x0]',']')
                        for i in range(1, 10):
                            of_inst = of_inst.replace('0x' + str(i) + ']',str(i) +']')
                        if address != of_address:
                            print(line)
                            print(of_line)
                            break
                        elif inst.strip() != of_inst.strip():
                            print(line)
                            print(of_line)
                idx += 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Difference between the generated log file for various disassemblers')
    parser.add_argument('-t', '--disasm_type', default='objdump', type=str, help='Disassembler')
    parser.add_argument('-f', '--file_name', type=str, help='Benchmark file name')
    parser.add_argument('-l', '--log_dir', default='benchmark/coreutils-objdump', type=str, help='Log file folder name')
    parser.add_argument('-o', '--objdump_dir', default='benchmark/coreutils-objdump', type=str, help='Log file folder name')
    args = parser.parse_args()
    log_dir = args.log_dir
    if args.disasm_type != 'objdump' and 'objdump' in args.log_dir:
        log_dir = log_dir.replace('objdump', args.disasm_type)
    log_dir = os.path.join(utils.PROJECT_DIR, log_dir)
    objdump_dir = os.path.join(utils.PROJECT_DIR, args.objdump_dir)
    file_name = args.file_name
    objdump_log_path = os.path.join(objdump_dir, file_name + '.log')
    log_path = os.path.join(log_dir, file_name + '.log')
    check_diff(log_path, objdump_log_path)
