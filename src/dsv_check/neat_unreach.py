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
$ python -m src.dsv_check.neat_unreach -e benchmark/coreutils-build -l benchmark/coreutils-radare2 -t radare2 -f basename
'''

import os
import xlwt
import argparse

from ..common import utils
from ..elf.elf_info import ELF_Info
from .disasm_objdump import Disasm_Objdump
from .construct_graph import Construct_Graph

cnt = 0
grey_cnt = 0
print_info = ''
_start_segment_address = None

target_dir = os.path.join(utils.PROJECT_DIR, 'temp')

def append_all_addresses(start_address, end_address, inst_addresses, address_inst_map, graph):
    global cnt, grey_cnt, print_info, _start_segment_address
    res = ''
    maybe_reachable = False
    if graph.is_reachable(_start_segment_address, start_address):
        maybe_reachable = True
        print_info += utils.u_hex(start_address) + ': ' + address_inst_map[start_address] + '\n'
    if start_address in inst_addresses:
        s_idx = inst_addresses.index(start_address)
        if end_address in inst_addresses:
            e_idx = inst_addresses.index(end_address)
            for idx in range(s_idx, e_idx + 1):
                address = inst_addresses[idx]
                inst = address_inst_map[address]
                if not (inst.startswith('nop ') or inst == 'nop'):
                    if maybe_reachable:
                        grey_cnt += 1
                    cnt += 1
                    res += utils.u_hex(address) + ': ' + inst + '\n'
    res += '\n'
    return res


def divide_to_block(new_content):
    start_address_list = []
    end_address_list = []
    _exists = False
    lines = new_content.split('\n')
    for line in lines:
        if line:
            address_str, _ = line.strip().split(':', 1)
            address = int(address_str, 16)
            if not _exists:
                start_address_list.append(address)
                _exists = True
        else:
            if _exists:
                end_address_list.append(address)
            _exists = False
    return start_address_list, end_address_list


def remove_implicit_called_functions(new_content, unreach_addresses, disasm_asm, graph):
    res = ''
    start_address_list, end_address_list = divide_to_block(new_content)
    label_address_list = sorted(list(disasm_asm.address_label_map.keys()))
    inst_addresses = disasm_asm.inst_addresses
    address_inst_map = disasm_asm.address_inst_map
    address_entries_map = disasm_asm.address_entries_map
    for start_address, end_address in zip(start_address_list, end_address_list):
        if start_address in label_address_list:
            if start_address in address_entries_map:
                if len(address_entries_map[start_address]) > 0:
                    for entry_address in address_entries_map[start_address]:
                        if entry_address not in unreach_addresses:
                            res += append_all_addresses(start_address, end_address, inst_addresses, address_inst_map, graph)
                            break
        else:
            res += append_all_addresses(start_address, end_address, inst_addresses, address_inst_map, graph)
    return res


def not_continuous(prev_address, address, disasm_asm):
    # print('addr: ' + hex(address))
    # print('prev_addr: ' + hex(prev_address))
    if prev_address:
        if prev_address in disasm_asm.inst_addresses:
            p_idx = disasm_asm.inst_addresses.index(prev_address)
            if disasm_asm.inst_addresses[p_idx + 1] != address:
                return True
        else:
            return False
    return False

def remove_unexplored_inst(new_log_path, disasm_asm):
    new_content = ''
    unreach_addresses = []
    unreach_started = False
    with open(new_log_path, 'r') as f:
        lines = f.readlines()
        prev_address = None
        for line in lines:
            line = line.strip()
            if line:
                if utils.LOG_UNREACHABLE_INDICATOR in line:
                    unreach_started = True
                elif unreach_started:
                    if ':' in line:
                        address_str, inst = line.strip().split(':', 1)
                        address = int(address_str, 16)
                        inst = inst.strip()
                        if address in disasm_asm.address_label_map:
                            new_content += '\n'
                        elif not_continuous(prev_address, address, disasm_asm):
                            new_content += '\n'
                        if address not in disasm_asm.unexplored_address_list:
                            if not (inst.startswith('nop ') or inst == 'nop'):
                                new_content += line + '\n'
                                unreach_addresses.append(address)
                        prev_address = address
    return new_content, unreach_addresses


def normalize_unreachable(new_log_path, disasm_asm, graph):
    new_content, unreach_addresses = remove_unexplored_inst(new_log_path, disasm_asm)
    new_content = remove_implicit_called_functions(new_content, unreach_addresses, disasm_asm, graph)
    with open(new_log_path, 'w+') as f:
        f.write(new_content)


def read_parameters(log_path):
    res_list = []
    res = utils.execute_command('tail ' + log_path)
    res = res.strip().split('\n')
    total_cnt = int(res[-3])
    white_cnt = int(res[-2])
    indirects_cnt = int(res[-1])
    res_list.append(total_cnt)
    res_list.append(white_cnt)
    res_list.append(grey_cnt)
    black_cnt = total_cnt - white_cnt - grey_cnt
    res_list.append(black_cnt)
    ratio = round(grey_cnt / white_cnt, 2)
    res_list.append(ratio)
    res_list.append(indirects_cnt)
    return res_list


def neat_main(disasm_asm, graph, log_path, new_log_path):
    global cnt, grey_cnt, print_info, _start_segment_address
    cnt, grey_cnt = 0, 0
    print_info = ''
    _start_segment_address = graph.start_segment_address
    normalize_unreachable(new_log_path, disasm_asm, graph)
    para_list = read_parameters(log_path)
    return para_list


def main_single(file_name, exec_dir, log_dir, disasm_type, verbose):
    exec_path = os.path.join(exec_dir, file_name)
    if exec_dir == log_dir:
        objdump_dir = log_dir
    else:
        objdump_dir = log_dir.replace(disasm_type, 'objdump')
    disasm_path = os.path.join(objdump_dir, file_name + '.objdump')
    log_path = os.path.join(log_dir, file_name + '.log')
    cmd = 'cp ' + log_path + ' ' + target_dir
    utils.execute_command(cmd)
    new_log_path = os.path.join(target_dir, file_name + '.log')
    disasm_asm = Disasm_Objdump(disasm_path)
    ei = ELF_Info(exec_path)
    cg = Construct_Graph(disasm_asm, new_log_path, ei)
    para_list = neat_main(disasm_asm, cg, log_path, new_log_path)
    if verbose:
        print(print_info)
    return para_list


def main_batch(exec_dir, log_dir, disasm_type, verbose):
    disasm_files = [os.path.join(dp, f) for dp, dn, filenames in os.walk(log_dir) for f in filenames if
                    f.endswith(disasm_type)]
    # sheet = add_xlws_sheet(workbook, disasm_type)
    line_no = 1
    for disasm_path in disasm_files:
        try:
            file_name = utils.get_file_name(disasm_path)
            print(file_name)
            if not (file_name.startswith(('bench-', 'sha')) or file_name in (('sort', 'test-localcharset'))):
                para_list = main_single(file_name, exec_dir, log_dir, disasm_type, verbose)
                # sheet.write(line_no, 0, file_name)
                # i = 1
                # for para in para_list:
                #     # sheet.write(line_no, i, para)
                #     i += 1
                print(file_name + '\t' + '\t'.join(list(map(lambda x: str(x), para_list))))
                line_no += 1
        except:
            continue


def main_specified(file_names, exec_dir, log_dir, disasm_type, verbose):
    for file_name in file_names:
        try:
            print(file_name)
            if not (file_name.startswith(('bench-', 'sha')) or file_name in (('sort', 'test-localcharset'))):
                para_list = main_single(file_name, exec_dir, log_dir, disasm_type, verbose)
                print(file_name + '\t' + '\t'.join(list(map(lambda x: str(x), para_list))))
        except:
            continue


def create_statistics_xlsw():
    workbook = xlwt.Workbook()
    return workbook

def add_xlws_sheet(workbook, disasm_type):
    sheet = workbook.add_sheet(disasm_type)
    sheet.write(0, 1, '# of total instructions')
    sheet.write(0, 2, '# of white instructions')
    sheet.write(0, 3, '# of grey instructions')
    sheet.write(0, 4, '# of black instructions')
    sheet.write(0, 5, 'Ratio (grey/white)')
    sheet.write(0, 6, '# of indirects')
    return sheet


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Disassembly Soundness Verification')
    parser.add_argument('-t', '--disasm_type', default='objdump', type=str, help='Disassembler type')
    parser.add_argument('-f', '--file_name', type=str, help='Benchmark file name')
    parser.add_argument('-v', '--verbose', default=False, action='store_true', help='Print the starts of unreachable instruction blocks')
    parser.add_argument('-b', '--batch', default=False, action='store_true', help='Run neat_unreach in batch mode')
    parser.add_argument('-e', '--elf_dir', default='benchmark/coreutils-build', type=str, help='Benchmark folder name')
    parser.add_argument('-l', '--log_dir', default='benchmark/coreutils-objdump', type=str, help='Disassembled folder name')
    args = parser.parse_args()
    utils.make_dir(target_dir)
    disasm_type = args.disasm_type
    log_dir = args.log_dir
    if disasm_type != 'objdump' and 'objdump' in args.log_dir:
        log_dir = log_dir.replace('objdump', disasm_type)
    log_dir = os.path.join(utils.PROJECT_DIR, log_dir)
    exec_dir = os.path.join(utils.PROJECT_DIR, args.elf_dir)
    if args.batch:
        main_batch(exec_dir, log_dir, args.disasm_type, args.verbose)
    else:
        para_list = main_single(args.file_name, exec_dir, log_dir, args.disasm_type, args.verbose)
        print(args.file_name + '\t' + '\t'.join(list(map(lambda x: str(x), para_list))))
        print(args.file_name + ' & ' + ' & '.join(list(map(lambda x: str(x), para_list))))
   
    
    # # Execute the results for specified test cases
    # file_names = ['mknod', 'date', 'id', 'csplit', 'paste', 'du', 'logname', 'pr']
    # main_specified(file_names, exec_dir, log_dir, args.disasm_type, args.verbose)
    
    # # Save the results for all the disassemblers
    # workbook = create_statistics_xlsw()
    # for disasm_type in ['objdump', 'radare2', 'angr', 'bap', 'hopper', 'idapro', 'ghidra', 'dyninst']:
    #     log_dir = log_dir if 'objdump' not in log_dir else log_dir.replace('objdump', disasm_type)
    #     main_batch(exec_dir, log_dir, disasm_type, args.verbose)
    # xls_path = os.path.join(os.path.dirname(exec_dir), 'statistics.xls')
    # workbook.save(xls_path)