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
import xlrd
import xlwt
import argparse
from ..common import utils


CHECK_RESULTS = ['', '$\\checkmark$', '$\\times$']

def open_statistics_xls(file_path):
    workbook = xlrd.open_workbook(file_path)
    return workbook

def create_statistics_xls():
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
    sheet.write(0, 7, 'Exec time (s)')
    sheet.write(0, 8, 'Missing instr')
    sheet.write(0, 9, 'Sound')
    return sheet

def reorder_xls_sheet(workbook, disasm_type, new_workbook, file_names):
    sheet = workbook.sheet_by_name(disasm_type)
    new_sheet = add_xlws_sheet(new_workbook, disasm_type)
    line_no = 1
    curr_names = sheet.col_values(0)
    for name in file_names:
        idx = curr_names.index(name)
        row = sheet.row_values(idx)
        for index, val in enumerate(row):
            if isinstance(val, float):
                new_sheet.write(line_no, index, round(val, 2))
            else:
                new_sheet.write(line_no, index, val)
        line_no += 1
    return new_sheet

def reorder_xls_sheet_batch(file_dir, wb_name, new_wb_name):
    wb_path = os.path.join(file_dir, wb_name)
    workbook = open_statistics_xls(wb_path)
    new_workbook = create_statistics_xls()
    for disasm_type in ['objdump', 'radare2', 'angr', 'bap', 'ghidra', 'dyninst']:
        if disasm_type == 'objdump':
            sheet = workbook.sheet_by_name(disasm_type)
            file_names = sheet.col_values(0)[1:]
        reorder_xls_sheet(workbook, disasm_type, new_workbook, file_names)
    new_wb_path = os.path.join(file_dir, new_wb_name)
    new_workbook.save(new_wb_path)


def read_xls_data(workbook, disasm_type):
    sheet = workbook.sheet_by_name(disasm_type)
    names = sheet.col_values(0)
    white_insts = sheet.col_values(2)
    missing_instr = sheet.col_values(8)
    sound = sheet.col_values(9)
    return names, white_insts, missing_instr, sound


def add_unsoundness(workbook1, workbook2, new_workbook, disasm_type):
    print(disasm_type)
    sheet1 = workbook1.sheet_by_name(disasm_type)
    sheet2 = workbook2.sheet_by_name(disasm_type)
    new_sheet = add_xlws_sheet(new_workbook, disasm_type)
    nrows = sheet1.nrows
    col_values = sheet2.col_values(0)
    line_no = 1
    for i in range(1, nrows):
        row1 = sheet1.row_values(i)
        name = row1[0].strip()
        if name:
            idx = col_values.index(name)
            row2 = sheet2.row_values(idx)
            for index, val in enumerate(row1):
                if index != 9:
                    new_sheet.write(line_no, index, val)
                else:
                    new_sheet.write(line_no, index, row2[-1])
        line_no += 1
    return new_sheet

def add_unsoundness_xls_sheet_batch(file_dir, file_name1, file_name2, new_file_name):
    file_path1 = os.path.join(file_dir, file_name1)
    workbook1 = open_statistics_xls(file_path1)
    file_path2 = os.path.join(file_dir, file_name2)
    workbook2 = open_statistics_xls(file_path2)
    new_workbook = create_statistics_xls()
    for disasm_type in ['objdump', 'radare2', 'angr', 'bap', 'ghidra', 'dyninst']:
        add_unsoundness(workbook1, workbook2, new_workbook, disasm_type)
    xls_path = os.path.join(file_dir, new_file_name)
    new_workbook.save(xls_path)


def has_missing_instr(white1, white_objdump):
    if abs(white1 - white_objdump) > 4:
        return True
    return False

def add_missing_instr(workbook1, workbook2, new_workbook, disasm_type):
    print(disasm_type)
    sheet1 = workbook1.sheet_by_name(disasm_type)
    sheet2 = workbook2.sheet_by_name(disasm_type)
    sheet_objdump = workbook1.sheet_by_name('objdump')
    new_sheet = add_xlws_sheet(new_workbook, disasm_type)
    nrows = sheet1.nrows
    col_values2 = sheet2.col_values(0)
    col_values_objdump = sheet_objdump.col_values(0)
    line_no = 1
    for i in range(1, nrows):
        row1 = sheet1.row_values(i)
        name = row1[0].strip()
        if name:
            idx2 = col_values2.index(name)
            idx_objdump = col_values_objdump.index(name)
            row2 = sheet2.row_values(idx2)
            row_objdump = sheet_objdump.row_values(idx_objdump)
            for index, val in enumerate(row1):
                if index != 8:
                    if isinstance(val, float):
                        new_sheet.write(line_no, index, round(val, 2))
                    else:
                        new_sheet.write(line_no, index, val)
                else:
                    if row1[-1].strip():
                        new_sheet.write(line_no, index, '')
                    elif has_missing_instr(row1[2], row_objdump[2]):
                        new_sheet.write(line_no, index, CHECK_RESULTS[2])
                    else:
                        new_sheet.write(line_no, index, val)
        line_no += 1
    return new_sheet

def add_missing_instr_xls_sheet_batch(file_dir, file_name1, file_name2, new_file_name):
    file_path1 = os.path.join(file_dir, file_name1)
    workbook1 = open_statistics_xls(file_path1)
    file_path2 = os.path.join(file_dir, file_name2)
    workbook2 = open_statistics_xls(file_path2)
    new_workbook = create_statistics_xls()
    for disasm_type in ['objdump', 'radare2', 'angr', 'bap', 'ghidra', 'dyninst']:
        add_missing_instr(workbook1, workbook2, new_workbook, disasm_type)
    xls_path = os.path.join(file_dir, new_file_name)
    new_workbook.save(xls_path)


def add_latex_for_row(row_values):
    res = ' & '
    for index, val in enumerate(row_values):
        if index == 0:
            if val:
                res += str(val)
            res += ' & '
        elif index in [1, 2, 3, 4, 6]:
            if isinstance(val, float):
                res += str(int(val))
            res += ' & '
        elif index == 5:
            if isinstance(val, float):
                res += str(val)
            res += ' & '
        elif index == 8:
            if val:
                res += CHECK_RESULTS[2]
            res += ' \\\\\n'
        else:
            if val:
                res += CHECK_RESULTS[2]
            res += ' & '
    # res += ' & ' + ' & '.join(list(map(lambda x: str(x), row_values))) + ' \\\\\n'
    return res

def add_latex_foot(disasm_type):
    res = ''
    if disasm_type == 'dyninst':
        res += '\n'
    else:
        res += '\\midrule\n'
    return res

def add_latex_disasm_type(disasm_type):
    res = disasm_type
    if disasm_type == 'bap':
        res = 'BAP'
    elif disasm_type == 'ghidra':
        res = 'Ghidra'
    elif disasm_type == 'dyninst':
        res = 'Dyninst'
    elif disasm_type == 'hopper':
        res = 'Hopper'
    elif disasm_type == 'idapro':
        res = 'IDA Pro'
    return res


def generate_latex_from_xls(workbook, disasm_type):
    res = '\\textsf{' + add_latex_disasm_type(disasm_type) + '}'
    sheet = workbook.sheet_by_name(disasm_type)
    nrows = sheet.nrows
    for i in range(1, nrows):
        row_values = sheet.row_values(i)
        res += add_latex_for_row(row_values)
    res += add_latex_foot(disasm_type)
    return res

def generate_latex_from_xls_wo_designated(workbook, disasm_type, file_names):
    res = '\\textsf{' + add_latex_disasm_type(disasm_type) + '}'
    sheet = workbook.sheet_by_name(disasm_type)
    nrows = sheet.nrows
    for i in range(1, nrows):
        row_values = sheet.row_values(i)
        name = row_values[0].strip()
        if name and name in file_names: pass
        else:
            res += add_latex_for_row(row_values)
    res += add_latex_foot(disasm_type)
    return res

def generate_latex_from_xls_with_designated(workbook, disasm_type, file_names):
    res = '\\textsf{' + add_latex_disasm_type(disasm_type) + '}'
    sheet = workbook.sheet_by_name(disasm_type)
    curr_names = sheet.col_values(0)
    for name in file_names:
        idx = curr_names.index(name)
        row_values = sheet.row_values(idx)
        res += add_latex_for_row(row_values)
    res += add_latex_foot(disasm_type)
    return res

def generate_latex_from_xls_wo_designated_batch(file_dir, workbook, file_names):
    latex_res = ''
    for disasm_type in utils.DISASSEMBLER_TYPES:
        latex_res += generate_latex_from_xls_wo_designated(workbook, disasm_type, file_names)
    latex_path = os.path.join(file_dir, 'latex.appendix')
    with open(latex_path, 'w+') as f:
        f.write(latex_res)

def generate_latex_from_xls_with_designated_batch(file_dir, workbook, file_names):
    res = ''
    for disasm_type in utils.DISASSEMBLER_TYPES:
        res += generate_latex_from_xls_with_designated(workbook, disasm_type, file_names)
    print(res)
    # latex_path = os.path.join(file_dir, 'latex.info')
    # with open(latex_path, 'w+') as f:
    #     f.write(res)

def generate_latex_from_xls_batch(file_dir, workbook_name, file_names):
    file_path = os.path.join(file_dir, workbook_name)
    workbook = open_statistics_xls(file_path)
    # generate_latex_from_xls_wo_designated_batch(file_dir, workbook, file_names)
    generate_latex_from_xls_with_designated_batch(file_dir, workbook, file_names)

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
    output_files = [os.path.join(dp, f) for dp, _, filenames in os.walk(dir_path) for f in filenames if f.endswith('.output')]
    for output_path in output_files:
        file_name = utils.get_file_name(output_path)
        cmd = 'head ' + output_path
        res = utils.execute_command(cmd)
        res = res.strip().split('\n')
        no_of_incorrect = res[7].strip().split(':', 1)[1].strip()
        if no_of_incorrect != '0':
            print(file_name)


def replace_all_log_files(dir_path):
    log_files = [os.path.join(dp, f) for dp, _, filenames in os.walk(dir_path) for f in filenames if f.endswith('.log')]
    for log_path in log_files:
        file_name = utils.get_file_name(log_path)
        print(file_name)
        new_content = ''
        with open(log_path, 'r') as f:
            new_content = f.read()
            new_content = new_content.replace('btl ', 'bt ')
        with open(log_path, 'w') as f:
            f.write(new_content)

    
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
        ratio = round((no_of_white - no_of_incorrect) / no_of_white, 5)
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
    # print_correctly_disassembled_inst_ratio(dir_path)
    # detect_all_unchecked_diassembled_files(dir_path)
    file_names = ['basename', 'expand', 'mknod', 'realpath', 'dir']
    generate_latex_from_xls_batch(utils.PROJECT_DIR, 'statistics.xlsx', file_names)
