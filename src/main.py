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
import time
import argparse
import logging
from .common import utils
from .common import global_var
from .normalizer import helper
from .normalizer.normalizer_factory import Disasm_Factory
from .cfg.cfg import CFG
from .soundness import soundness
from .dsv_check import neat_unreach


CHECK_RESULTS = ['', '$\\times$']

def construct_cfg(disasm_asm, disasm_type):
    start_address = global_var.elf_info.entry_address
    main_address = global_var.elf_info.main_address
    address_sym_table = global_var.elf_info.address_sym_table
    address_inst_map = disasm_asm.get_address_inst_map()
    cfg = CFG(address_sym_table, address_inst_map, disasm_asm.address_next_map, start_address, main_address, disasm_type)
    return cfg


def set_logger(disasm_path, disasm_type, verbose=False):
    for log_name in utils.LOG_NAMES:
        logger_path = disasm_path.replace('.' + disasm_type, '.' + log_name)
        utils.setup_logger(log_name, logger_path, verbose, logging.DEBUG)

def close_logger():
    for log_name in utils.LOG_NAMES:
        utils.close_logger(log_name)


def write_results(disasm_asm, cfg):
    reachable_address_num = len(cfg.reachable_addresses())
    indirects_num = len(cfg.indirect_inst_set)
    utils.logger.info(disasm_asm.valid_address_no)
    utils.logger.info(reachable_address_num)
    utils.logger.info(indirects_num)


def check_soundness(elf_lib_dir, disasm_lib_dir, file_name):
    print(file_name)
    disasm_log_path = os.path.join(disasm_lib_dir, file_name + '.log')
    exec_path = os.path.join(elf_lib_dir, file_name)
    global_var.get_elf_info(exec_path)
    res = soundness.sound_disasm_file(global_var.elf_content, disasm_log_path)
    return res


def check_soundness_batch(elf_lib_dir, disasm_lib_dir):
    disasm_log_files = [os.path.join(dp, f) for dp, _, filenames in os.walk(disasm_lib_dir) for f in filenames if f.endswith('.log')]
    for disasm_log_path in disasm_log_files:
        file_name = utils.get_file_name(disasm_log_path)
        exec_path = os.path.join(elf_lib_dir, file_name)
        if os.path.exists(exec_path):
            print(file_name)
            global_var.get_elf_info(exec_path)
            soundness.sound_disasm_file(global_var.elf_content, disasm_log_path)
            time.sleep(10)


def check_soundness_specified(file_names, elf_lib_dir, disasm_lib_dir, disasm_type):
    for file_name in file_names:
        print(file_name)
        exec_path = os.path.join(elf_lib_dir, file_name)
        disasm_log_path = os.path.join(disasm_lib_dir, file_name + '.log')
        if os.path.exists(exec_path):
            global_var.get_elf_info(exec_path)
            soundness.sound_disasm_file(global_var.elf_content, disasm_log_path)
            time.sleep(10)
        

def dsv_main(exec_path, disasm_path, disasm_type, verbose=False):
    set_logger(disasm_path, disasm_type, verbose)
    global_var.get_elf_info(exec_path)
    helper.disassemble_to_asm(exec_path, disasm_path, disasm_type)
    disasm_factory = Disasm_Factory(disasm_path, exec_path, disasm_type)
    disasm_asm = disasm_factory.get_disasm()
    cfg = construct_cfg(disasm_asm, disasm_type)
    write_results(disasm_asm, cfg)
    close_logger()


def dsv_batch(elf_lib_dir, disasm_lib_dir, disasm_type, verbose=False):
    disasm_files = [os.path.join(dp, f) for dp, _, filenames in os.walk(disasm_lib_dir) for f in filenames if f.endswith(disasm_type)]
    for disasm_path in disasm_files:
        file_name = utils.get_file_name(disasm_path)
        print(file_name)
        exec_path = os.path.join(elf_lib_dir, file_name)
        if os.path.exists(exec_path):
            try:
                dsv_main(exec_path, disasm_path, disasm_type, verbose)
                time.sleep(15)
                para_list = neat_unreach.main_single(file_name, elf_lib_dir, disasm_lib_dir, disasm_type, False)
                print(file_name + '\t' + '\t'.join(list(map(lambda x: str(x), para_list))))
            except:
                close_logger()
                time.sleep(15)
                continue


def dsv_specified(file_names, elf_lib_dir, disasm_lib_dir, disasm_type, verbose=False):
    for file_name in file_names:
        print(file_name)
        exec_path = os.path.join(elf_lib_dir, file_name)
        disasm_path = os.path.join(disasm_lib_dir, file_name + '.' + disasm_type)
        try:
            dsv_main(exec_path, disasm_path, disasm_type, verbose)
            time.sleep(15)
            para_list = neat_unreach.main_single(file_name, elf_lib_dir, disasm_lib_dir, disasm_type, False)
            print(file_name + '\t' + '\t'.join(list(map(lambda x: str(x), para_list))))
        except:
            close_logger()
            time.sleep(15)
            continue


if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Disassembly Soundness Verification')
    parser.add_argument('-t', '--disasm_type', default='objdump', type=str, help='Disassembler')
    parser.add_argument('-b', '--batch', default=False, action='store_true', help='Run dsv_main in batch mode') 
    parser.add_argument('-s', '--soundness', default=False, action='store_true', help='Check the soundness for specific file') 
    parser.add_argument('-l', '--log_dir', default='benchmark/coreutils-objdump', type=str, help='Benchmark library') 
    parser.add_argument('-e', '--elf_dir', default='benchmark/coreutils-build', type=str, help='Elf shared object library') 
    parser.add_argument('-f', '--file_name', type=str, help='Benchmark file name')
    parser.add_argument('-v', '--verbose', default=False, action='store_true', help='Whether to print log information on the screen')
    parser.add_argument('-c', '--bmc_bound', default=25, type=int, help='The default value of the BMC bound')
    args = parser.parse_args()
    utils.MAX_VISIT_COUNT = args.bmc_bound
    disasm_type = args.disasm_type
    log_dir = args.log_dir
    if disasm_type != 'objdump' and 'objdump' in args.log_dir:
        log_dir = log_dir.replace('objdump', disasm_type)
    disasm_lib_dir = os.path.join(utils.PROJECT_DIR, log_dir)
    elf_lib_dir = os.path.join(utils.PROJECT_DIR, args.elf_dir)
    # 
    if args.soundness:
        if args.batch:
            check_soundness_batch(elf_lib_dir, disasm_lib_dir)   
        else: 
            check_soundness(elf_lib_dir, disasm_lib_dir, args.file_name)
    else:
        if args.batch:
            dsv_batch(elf_lib_dir, disasm_lib_dir, disasm_type, args.verbose)
        else:
            disasm_path = os.path.join(disasm_lib_dir, args.file_name + '.' + disasm_type)
            exec_path = os.path.join(elf_lib_dir, args.file_name)
            dsv_main(exec_path, disasm_path, disasm_type, args.verbose)
    # 
    # file_names = ['date', 'id', 'paste', 'logname', 'pr']
    # dsv_specified(file_names, elf_lib_dir, disasm_lib_dir, disasm_type, args.verbose)
    # # check_soundness_specified(file_names, elf_lib_dir, disasm_lib_dir, disasm_type)
    
        