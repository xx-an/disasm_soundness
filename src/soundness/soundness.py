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

from ..common import utils
from .reachable import Reachable

optimized_exceptions = ['ret']

def _check_bin_eq(address, inst, elf_content):
    bin_rep = utils.generate_inst_bin(inst)
    elf_bytes = elf_content.read_byte_sequence(address, utils.get_bytes_len(bin_rep))
    if not bin_rep: 
        print('The binary representations are invalid for inst: ' + inst + ' at address ' + str(hex(address)))
    if bin_rep != elf_bytes and not utils.check_jmp_with_address(inst) and not inst.startswith('nop') and 'ret' not in inst:
        print('The binary representations are not equivalent for inst: ' + inst + ' at address ' + str(hex(address)))
        print('gcc binary rep: ' + bin_rep)
        print('elf binary rep: ' + elf_bytes)
    return True


def sound(elf_content, disasm_asm, cfg):
    addresses = cfg.reachable_addresses()
    address_inst_map = disasm_asm.get_address_inst_map()
    for address in addresses:
        inst = address_inst_map[address]
        res = _check_bin_eq(address, inst, elf_content)
        if not res:
            return False
    return True
        

def sound_disasm_file(elf_content, disasm_log_file):
    reachable = Reachable(disasm_log_file)
    reachable_address_table = reachable.reachable_address_table
    for address in reachable_address_table.keys():
        inst = reachable_address_table[address]
        res = _check_bin_eq(address, inst, elf_content)
        if not res:
            return False
    return True

