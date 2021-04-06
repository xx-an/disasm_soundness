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

class Reachable(object):
    def __init__(self, log_file):
        self.log_file = log_file
        self.reachable_address_table = {}
        self.read_from_log_file()

    def read_from_log_file(self):
        with open(self.log_file, 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip()
                if line and line.startswith('0x') and ':' in line and 'the return address is' not in line and 'jump address' not in line:
                    address, inst = line.split(':', 1)
                    address = int(address, 16)
                    inst = inst.strip()
                    self.reachable_address_table[address] = inst