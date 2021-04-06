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
from ..common import utils


class ELF_Content(object):
    def __init__(self, src_path):
        self.src_path = src_path
        self.address_bytes_map = {}
        self.read_elf_contents()


    def read_elf_contents(self):
        idx = 0
        with open(self.src_path, 'rb') as f:
            bytes_read = f.read()
            for byte in bytes_read:
                self.address_bytes_map[idx] = byte
                idx += 1  
        

    def read_bytes(self, address, length):
        res = []
        for i in range(length - 1, -1, -1):
            curr = address + i
            if curr in self.address_bytes_map:
                res.append(self.address_bytes_map[curr])
            else:
                return []
        return utils.bytes_to_int(res)

    def read_byte_sequence(self, address, length):
        res = []
        for i in range(length - 1, -1, -1):
            curr = address + i
            if curr in self.address_bytes_map:
                res.append(self.address_bytes_map[curr])
            else:
                return ''
        return utils.bytes_to_hex(res)


    def read_bytes_all(self):
        num = len(self.address_bytes_map)
        for i in range(num):
            res = self.read_bytes(i, 1)
            print(res)

