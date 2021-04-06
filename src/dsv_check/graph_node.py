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

class Node(object):

    def __init__(self, start_addr, end_addr, inst_addresses):
        self.address_list = []
        self.node_id = None
        if start_addr in inst_addresses:
            s_idx = inst_addresses.index(start_addr)
            if end_addr in inst_addresses:
                self.node_id = start_addr
                e_idx = inst_addresses.index(end_addr)
                for idx in range(s_idx, e_idx + 1):
                    address = inst_addresses[idx]
                    self.address_list.append(address)


    def located_in_this_node(self, address):
        return address in self.address_list

    def pp_node(self, address_inst_map):
        for address in self.address_list:
            print(hex(address) + ': ' + address_inst_map[address])



