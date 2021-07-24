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

def backtrack_to_start(block, address, block_set):
    trace_list = [address]
    parent_no = block.parent_no
    while parent_no:
        parent_blk = block_set[parent_no]
        p_address = parent_blk.address
        trace_list.append(p_address)
        parent_no = parent_blk.parent_no
    return trace_list


def pp_trace_list(trace_list, address_inst_map):
    utils.logger.debug(', '.join([hex(address) + ': ' + address_inst_map[address] for address in trace_list[::-1]]))
    # for address in trace_list:
    #     inst = address_inst_map[address]
    #     utils.logger.debug(hex(address) + ': ' + inst)
    #     utils.logger.debug(curr.sym_store.pp_store())