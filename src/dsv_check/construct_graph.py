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

from ..common import lib
from ..common import utils
from ..elf.elf_info import ELF_Info
from ..disassembler import helper
from .graph import Graph
from .graph_node import Node
from .disasm_objdump import Disasm_Objdump


'''
$ python -m src.dsv_check.construct_graph -l benchmark/coreutils-build -L benchmark/coreutils-radare2 -d benchmark/coreutils-objdump -t radare2 -f basename
'''

class Construct_Graph(object):
    def __init__(self, disasm_asm, log_path, elf_info):
        self.node_set = {}
        self.graph = Graph()
        self.elf_info = elf_info
        self.start_segment_address = elf_info.entry_address
        self.address_entries_map = {}
        self.call_to_addr_set = set()
        self.address_inst_map = disasm_asm.address_inst_map
        self.inst_addresses = disasm_asm.inst_addresses
        self.organize_address_entires(log_path, disasm_asm)
        new_content = self.construct_splitted_content(disasm_asm)
        self.construct_graph(new_content, disasm_asm.inst_addresses)


    def construct_nodes(self, start_address, end_address, inst_addresses):
        node = Node(start_address, end_address, inst_addresses)
        self.node_set[start_address] = node
        self.graph.add_vertex(start_address)


    def construct_edges(self, address):
        if address in self.address_entries_map:
            address_entries = self.address_entries_map[address]
            # print(hex(address) + ': ' + str(address_entries))
            for addr in address_entries:
                node_id = self.search_node_id(addr)
                # print(node_id)
                if node_id:
                    if address != node_id:
                        self.graph.add_edge([node_id, address])


    def search_node_id(self, address):
        node_id = None
        for start_addr, end_addr in zip(self.start_address_list, self.end_address_list):
            if address >= start_addr and address <= end_addr:
                # print(hex(start_addr) + ', ' + hex(end_addr))
                node = self.node_set[start_addr]
                if node.located_in_this_node(address):
                    node_id = start_addr
                break
        return node_id

    def divide_to_block(self, new_content):
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


    def construct_graph(self, new_content, inst_addresses):
        self.start_address_list, self.end_address_list = self.divide_to_block(new_content)
        for start_address, end_address in zip(self.start_address_list, self.end_address_list):
            self.construct_nodes(start_address, end_address, inst_addresses)
        for start_address in self.start_address_list:
            self.construct_edges(start_address)


    def print_path(self, path):
        for node_id in path:
            node = self.node_set[node_id]
            node.pp_node(self.address_inst_map)
            print('\n')

    def gen_path(self, start_vertex, end_vertex, prev_node):
        path = [end_vertex]
        curr = end_vertex
        while curr != start_vertex:
            prev = prev_node[curr]
            path.append(prev)
            curr = prev
        path.reverse()
        return path

    def check_reachable(self, start_vertex, end_vertex, start_addr, end_addr):
        visited = {}
        prev_node = {}
        graph_dict = self.graph.graph_dict()
        for vertex in graph_dict:
            visited[vertex] = False
        queue = []
        queue.append(start_vertex)
        visited[start_vertex] = True
        n = queue.pop(0)
        if n == end_vertex:
            if start_addr <= end_addr:
                return True, self.gen_path(start_vertex, end_vertex, prev_node)
        node = self.node_set[n]
        for v in graph_dict[n]:
            if not visited[v]:
                v_entries = self.address_entries_map[v]
                for ve in v_entries:
                    if node.located_in_this_node(ve):
                        if ve >= start_addr:
                            queue.append(v)
                            prev_node[v] = n
                            visited[v] = True
                            break
        while queue:
            n = queue.pop(0)
            if n == end_vertex:
                return True, self.gen_path(start_vertex, end_vertex, prev_node)
            for v in graph_dict[n]:
                if not visited[v]:
                    queue.append(v)
                    prev_node[v] = n
                    visited[v] = True
        return False, None

    def is_reachable(self, start_addr, end_addr):
        start_node_id = self.search_node_id(start_addr)
        end_node_id = self.search_node_id(end_addr)
        if start_node_id is not None and end_node_id is not None:
            if start_node_id == end_node_id:
                return True
            else:
                res, _ = self.check_reachable(start_node_id, end_node_id, start_addr, end_addr)
                if res:
                    return True
        return False


    def find_path(self, start_addr, end_addr):
        start_node_id = self.search_node_id(start_addr)
        end_node_id = self.search_node_id(end_addr)
        # print(hex(start_node_id))
        # print(hex(end_node_id))
        if start_node_id is not None and end_node_id is not None:
            if start_node_id == end_node_id:
                node = self.node_set[start_node_id]
                node.pp_node(self.address_inst_map)
            else:
                res, path = self.check_reachable(start_node_id, end_node_id, start_addr, end_addr)
                if res:
                    self.print_path(path)
                else:
                    print('There is no path')


    def not_continuous(self, prev_address):
        if prev_address:
            p_inst = self.address_inst_map[prev_address]
            if utils.check_branch_inst_wo_call(p_inst):
                return True
            elif p_inst.startswith('call'):
                if prev_address in self.call_to_addr_set:
                    return True
        return False

    def _add_to_address_entries_map(self, addr, entry):
        if addr in self.address_entries_map:
            if entry not in self.address_entries_map[addr]:
                self.address_entries_map[addr].append(entry)
        else:
            self.address_entries_map[addr] = [entry]


    def organize_address_entires(self, log_path, disasm):
        with open(log_path, 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip()
                if ': jump address is ' in line or ': the return address is ' in line:
                    infix = ': jump address is ' if ': jump address is ' in line else ': the return address is '
                    line_split = line.split(infix)
                    addr = int(line_split[0].strip(), 16)
                    # if addr not in disasm_asm.invalid_address_list:
                    jmp_addr_str = line_split[1].strip()
                    if utils.imm_pat.match(jmp_addr_str):
                        inst = self.address_inst_map[addr]
                        inst_name = inst.split(' ', 1)[0]
                        jmp_addr = int(jmp_addr_str, 16)
                        if inst_name == 'call':
                            if jmp_addr not in disasm.invalid_address_list:
                                self._add_to_address_entries_map(jmp_addr, addr)
                                self.call_to_addr_set.add(addr)
                            else:
                                new_inst = self.address_inst_map[jmp_addr]
                                if new_inst.startswith('jmp') and new_inst.endswith(']') and 'rip' in new_inst:
                                    idx = self.inst_addresses.index(jmp_addr)
                                    rip = self.inst_addresses[idx + 1]
                                    next_addr = utils.extract_content(new_inst, '[')
                                    next_addr = next_addr.replace('rip', hex(rip))
                                    next_addr = eval(next_addr)
                                    if next_addr in self.elf_info.address_sym_table:
                                        sym_name = self.elf_info.address_sym_table[next_addr][0]
                                        if sym_name in lib.TERMINATION_FUNCTIONS:
                                            self.call_to_addr_set.add(addr)
                        else:
                            self._add_to_address_entries_map(jmp_addr, addr)
                elif ': jump addresses resolved using jump table ' in line:
                    line_split = line.split(': jump addresses resolved using jump table ')
                    addr = int(line_split[0].strip(), 16)
                    # if addr not in disasm_asm.invalid_address_list:
                    jmp_table_entries = utils.extract_content(line_split[1].strip(), '[')
                    jmp_table_entries = jmp_table_entries.split(',')
                    jump_targets = [utils.imm_str_to_int(x.strip()) for x in jmp_table_entries]
                    for target in jump_targets:
                        self._add_to_address_entries_map(target, addr)


    def construct_splitted_content(self, disasm_asm):
        new_content = ''
        for address in self.address_inst_map:
            # if address not in disasm_asm.invalid_address_list:
            inst = self.address_inst_map[address]
            if address in disasm_asm.address_label_map:
                new_content += '\n'
            elif self.not_continuous(prev_address):
                prev_inst = self.address_inst_map[prev_address]
                if utils.check_not_single_branch_inst(prev_inst):
                    self._add_to_address_entries_map(address, prev_address)
                new_content += '\n'
            elif address in self.address_entries_map:
                self.address_entries_map[address].append(prev_address)
                new_content += '\n'
            new_content += hex(address) + ': ' + inst + '\n'
            prev_address = address
        # print(new_content)
        return new_content

    def draw(self):
        vertices = self.graph.vertices()
        graph_dict = self.graph.graph_dict()
        res = 'digraph cfg {\n'
        res += '    node [shape=record];\n'
        for vertex in vertices:
            res += self.draw_node(vertex)
            edges = set(graph_dict[vertex])
            for neighbour in edges:
                res += self.draw_edge(vertex, neighbour)
        res += '}'
        with open('cfg.dot', 'w+') as f:
            f.write(res)
        utils.convert_dot_to_png('cfg')

    def draw_node(self, node_id):
        res = '    node_' + hex(node_id) + ' [label=\"'
        res += '<n' + hex(node_id) + '> '
        res += hex(node_id)
        res += '\"];\n'
        return res

    def draw_edge(self, start_node_id, end_node_id):
        res = '    node_' + hex(start_node_id) + ':n' + hex(start_node_id)
        res += ' -> '
        res += 'node_' + hex(end_node_id) + ':n' + hex(end_node_id)
        res += ';\n'
        return res


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Disassembly Soundness Verification')
    parser.add_argument('-t', '--disasm_type', default='objdump', type=str, help='Disassembler')
    parser.add_argument('-f', '--filename', type=str, help='Benchmark file name')
    parser.add_argument('-l', '--lib', default='litmus-test', type=str, help='Benchmark folder name')
    parser.add_argument('-d', '--objdump_dir', default='litmus-test', type=str, help='Objdump folder name')
    parser.add_argument('-L', '--log_dir', default='litmus-test', type=str, help='Disassembled folder name')
    args = parser.parse_args()
    objdump_dir = os.path.join(utils.PROJECT_DIR, args.objdump_dir)
    log_dir = os.path.join(utils.PROJECT_DIR, args.log_dir)
    target_dir = os.path.join(utils.PROJECT_DIR, 'temp')
    file_name = args.filename
    exec_path = os.path.join(utils.PROJECT_DIR, os.path.join(args.lib, file_name))
    disasm_path = os.path.join(objdump_dir, file_name + '.objdump')
    log_path = os.path.join(log_dir, file_name + '.log')
    aux_path = os.path.join(log_dir, file_name + '.aux')
    disasm_asm = Disasm_Objdump(disasm_path)
    ei = ELF_Info(exec_path)
    cg = Construct_Graph(disasm_asm, log_path, ei)
    # cg.draw()
    cg.find_path(0x201e, 0x22a4)
