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

import sys
from ..common import utils

class State(object):

    cnt = -1
    
    def __init__(self, parent_no, address, inst, sym_store, constraint, state_no=None):
        self.parent_no = parent_no
        self.address = address
        self.inst = inst
        self.sym_store = sym_store
        self.constraint = constraint
        self.children_state_list = []
        if state_no:
            self.state_no = state_no
        else:
            self.state_no = self.__class__.cnt
            self.__class__.cnt += 1


    def add_to_children_list(self, state_no):
        self.children_state_list.append(state_no)

    
    def draw(self):
        res = '    state_' + str(self.state_no) + ' [label=\"'
        res += '<b' + str(self.state_no) + '> '
        res += self.inst
        res += '\\l'
        if self.sym_store:
            res += '|' + self.sym_store.draw()
        if self.constraint:
            res += '|' + self.constraint.draw()
        res += '\"];\n'
        return res


    def draw_edge(self):
        res = '    state_' + str(self.state_no) + ':b' + str(self.state_no)
        res += ' -> {'
        for end_state in self.children_state_list:
            end_state_no = end_state.state_no
            res += 'state_' + str(end_state_no) + ':b' + str(end_state_no)
            res += ' '
        res += '};\n'
        return res

    