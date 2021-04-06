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

from . import utils

class Inst_Elem(object):
    def __init__(self, inst):
        inst = inst.strip()
        inst_split = inst.split(' ', 1)
        self.inst_name = inst_split[0].strip()
        self.inst_args = utils.extract_inst_args(inst_split)


    def reverse_arg_order(self):
        self.inst_args.reverse()


    def normalize(self, address, format_arg, rewrite_inst=utils.id_op, *args):
        inst_args = list(map(lambda x: format_arg(address, self.inst_name, x, *args), self.inst_args))
        inst_arg = ','.join(inst_args)
        result = self.inst_name + ' ' + inst_arg
        return rewrite_inst(result)

