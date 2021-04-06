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

class Constraint:
    cnt = 0

    def __init__(self, parent, last_predicate):
        self.predicate = last_predicate
        self.parent = parent
        self.id = self.__class__.cnt
        self.__class__.cnt += 1

    def __eq__(self, other):
        """Two Constraints are equal iff they have the same chain of predicates"""
        if isinstance(other, Constraint):
            if not self.predicate == other.predicate:
                return False
            return self.parent is other.parent
        else:
            return False

    def update_predicate(self, last_predicate):
        self.predicate = last_predicate

    def get_asserts_and_query(self):
        asserts = []
        tmp = self.parent
        while tmp is not None and tmp.parent is not None:
            asserts.append(tmp.predicate)
            tmp = tmp.parent
        return asserts, self.predicate

    def get_length(self):
        if self.parent == None:
            return 0
        return 1 + self.parent.get_length()

    def __str__(self):
        return str(self.predicate)#  + " (path_len: %d)" % (self.get_length())

    def __repr__(self):
        s = repr(self.predicate)
        if self.parent is not None:
            s += "\\l%s" % repr(self.parent)
        return s

    def draw(self):
        return self.__repr__()
