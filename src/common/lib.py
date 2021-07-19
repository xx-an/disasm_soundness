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

CONDITIONAL_FLAGS = {
    'a': 'CF==0 and ZF==0',
    'ae': 'CF==0',
    'b': 'CF==1',
    'be': 'CF==1 or ZF==1',
    'c': 'CF==1',
    'e': 'ZF==1',
    'g': 'ZF==0 and SF==OF',
    'ge': 'SF==OF',
    'l': 'SF<>OF',
    'le': 'ZF==1 or SF<>OF',
    'na': 'CF==1 or ZF==1',
    'nae': 'CF==1',
    'nb': 'CF==0',
    'nbe': 'CF==0 and ZF==0',
    'nc': 'CF==0',
    'ne': 'ZF==0',
    'ng': 'ZF==1 or SF<>OF',
    'nge': 'SF<>OF',
    'nl': 'SF==OF',
    'nle': 'ZF==0 and SF==OF',
    'no': 'OF==0',
    'np': 'PF==0',
    'ns': 'SF==0',
    'nz': 'ZF==0',
    'o': 'OF==1',
    'p': 'PF==1',
    'pe': 'PF==1',
    'po': 'PF==0',
    's': 'SF==1',
    'z': 'ZF==1',
}

REG_INFO_DICT = {
    'ah': ('rax', 8, 8),
    'bh': ('rbx', 8, 8),
    'ch': ('rcx', 8, 8),
    'dh': ('rdx', 8, 8),
    'eax': ('rax', 0, 32),
    'ax': ('rax', 0, 16),
    'al': ('rax', 0, 8),
    'ebx': ('rbx', 0, 32),
    'bx': ('rbx', 0, 16),
    'bl': ('rbx', 0, 8),
    'ecx': ('rcx', 0, 32),
    'cx': ('rcx', 0, 16),
    'cl': ('rcx', 0, 8),
    'edx': ('rdx', 0, 32),
    'dx': ('rdx', 0, 16),
    'dl': ('rdx', 0, 8),
    'esi': ('rsi', 0, 32),
    'si': ('rsi', 0, 16),
    'sil': ('rsi', 0, 8),
    'edi': ('rdi', 0, 32),
    'di': ('rdi', 0, 16),
    'dil': ('rdi', 0, 8),
    'ebp': ('rbp', 0, 32),
    'bp': ('rbp', 0, 16),
    'bpl': ('rbp', 0, 8),
    'esp': ('rsp', 0, 32),
    'sp': ('rsp', 0, 16),
    'spl': ('rsp', 0, 8),
    'r8d': ('r8', 0, 32),
    'r8w': ('r8', 0, 16),
    'r8b': ('r8', 0, 8),
    'r9d': ('r9', 0, 32),
    'r9w': ('r9', 0, 16),
    'r9b': ('r9', 0, 8),
    'r10d': ('r10', 0, 32),
    'r10w': ('r10', 0, 16),
    'r10b': ('r10', 0, 8),
    'r11d': ('r11', 0, 32),
    'r11w': ('r11', 0, 16),
    'r11b': ('r11', 0, 8),
    'r12d': ('r12', 0, 32),
    'r12w': ('r12', 0, 16),
    'r12b': ('r12', 0, 8),
    'r13d': ('r13', 0, 32),
    'r13w': ('r13', 0, 16),
    'r13b': ('r13', 0, 8),
    'r14d': ('r14', 0, 32),
    'r14w': ('r14', 0, 16),
    'r14b': ('r14', 0, 8),
    'r15d': ('r15', 0, 32),
    'r15w': ('r15', 0, 16),
    'r15b': ('r15', 0, 8)
}


AUX_REG_INFO = {
    8: ('al', 'ah', 'ax'),
    16: ('ax', 'dx', 'dx:ax'),
    32: ('eax', 'edx', 'edx:eax'),
    64: ('rax', 'rdx', 'rdx:rax')
}

REG64_NAMES = {'rax', 'rbx', 'rcx', 'rdx', 'rsp', 'rbp', 'rsi', 'rdi', 
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'}

REG_NAMES = REG64_NAMES | set(REG_INFO_DICT.keys())

FLOATING_POINT_ST_REGS = ('st0', 'st1', 'st2', 'st3', 'st4', 'st5', 'st6', 'st7')

CONDITIONAL_JMP_INST = set(map(lambda x: 'j' + x, CONDITIONAL_FLAGS.keys()))

RFlags = ['CF', 'ZF', 'OF', 'SF', 'PF']

SEG_REGS = {'ss', 'cs', 'ds', 'es', 'fs', 'gs'}

JMP_INST = CONDITIONAL_JMP_INST | {'jmp', 'call', 'ret'}

JMP_INST_WITHOUT_CALL = CONDITIONAL_JMP_INST | {'jmp', 'ret'}

JMP_INST_WITH_ADDRESS = CONDITIONAL_JMP_INST | {'jmp', 'call'}

DEFAULT_REG_LEN = 64
C_INT_LEN = 32

REG = 'register'
MEM = 'memory'
FLAGS = 'flags'
SEG = 'segment_register'
AUX_MEM = 'aux_memory'

STATE_NAMES = {REG, MEM, FLAGS, SEG, AUX_MEM}
RECORD_STATE_NAMES = [REG, MEM]

TERMINATION_FUNCTIONS = {
    "__stack_chk_fail",
    "__overflow",
    "err",
    "error",
    "error_at_line",
    "errx",
    "exit",
    "_exit",
    "abort",
    "raise",
    "__assert_fail",
    "g_assertion_message_expr",
    "g_assertion_message",
    "g_abort",
    "obstack_alloc_failed_handler",
    "pthread_exit"
}


GENERAL_INSTRUCTIONS = {
    'mov', 'lea', 'push', 'pop', 'add', 'sub', 'xor',
    'and', 'or', 'sar', 'shr', 'sal', 'shl', 'xchg',
    'neg', 'not', 'test', 'cmp', 'imul', 'mul', 'idiv', 'div',
    'cmpxchg', 'movzx', 'movsx', 'movsxd', 'leave', 'inc', 'dec', 'adc', 'sbb',
    'cbw', 'cwde', 'cdqe','cwd', 'cdq', 'cqo', 'ror', 'rol', 'nop', 'hlt'
}


INSTS_AFF_FLAGS_WO_CMP_TEST = {
    'add', 'sub', 'xor', 'and', 'or', 'sar', 'shr', 'sal', 'shl',
    'neg', 'not', 'imul', 'mul', 'inc', 'dec', 'adc', 'sbb', 'ror', 'rol'
    }

BAP_RELATED_INST = {'stos', 'fild', 'fld', 'fstp', 'fadd'}

CODE_SEGMENTS = ('.plt.got', '.plt', '.text')

DATA_SEGMENTS = ('.rodata', '.data', '.bss')

CONDITIONAL_MOV_INST = set(map(lambda x: 'cmov' + x, CONDITIONAL_FLAGS.keys()))

CONDITIONAL_SET_INST = set(map(lambda x: 'set' + x, CONDITIONAL_FLAGS.keys()))

INSTRUCTIONS = GENERAL_INSTRUCTIONS | JMP_INST | CONDITIONAL_MOV_INST | CONDITIONAL_SET_INST | BAP_RELATED_INST


def init_ida_struct_info():
    ida_struct_table = {}
    ida_struct_table['mbstate_t'] = {}
    ida_struct_table['mbstate_t']['__count'] = (0, 'dd')
    ida_struct_table['mbstate_t']['__value'] = (4, '?')
    ida_struct_table['timespec'] = {}
    ida_struct_table['timespec']['tv_sec'] = (0, 'dq')
    ida_struct_table['timespec']['tv_nsec'] = (8, 'dq')
    ida_struct_table['sigset_t'] = {}
    ida_struct_table['sigset_t']['__val'] = (0, 'dq')
    ida_struct_table['tm'] = {}
    ida_struct_table['tm']['tm_sec'] = (0, 'dd')
    ida_struct_table['tm']['tm_min'] = (4, 'dd')
    ida_struct_table['tm']['tm_hour'] = (8, 'dd')
    ida_struct_table['tm']['tm_mday'] = (12, 'dd')
    ida_struct_table['tm']['tm_mon'] = (16, 'dd')
    ida_struct_table['tm']['tm_year'] = (20, 'dd')
    ida_struct_table['tm']['tm_wday'] = (24, 'dd')
    ida_struct_table['tm']['tm_yday'] = (28, 'dd')
    ida_struct_table['tm']['tm_isdst'] = (32, 'dd')
    ida_struct_table['tm']['tm_gmtoff'] = (40, 'dq')
    ida_struct_table['tm']['tm_zone'] = (48, 'dq')
    ida_struct_table['stat'] = {}
    ida_struct_table['stat']['st_dev'] = (0, 'dq')
    ida_struct_table['stat']['st_ino'] = (8, 'dq')
    ida_struct_table['stat']['st_nlink'] = (16, 'dq')
    ida_struct_table['stat']['st_mode'] = (24, 'dd')
    ida_struct_table['stat']['st_uid'] = (28, 'dd')
    ida_struct_table['stat']['st_gid'] = (32, 'dd')
    ida_struct_table['stat']['st_rdev'] = (40, 'dq')
    ida_struct_table['stat']['st_size'] = (48, 'dq')
    ida_struct_table['stat']['st_blksize'] = (56, 'dq')
    ida_struct_table['stat']['st_blocks'] = (64, 'dq')
    ida_struct_table['stat']['st_atim'] = (72, 'timespec')
    ida_struct_table['stat']['st_mtim'] = (88, 'timespec')
    ida_struct_table['stat']['st_ctim'] = (104, 'timespec')
    ida_struct_table['itimerspec'] = {}
    ida_struct_table['itimerspec']['it_interval'] = (0, 'timespec')
    ida_struct_table['itimerspec']['it_value'] = (16, 'timespec')
    ida_struct_table['timeval'] = {}
    ida_struct_table['timeval']['tv_sec'] = (0, 'dq')
    ida_struct_table['timeval']['tv_usec'] = (8, 'dq')
    ida_struct_table['statfs'] = {}
    ida_struct_table['statfs']['f_type'] = (0, 'dq')
    ida_struct_table['statfs']['f_bsize'] = (8, 'dq')
    ida_struct_table['statfs']['f_blocks'] = (16, 'dq')
    ida_struct_table['statfs']['f_bfree'] = (24, 'dq')
    ida_struct_table['statfs']['f_bavail'] = (32, 'dq')
    ida_struct_table['statfs']['f_files'] = (40, 'dq')
    ida_struct_table['statfs']['f_ffree'] = (48, 'dq')
    ida_struct_table['statfs']['f_fsid'] = (56, '?')
    ida_struct_table['statfs']['f_namelen'] = (64, 'dq')
    ida_struct_table['statfs']['f_frsize'] = (72, 'dq')
    ida_struct_table['statfs']['f_flags'] = (80, 'dq')
    ida_struct_table['statfs']['f_spare'] = (88, 'dq')
    ida_struct_table['termios'] = {}
    ida_struct_table['termios']['c_iflag'] = (0, 'dd')
    ida_struct_table['termios']['c_oflag'] = (4, 'dd')
    ida_struct_table['termios']['c_cflag'] = (8, 'dd')
    ida_struct_table['termios']['c_lflag'] = (12, 'dd')
    ida_struct_table['termios']['c_line'] = (16, 'db')
    ida_struct_table['termios']['c_cc'] = (17, 'db')
    ida_struct_table['termios']['c_ispeed'] = (52, 'dd')
    ida_struct_table['termios']['c_ospeed'] = (56, 'dd')
    return ida_struct_table

