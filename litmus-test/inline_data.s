.intel_syntax noprefix
.text
    .globl _start
_start:
mov    rax, 0x1
mov    rbx, 0x2
add    rax, rbx
cmp    rax, 0x3
jmp    foo
.byte 0x1,0x2
.align 64
foo:
mov   rcx, 0x4
add   rcx, rax
ret


