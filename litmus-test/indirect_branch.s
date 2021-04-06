.intel_syntax noprefix
.text
    .globl _start
_start:
mov    rax, 1
mov    rbx, 2
add    rax, rbx
cmp    rdi, 0x3
ja     foo
mov    eax, edi
lea    rdx, [.jt]
mov    rax, qword ptr [rdx+rax*8]
jmp    rax
.L1:
add    rbx, 2
ret
.L2:
mov    rax, 1
ret
.L3:
imul   rax, rdx
ret
.L4:
mov    rcx, rax
add    rbx, rcx
ret
foo:
add    rbx, 1
mov    rcx, rbx
ret

.section .rodata
.jt:
.quad .L1
.quad .L2
.quad .L3
.quad .L4
