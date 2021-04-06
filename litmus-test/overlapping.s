section .text
    global _start
_start:
mov eax, 0x10
mov ecx, 0x20
add eax, ecx
jmp $-10
add eax, ebx
ret
