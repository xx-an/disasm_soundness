section .rodata
message_a: db "This is location A\n",0
message_b: db "This is location B\n",0
message_c: db "This is location C\n",0

section .text
    global main
    extern puts
main:
push   rbp
mov    rbp,rsp
sub    rsp,0x40
mov    dword [rbp-0x34],edi
xor    eax,eax
mov    dword [rbp-0x28],0x0
jmp    $+0x1d
mov    eax,dword [rbp-0x28]
mov    edi,eax
call   _pick
mov    rdx,rax
mov    eax,dword [rbp-0x28]
cdqe   
mov    qword [rbp+rax*8-0x20],rdx
add    dword [rbp-0x28],0x1
cmp    dword [rbp-0x28],0x2
jle    $-31
mov    dword [rbp-0x24],0x0
jmp    $+0x18
mov    eax,dword [rbp-0x24]
cdqe   
mov    rax,qword [rbp+rax*8-0x20]
mov    rdi,rax
call   _callback
add    dword [rbp-0x24],0x1
mov    eax,dword [rbp-0x34]
mov    esi,eax
mov    edi,0x3
call   _min
cmp    dword [rbp-0x24],eax
jl     $-40
mov    eax,0x0
leave  
ret        

_pick:
push   rbp
mov    rbp,rsp
mov    dword [rbp-0x4],edi
mov    eax,dword [rbp-0x4]
cmp    eax,0x1
je     $+0x15
cmp    eax,0x2
je     $+0x1a
test   eax,eax
jne    $+0x20
lea    rax,[$+0x20]
jmp    $+0x16
lea    rax,[$+0x28]
jmp    $+0xc
lea    rax,[$+0x30]
jmp    $+0x2
pop    rbp
ret
push   rbp
mov    rbp,rsp
lea    rdi,[rel message_a]
call   puts wrt ..plt
pop    rbp
ret
push   rbp
mov    rbp,rsp
lea    rdi,[rel message_b]
call   puts wrt ..plt
pop    rbp
ret    
push   rbp
mov    rbp,rsp
lea    rdi,[rel message_c]
call   puts wrt ..plt
pop    rbp
ret 

_callback:
push   rbp
mov    rbp,rsp
sub    rsp,0x10
mov    qword [rbp-0x8],rdi
mov    rdx,qword [rbp-0x8]
mov    eax,0x0
call   rdx
leave  
ret    

_min:
push   rbp
mov    rbp,rsp
mov    dword [rbp-0x4],edi
mov    dword [rbp-0x8],esi
mov    eax,dword [rbp-0x4]
cmp    dword [rbp-0x8],eax
cmovle eax,dword [rbp-0x8]
pop    rbp
ret    



