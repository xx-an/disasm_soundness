Compile and link different assembly files under litmus-test directory

Overlapping
$ nasm -f elf64 overlapping.s
$ gcc overlapping.o -nostdlib -m64 -o overlapping

Inline data
$ gcc -Wall -Wextra -nostdlib -Wl,-e_start inline_data.s -o inline_data

Indirect branch
$ as -gstabs indirect_branch.s -o indirect_branch.o
$ ld --dynamic-linker /lib/ld-linux-x86-64.so.2 -o indirect_branch indirect_branch.o -lc

Callback
$ nasm -f elf64 callback.s
$ gcc callback.o -m64 -no-pie -o callback


