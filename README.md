# DSV: Disassembly Soundness Validation

DSV is a tool that automatically validates the soundness of a disassembly process.

DSV structure:

    benchmark

    litmus-test

    micro-benchmark

    src

    lib

    LICENSE

    README.md




Prerequisites:

    python3 (>= 3.7.1)

    java (>=11.0.2)

    objdump (>= 2.30)

    radare2 (3.7.1)

    angr (8.19.7.25)

    BAP (1.6.0)

    Ghidra (9.0.4)

      |-- Download Ghidra package from https://www.ghidra-sre.org/

      |-- Move Ghidra package under the DSV/lib directory

      |-- $ cd ghidra_9.0.4

      |-- $ ./ghidraRun

    Dyninst(10.2.1)

      |-- Download, make and install the dyninst following the steps in https://github.com/dyninst/dyninst/releases/tag/v10.2.1

      |-- Add the lib of the installed dyninst project to LD_LIBRARY_PATH

      |-- Execute the following command under DSV/lib directory

      |-- $ g++ -std=c++0x -o disassemble_dyninst disassemble_dyninst.cc -L/usr/local/share/dyninst/lib -I/usr/local/share/dyninst/include -lparseAPI -linstructionAPI -lsymtabAPI -lsymLite -ldynDwarf -ldynElf -lcommon -lelf -ldwarf -lboost_system



Note:

    -- The compiled binary files for Coreutils are located at DSV/benchmark/coreutils-build

    -- The test cases used in Section 5.2 is stored in DSV/litmus-test

    -- A package of Ghidra and Dyninst has been stored in the DSV/lib directory



Apply DSV to construct a CFG on a specific file disasembled by a disassembler and get the information regarding # of instructions and unreachable instructions ...

    $ python -m src.main -e benchmark/coreutils-build -l benchmark/coreutils-radare2 -t radare2 -f basename



Apply DSV to validate the soundness and report all the incorrectly disassembled instructions after the CFG is constructed

    $ python -m src.main -e benchmark/coreutils-build -l benchmark/coreutils-radare2 -t radare2 -f basename -s



Use DSV to build up the CFG for all the files under a directory

    $ python -m src.main -e benchmark/coreutils-build -l benchmark/coreutils-radare2 -t radare2 -b



Use DSV to validate the soundness of all the files under a directory after the CFGs are constructed

    $ python -m src.main -e benchmark/coreutils-build -l benchmark/coreutils-radare2 -t radare2 -b -s


