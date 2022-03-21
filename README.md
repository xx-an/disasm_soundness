# DSV: Disassembly Soundness Validation

# Introduction
This is the artifact belonging the NFM'22 paper entitled *DSV: Disassembly Soundness Validation without Assuming a Ground Truth*. The purpose of this artifact is to provide a permanent snapshot of the code that can be used to reproduce the results presented in that paper.

# Setup
DSV is a tool that automatically validates the soundness of a disassembly process. The project is carried out on Ubuntu 20.04.2 LTS operating system with up-to-date default packages. Besides, you will need to install the following packages.

    python3 (>= 3.7.1)
    java (>= 11.0.2)
    gcc (>= 9.4.0)

Our tool is applied to test 8 different disassemblers, which are respectively 

    objdump (>= 2.30)
    radare2 (3.7.1)
    angr (8.19.7.25)
    BAP (1.6.0)
    Hopper (4.7.3)
    IDA Pro (7.6)
    Ghidra (9.0.4)
    Dyninst(10.2.1)
  
If you want to test any of the disassemblers, you could install the disassembler following the instructions on its official website. Meanwhile, since DSV is implemented using Python, angr could be installed as a package in Python using the following commands:

    sudo apt-get install python3-dev libffi-dev build-essential virtualenvwrapper
    mkvirtualenv --python=$(which python3) angr && pip install angr

# Normalize

After all the packages are installed, DSV could normalize the disassembly results of all the disassemblers in a unified format. It is worth noting that to normalize the output of IDA Pro disassembler, we used an *ida_struct.info* file to keep record of all the struct type information defined by IDA Pro disassembler. Currently, the recorded struct type is sufficient for the testing on our benchmark. If you need to test IDA Pro on some other test cases and some of the IDA-defined struct type is unrecognizable, you could add the corresponding information in the *ida_struct.info* file. The *offset* indicates the offset of corresponding item in the struct.

    struct name: 
      item_name: offset, item_type (? represents undefined or unknown type)

# Benchmark

The compiled binary files for Coreutils library is located at `benchmark/coreutils-build` folder. The disassembled results for the Coreutils library using different disassemblers are respectively stored in `benchmark/coreutils-disassembler` folder. Meanwhile, the testing results for all the test cases are collected in a `statistics.xlsx` file.

# Running test cases

DSV is carried out using the *python -m src.main* command. We use different command-line flags to pass on different arguments and to indicate specific operation. 

  -e, --elf_dir
      Relative path to a binary file
  -l, --log_dir
      Relative path to the assembly file
  -t, --disasm_type
      Type of the disassembler, which could be *objdump, ghidra, radare2, angr, bap, dyninst, hopper, idapro*
  -f, --file_name
      Name of the binary file
  -b, --batch
      Run DSV in batch mode
  -s, --soundness
      Only check the soundness for specific disassembly process
  -v, --verbose
      Whether to print the logging information on the screen
  -c, --bmc_bound
      The default bound of the bounded model checking

For example, to construct the control flow of a specific assembly file disasembled by a disassembler and get the information regarding the number of reachable and unreachable instructions, you could use the following command:

    python -m src.main -e benchmark/coreutils-build -l benchmark/coreutils-radare2 -t radare2 -f basename

To apply DSV to validate the soundness of a disassembly process and report all the incorrectly disassembled instructions after the CFG is constructed:

    python -m src.main -e benchmark/coreutils-build -l benchmark/coreutils-angr -t angr -f basename -s

To use DSV to build up the CFG for all the files under a directory.

    python -m src.main -e benchmark/coreutils-build -l benchmark/coreutils-hopper -t hopper -b

Use DSV to validate the soundness of all the files under a directory after the CFGs are constructed

    python -m src.main -e benchmark/coreutils-build -l benchmark/coreutils-objdump -t objdump -b -s




