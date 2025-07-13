---
title: m0leCon teaser 2023 - rev - NoRegVM Flag Checker
slug: noregvm-flag-checker
published: 2023-05-14
tags: [ CTF, rev, VM, disassembler, linear algebra ]
category: CTF writeups
description: Reversing a flag checker program written for a virtual machine with no registers
---

## About the challenge

This is the rev counterpart for the NoRegVM in m0leCon teaser 2023.

We were given the virtual machine (VM) executable,
the flag checker program, and the initial memory data paired with the checker.

Note to self:
This is your first time successfully solving a VM challenge, and actually
writing a disassembler for it. You should be proud of yourself.

---

## Initial Exploration

The virtual machine is a Linux ELF executable, running in x86_64 architecture.
The binary is not stripped, so the functions calls
representing the instructions show up when
we look up the symbols in the program
(e.g. via readelf).

Note: Usually, it's not that important to look at the architecture
and protections that the VM runs in.
We're reverse engineering a program, not exploiting it.

Running `strings` does not really give much information about the program.
It does show the function names for each instruction the VM
supports, and a string literal that should appear
when the VM fails to open a file.

## Strategy

For VM challenges, the solution usually starts
with reversing the virtual machine, creating a dissassembler for it,
and then reversing the program written for the virtual machine.

## VM software architecture

Most VMs (including this one) are designed to act similarly to hardware.

Here's how the VM works for this challenge:

1. Pre-initialization \
    Memory is allocated for storing the program and memory data.
2. Initialization \
    The program file is read and saved in the VM program memory. \
    The memory file is read and saved in the VM program memory. \
    Other things like program counter (PC), input buffer and output buffer
    are initialized.
3. Fetch \
    The VM fetches the instruction opcode pointed by the program counter. \
    The VM gets the arguments for the instruction.
4. Dispatch \
    The VM passes the arguments to the appropriate handler \
    (function that does the actual execution of the instruction) \
    corresponding to the instruction opcode.
5. Decode \
    The arguments are decoded by the handler, turning them to \
    program jump offsets, memory indices, or input/output buffer pointers.
6. Execute \
    The handler runs the specific calculations for the instruction. \
    Necessary reads and writes to memory are also done here.
7. Next \
    VM goes to the next instruction and goes back to fetch \
    if the VM cannot recognize the opcode, it exits.
8. Termination \
    The VM frees all the space allocated for running the program and memory.

## Reversing the virtual machine

As the title of the challenge suggests, the virtual machine has memory
that can be read and write, but no registers (e.g. rax in x86_64, $gp in MIPS).
This means all the program data - including immediate results from calculations -
are stored in memory, instead of using registers.

The VM architecture is little-endian and has word-addressable memory (addresses
point to 32-bit words, not bytes).

The program is composed of instructions and arguments for instructions.
All instruction opcodes are one word in length, and each argument for
each instruction is one word in length as well.

### program loop

Here is a decompilation of the program loop.

```c
void loop(int *program_start,int *program_end)

{
  int args_read;
  char *p_output;
  int *pc;
  
  p_output = output;
  pc = program_start;

  while (((program_start <= pc && (pc < program_end)) && (*pc != 0))) {
    switch(*pc) {
    case 1:
      args_read = add(pc + 1);
      pc = pc + (args_read + 1);
      break;
    case 2:
      args_read = sub(pc + 1);
      pc = pc + (args_read + 1);
      break;
    case 3:
      args_read = mul(pc + 1);
      pc = pc + (args_read + 1);
      break;
    case 4:
      args_read = divide(pc + 1);
      pc = pc + (args_read + 1);
      break;
    case 5:
      args_read = rst_in();
      pc = pc + (args_read + 1);
      break;
    case 6:
      args_read = rst_out();
      pc = pc + (args_read + 1);
      break;
    case 7:
      args_read = pop_in(pc + 1);
      pc = pc + (args_read + 1);
      break;
    case 8:
      args_read = pop_out(pc + 1);
      pc = pc + (args_read + 1);
      break;
    case 9:
      args_read = read_buf(pc + 1);
      pc = pc + (args_read + 1);
      break;
    case 10:
      args_read = write_buf(pc + 1,&p_output);
      pc = pc + (args_read + 1);
      break;
    case 0xb:
      args_read = jmp(pc + 1);
      pc = pc + (args_read + 1);
      break;
    case 0xc:
      args_read = njmp(pc + 1);
      pc = pc + (args_read + 1);
      break;
    case 0xd:
      args_read = len(pc + 1);
      pc = pc + (args_read + 1);
      break;
    default:
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
  }
}
```

The switch is just the dispatch,
mapping all the supported instruction opcodes
to their respective execution procedures.

Observe that most of the procedures take `pc + 1` as the first parameter.
This is because it points to the first argument of the instrucion. If the
instruction requires more than one arguments, then the the second argument
is at `pc + 2`, third argument is at `pc + 3`, and so on.

Each execution procedure returns how many arguments it read, so that
the VM can determine how many words to skip so we point to the correct
instruction after execution.

Note: `jmp` and `njmp` doen't necessarily return the number of arguments read
(spoiler: they always read two args),
but they return the number of words to skip.

### Arithmetic Operations (add, sub, mul, div)

```c
int add(int *args)

{
  memory[*args] = memory[args[2]] + memory[args[1]];
  return 3;
}

int sub(int *args)

{
  memory[*args] = memory[args[1]] - memory[args[2]];
  return 3;
}

int mul(int *args)

{
  memory[*args] = memory[args[2]] * memory[args[1]];
  return 3;
}

int divide(int *args)

{
  if (memory[2] == 0) {
    memory[*args] = memory[args[1]] / memory[args[2]];
  }
  return 3;
}
```

All three args in all of the arithmetic operations are addresses in memory.
The values for the arithmetic operation are first loaded from memory, before
calculating the result, then storing it in the memory addressed
by the destination index.

### I/O operations

```c
int rst_in(void)

{
  in_pointer = 0;
  return 0;
}

int rst_out(void)

{
  out_pointer = 0;
  return 0;
}
```

These reset operations are just for reseting back the pointers to the input
and output buffers back to the start. They don't take any parameters.

```c
int pop_in(int *args)

{
  long lVar1;
  int i;
  
  for (i = 0; i < args[1]; i = i + 1) {
    lVar1 = (long)in_pointer;
    in_pointer = in_pointer + 1;
    memory[i + *args] = (int)(char)input[lVar1];
  }
  return 2;
}

int pop_out(int *args)

{
  long lVar1;
  int i;
  
  for (i = 0; i < args[1]; i = i + 1) {
    lVar1 = (long)out_pointer;
    out_pointer = out_pointer + 1;
    output[lVar1] = (char)memory[i + *args];
  }
  return 2;
}
```

Both `pop_in` and `pop_out` take two arguments, the first one is
a memory address, the second one (n) is the number of characters to pop.

`pop_in` puts n chars from the input buffer to the memory.
`pop_out` puts n chars from the memory to the output buffer.

Note: when the chars are stored in memory, each char will occupy one word, not
just one byte. This is because the memory is an array of words, not bytes.

```c
int read_buf(int *args)

{
  if (*args < 200) {
    fgets(input,*args,stdin);
  }
  return 1;
}

int write_buf(int *param_1,char **param_2)

{
  if (*param_1 < 200) {
    printf("%s",*param_2);
  }
  return 1;
}
```

`read_buf` takes one argument, the number of chars to read from stdin, and
stores them in the input buffer.
`write_buf` takes two arguments, the number of chars to write to stdout,
and the address of the output buffer.

### Jump operations

```c
int jmp(int *args)

{
  int num_skip;
  
  if ((args[1] == 0) || (memory[args[1]] != 0)) {
    num_skip = *args;
  }
  else {
    num_skip = 2;
  }
  return num_skip;
}


int njmp(int *args)

{
  int num_skip;
  
  if ((args[1] == 0) || (memory[args[1]] == 0)) {
    num_skip = *args;
  }
  else {
    num_skip = 2;
  }
  return num_skip;
}
```

As you can see, `jmp` and `njmp` are identical, except for the condition
check. `jmp` checks if the value at the memory address is non-zero,
while `njmp` checks if the value at the memory address is zero.

`jmp` and `njmp` both take two arguments, the first one is the number of
words to skip if the condition is true, the second one is the memory address
to check the condition.

`jmp` will do the jump if the value in the memory address is non-zero,
while `njmp` will do the jump if the value in the memory address is zero.

### `len` operation

```c
int len(int *args)

{
  size_t string_length;
  int i;
  int *pc_mem_str;
  char built_str [200];
  
  i = 0;
  pc_mem_str = memory + *args;
  while (*pc_mem_str != 0) {
    built_str[i] = (char)*pc_mem_str;
    i = i + 1;
    pc_mem_str = pc_mem_str + 1;
  }
  string_length = strlen(built_str);
  memory[args[1]] = (int)string_length;
  return 2;
}
```

The `len` operation takes two arguments, the first one is the memory address
of the string, the second one is the memory address to store the length of
the string.

The `len` operation will calculate the length of the string, and store it
in the memory address specified by the second argument. This is done by first
rebuilding the string from the memory, then using `strlen` to calculate the
length of the string.

## Writing a disassembler for the VM

The first step to writing a disassembler is to understand the format of the
binary file. The binary file is a sequence of 32-bit words, each word
representing an instruction or an argument.

We can just do a linear sweep of the binary file, and print out the
instructions as we go.
The only thing we need to be careful about is that some instructions
have arguments, and we need to know how many arguments each instruction has.
But that is easy to figure out, since we have the source code for the VM, which
we have already analyzed.

Another thing that I observed while analyzing the flag checker with my
disassembler is that certain memory addresses are used as if they are
registers:

1. The memory address 800 is used as the accumulator (`acc`).
2. The memory address 801 is used as a register for immediate values (`reg`).
3. The memory address 500 has the string literal for when the flag is correct.
4. The memory address 520 has the string literal for when the flag is wrong.

The input buffer is stored in memory
addresses 596 to 621, and I confirmed that while the read_buf operation
at the start reads up to 50 chars from stdin, there is a check after
the read_buf operation that makes sure that the number of chars read
should only be 26 (the length of the flag plus the newline character).

After a few iterations of writing the disassembler, I was able to write
a simple function that can rename the memory addresses to their
corresponding names, and if they are not one of the special memory addresses,
it will print out the value stored in the memory address.

The following is a disassembler I wrote for the VM:

```rust
fn get_register_name(b: u32, memory: &[u32]) -> String {
    if b >= 596 && b - 596 < 26 {
        return format!("input[{}]", b - 596);
    }

    return match b {
        800 => "acc".to_string(),
        801 => "reg".to_string(),
        520 => "wrong".to_string(),
        500 => "correct".to_string(),
        // 900 => "zero".to_string(),
        _ => format!("{}", memory[b as usize]),
    };
}

fn read_stuff(filename: &str) -> Vec<u32> {
    return std::fs::read(filename)
        .expect("ntr: failed to read file")
        .chunks(4)
        .map(|chunk| {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(chunk);
            u32::from_le_bytes(bytes)
        })
        .collect();
}

fn main() {
    let program = read_stuff("challenge.vm");
    let memory = read_stuff("memory.vm");

    // disassemble the program by a one-shot linear sweep

    let mut pc = 0;
    while pc < program.len() {
        let opcode = program[pc];

        match opcode {
            1..=4 => {
                // arithmetic operations
                let a = program[pc + 1];
                let b = program[pc + 2];
                let c = program[pc + 3];

                let a = get_register_name(a, &memory);
                let b = get_register_name(b, &memory);
                let c = get_register_name(c, &memory);

                let op = match opcode {
                    1 => "add",
                    2 => "sub",
                    3 => "mul",
                    4 => "div",
                    _ => unreachable!(),
                };

                println!("{} {}, {}, {}", op, a, b, c);
                pc += 3;
            }
            5 => {
                // rst_in operation
                println!("rst_in");
            }
            6 => {
                // rst_out operation
                println!("rst_out");
            }
            7..=8 => {
                // pop_in and pop_out operations

                let dst = program[pc + 1];
                let num_bytes = program[pc + 2];

                let dst = get_register_name(dst, &memory);

                let op = match opcode {
                    7 => "pop_in",
                    8 => "pop_out",
                    _ => unreachable!(),
                };

                println!("{} {}, {}", op, dst, num_bytes);
                pc += 2;
            }
            9..=10 => {
                // read_buf and write_buf operations

                let arg = program[pc + 1];

                let op = match opcode {
                    9 => "read_buf",
                    10 => "write_buf",
                    _ => unreachable!(),
                };

                println!("{} {}", op, arg);
                pc += 1;
            }
            11..=12 => {
                // jmp and njmp operations

                let arg = program[pc + 1];
                let arg2 = program[pc + 2];

                let arg2 = get_register_name(arg2, &memory);

                let op = match opcode {
                    11 => "jmp",
                    12 => "njmp",
                    _ => unreachable!(),
                };

                println!("{} {}, {}", op, arg, arg2);
                pc += 2;
            }
            13 => {
                // len operation
                let str = program[pc + 1];
                let result = program[pc + 2];

                let str = format!("&{}", get_register_name(str, &memory));
                let result = get_register_name(result, &memory);

                println!("len {}, {}", str, result);
                pc += 2;
            }
            _ => {
                // exit loop
                println!("exit {}", opcode);
            }
        }

        pc += 1;
    }
}
```

---

## The flag checker program

Now that we have a disassembler, we can finally analyze the flag checker.

The flag checker is a program that takes in a flag as input, and checks
if the flag is correct. Let's see the first few lines of the disassembled
flag checker.

```asm
read_buf 50
pop_in input[0], 50
rst_in

len &input[0], acc
sub acc, acc, 26
njmp 9, acc
pop_out wrong, 20
write_buf 10
rst_out
exit 0

add acc, 0, 0
sub reg, input[0], 112  ; 'p'
add acc, acc, reg
sub reg, input[1], 116  ; 't'
add acc, acc, reg
sub reg, input[2], 109  ; 'm'
add acc, acc, reg
sub reg, input[3], 123  ; '{'
add acc, acc, reg
sub reg, input[24], 125 ; '}'
add acc, acc, reg
njmp 9, acc
pop_out wrong, 20
write_buf 10
rst_out
exit 0

...
```

Note: I put some comments and split the code into blocks for readability.

The first few lines of the flag checker reads 50 bytes from stdin,
and stores it in the input buffer. Then, it pops 50 bytes from the input
buffer, and stores it in memory.

After that, it gets the length of the input (that is now stored in memory),
and subtracts 26 from it. If the result is not zero, it jumps to the
`wrong` label, which will print out the message for wrong flag and exit.
If the result is zero, it will continue to the next block of code.
This means that our flag must be 26 characters long, including the newline
(due to `fgets` reading the newline character).

The next block of code checks if the flag is formatted correctly.
It's just a quirky way of checking if the flag starts with `ptm{` and ends
with `}`. If the flag is not formatted correctly, the `njmp` instruction
will not jump, and the program will continue to the next block of code,
which will print out the message for wrong flag and exit.

## do you even math, bro?

The next 20 blocks of code after the initial checks are the most interesting
part of the flag checker. They are all very similar, so I will only explain
the first block.

```asm
add acc, 0, 0
mul reg, input[4], 153
add acc, acc, reg
mul reg, input[5], 83
add acc, acc, reg
mul reg, input[6], 80
add acc, acc, reg
mul reg, input[7], 156
add acc, acc, reg
mul reg, input[8], 14
add acc, acc, reg
mul reg, input[9], 73
add acc, acc, reg
mul reg, input[10], 71
add acc, acc, reg
mul reg, input[11], 117
add acc, acc, reg
mul reg, input[12], 76
add acc, acc, reg
mul reg, input[13], 67
add acc, acc, reg
mul reg, input[14], 120
add acc, acc, reg
mul reg, input[15], 178
add acc, acc, reg
mul reg, input[16], 199
add acc, acc, reg
mul reg, input[17], 158
add acc, acc, reg
mul reg, input[18], 73
add acc, acc, reg
mul reg, input[19], 16
add acc, acc, reg
mul reg, input[20], 86
add acc, acc, reg
mul reg, input[21], 195
add acc, acc, reg
mul reg, input[22], 108
add acc, acc, reg
mul reg, input[23], 129
add acc, acc, reg
sub acc, acc, 234808
njmp 9, acc
pop_out wrong, 20
write_buf 10
rst_out
exit 0
```

This is one of 20 blocks of code that checks if the flag is correct.
It starts with initializing the accumulator to 0, and then multiplying
the ASCII value of each character in the flag with a constant, and adding
it to the accumulator. This is done for each character in the flag (except
for the first 4 characters and the last,
which are already checked in the first few blocks).
After that, it subtracts a constant from the accumulator, and skips the
printing of the wrong flag message if the result is zero.

Basically the `mul` and `add` chain is just a way of calculating the
dot product of the flag and a vector of constants. It's just a multiply and
accumulate operation (MAC),
then a check if the result of the dot product is zero.

This goes on for 20 blocks, involving 20 different vectors of constants, and
the same input chars.

So for the constraints of the flag, we have:

```
input[4] * c_0 + input[5] * c_1 + ... + input[23] * c_22 - c_23 == 0
input[4] * c_24 + input[5] * c_25 + ... + input[23] * c_46 - c_47 == 0
...
```

Which can be rewritten as:

```
input[4] * c_0 + input[5] * c_1 + ... + input[23] * c_22 == c_23
input[4] * c_24 + input[5] * c_25 + ... + input[23] * c_46 == c_47
...
```

Now we can use angr and z3 for this... right?

Me: Got stuck brute-forcing a solution using angr and z3. Calls for
therapy because I'm too dumb to solve this.

[gcheang](https://github.com/gcheang): You know what this looks like?
This looks like linear algebra.

See this
[relevant tweet by cts](https://twitter.com/gf_256/status/1543321843037310985).

## Solving the flag checker with linear algebra

The constraints of the flag checker can be rewritten as a system of linear
equations.

I wrote a python script to generate the system of linear equations from the
disassembly itself.

```python
import numpy as np

# A * x = b

A = []
b = []

with open("disasm.txt", "r") as f:
    # skip 26 lines of disassembly (the initial checks)
    for i in range(26):
        f.readline()

    row = []
    for line in f:
        if line.startswith("add, acc, 0, 0"):
            row = []
        elif line.startswith("mul"):
            row.append(int(line.strip().split(' ')[-1]))
        elif line.startswith("sub"):
            expected_acc = int(line.strip().split(' ')[-1])
            A.append(row[:])
            row = []
            b.append([expected_acc])

A = np.array(A, dtype=np.int32)
b = np.array(b, dtype=np.int32)

assert A.shape[0] == b.shape[0]
assert A.shape[1] == b.shape[0]

x = np.linalg.solve(A, b)
x = np.rint(x)

flag = 'ptm{'

for i in range(len(x)):
    flag += chr(round(x[i][0]))

flag += '}'

print(flag)
```

Running the script should give us the flag, because after the 20 blocks of
crunching MACs, the flag checker will print out the "Flag correct!" message.

```
pop_out correct, 20
write_buf 10
rst_out
exit 0
```

And here is when we enter the flag as input in the VM:

```
$ ./challenge challenge.vm memory.vm
ptm{rngahuzruxaoczobmdlw}
Flag correct!
```
