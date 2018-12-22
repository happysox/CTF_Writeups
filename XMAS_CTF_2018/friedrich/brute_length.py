#!/usr/bin/python2
from pwn import *

msg = "length"
i = 1

with context.quiet:
    while "length" in msg:
        p = process('./repaired')
        p.sendline("A"*i)
        msg = p.recvline()
        p.close()
        i+=1
print i-1
