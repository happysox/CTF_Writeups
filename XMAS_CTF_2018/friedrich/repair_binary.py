#!/usr/bin/python2

with open("chall","r") as fh:
    raw = fh.read()

unxored=""
for i in range(0, 200):
    print i, raw[i]
    unxored+=chr(ord(raw[i])^13)

repaired = unxored + raw[200:]

with open("repaired", "w") as fh:
    fh.write(repaired)
