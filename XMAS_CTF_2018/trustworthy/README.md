# Santa thinks you're trustworthy

![](pics/trustworthy.png)

### Summary

* Analyze TCP protocol used to play tic-tac-toe against a server
* Cheat

### Walkthrough
We are given an ELF `client`, and instructions for how to use it.
```
client: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e38d91544ca9e0e975db6c04ab1ac6772ae877f3, not stripped
```

```
$ ./client 199.247.6.180
```
We get to play tic-tac-toe, where we start (we place X's and the server places O's).
```
press 'q' to quit
| | | |
| | | |
| | | |
```
```
press 'q' to quit
|X| | |
| |O| |
| | | |
```
Seems impossible to win since the computer always makes the right move.
```
press 'q' to quit
|X|O| |
|O|O|X|
|X|X|O|
```
The description also told us to win, so let's figure out how.

### Network analysis
Using Wireshark to filter on IP:
`ip.addr == 199.247.6.180`
shows us that the server runs on port 11000. I used "Follow TCP Stream" to see the conversation:


```
ff582020202020202020a7
582020204f20202020
ff585820204f20202020b0
58584f204f20202020
ff58584f204f20582020a7
58584f4f4f20582020
ff58584f4f4f20585820b0
58584f4f4f4f585820
```

The protocol seems very simple. The client and server sends the state of the game board back and forth. The client, prepends `ff` and rotates between appending `a7` or `b0` every turn.

```
ff582020202020202020a7 //client sends:
                                        |X| | |
                                        | | | |
                                        | | | |
582020204f20202020     //server sends:
                                        |X| | |
                                        | |O| |
                                        | | | |
ff585820204f20202020b0 //client sends:
                                        |X|X| |
                                        | |O| |
                                        | | | |
58584f204f20202020     //server sends:
                                        |X|X|O|
                                        | |O| |
                                        | | | |
etc...
```

### Solution

So I wrote a python script to cheat. The server seemed to have *a little* validation against cheating, as we couldn't straight up send a 3-in-a-row board. Sending a board with 3 X's in a row means we also have to send 2 O's in reasonable places:

```python
#!/usr/bin/python2
from pwn import *
from binascii import hexlify, unhexlify

state = "202020202020202020"
tick = 0

def send_move(index, state, tick):
    state=state[:index*2] + "58" + state[(index+1)*2:]
    end = "a7" if tick==0 else "b0"
    tick = (tick + 1) % 2
    to_send = "ff"+state+end
    p.sendline(unhexlify(to_send))
    return state, tick

def parse_response():
    state = hexlify(p.recv())
    return state

def cheat(state, tick):
    state = "585858204f4f202020"
    print "sending custom state: %s" % bytes(state)
    end = "a7" if tick==0 else "b0"
    tick = (tick + 1) % 2
    to_send = "ff"+state+end
    p.sendline(unhexlify(to_send))
    return state, tick

with context.verbose:
    p = remote('199.247.6.180', 11000)
    state, tick = send_move(0, state, tick)
    state = parse_response()
    state, tick = send_move(1, state, tick)
    state = parse_response()
    #Cheating time:
    state, tick = cheat(state, tick)
    p.recvall()
```


```
$ ./exploit.py 
[+] Opening connection to 199.247.6.180 on port 11000: Done
[DEBUG] Sent 0xc bytes:
    00000000  ff 58 20 20  20 20 20 20  20 20 a7 0a               │·X  │    │  ··││
    0000000c
[DEBUG] Received 0x9 bytes:
    'X   O    '
[DEBUG] Sent 0xc bytes:
    00000000  ff 58 58 20  20 4f 20 20  20 20 b0 0a               │·XX │ O  │  ··││
    0000000c
[DEBUG] Received 0x9 bytes:
    'XXO O    '
   *** ^ our three in a row is blocked ***

sending custom state: 585858204f4f202020

[DEBUG] Sent 0xc bytes:
    00000000  ff 58 58 58  20 4f 4f 20  20 20 a7 0a               │·XXX│ OO │  ··││
                *** We move the server's "O"                 from here^   ^to here
                    And place our third X in its place ***
    0000000c
[-] Receiving all data: Failed
[DEBUG] Received 0x22 bytes:
    'X-MAS{cl13n7_v4l1d4710n_5uck5____}'
```
