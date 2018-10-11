# load3r

The Note about how to run the file was added after we solved the challenge. Since this was a simple reverse challenge, we were able to solve it using only static analysis.

![alt text](https://raw.githubusercontent.com/happysox/CTF_Writeups/master/InCTF_2018/load3r/pics/load3r.png)

We use `file` and see that we have gotten our hands on some kind of boot loader:
`boot_try.bin: DOS/MBR boot sector`

Running strings on the file yields us, among other things, two interesting strings that suspiciously enough are of the same length:
```
w2g1kS<c7me3keeuSMg1kSk%Se<=S3%/e/
0100010011011101111111011010110101
```
Our first thought is that the string probably holds the correct password and the bitstring is some kind of encryption key.

### Reversing

Now it's time to fire up a disassembler. We used IDA Pro and disassembled it in 16-bit mode.

We find BIOS interrupts for reading characters from the keyboard and writing to the screen. The program asks for a password. A bit further down we find the first manipulation of the entered password.


1. The program takes the password and the bitstring key, goes index-by-index and does a bitwise right shift if the corresponding index of the bitstring is a 0, otherwise it does a left shift.
![alt text](https://raw.githubusercontent.com/happysox/CTF_Writeups/master/InCTF_2018/load3r/pics/ida1.png)

2. After this, we see that the program itirates over the password again, xor'ing every character with 5.
![alt text](https://raw.githubusercontent.com/happysox/CTF_Writeups/master/InCTF_2018/load3r/pics/ida2.png)

3. Finally, the program compares our entered password with the stored encrypted password in reverse.
![alt text](https://raw.githubusercontent.com/happysox/CTF_Writeups/master/InCTF_2018/load3r/pics/ida3.png)

### Solution

We take the stored encrypted password and doing the whole process backwards:

```python
def decrypt(cipher, key):
    #Reverse the string and xor with 5. Bitshift left or right based on key.
    plaintext = ""
    for char, bit in zip(cipher[::-1], key):
        if int(bit):
            plaintext += chr((ord(char)^5) >> 1)
        else:
            plaintext += chr((ord(char)^5) << 1)

    return plaintext

cipher = "w2g1kS<c7me3keeuSMg1kSk%Se<=S3%/e/"
key = "0100010011011101111111011010110101"

print "inctf{%s}" % decrypt(cipher, key)

```
```inctf{T0T@l+pr0+@7+7h1$+8007l04d3r+7h1n9}```
