#!/usr/bin/python

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
