#!/usr/bin/python2
from Crypto.Cipher import AES
from binascii import unhexlify

def decrypt(key, cipher_text):
    aes = AES.new(key)
    plaintext = aes.decrypt(cipher_text[:16])
    return plaintext

cipher_text = unhexlify("a629fc7035ccd2df99fb42ebc25e4f9f")
print decrypt("ITSTHECRYPTOKEY!", cipher_text)
