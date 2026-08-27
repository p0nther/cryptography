"""
#Objective: do strxor on string

#Methodology: use strxor to do it but don't  forget to use b'' 'cause strxor only work on bytes not string 

#Lesson&Mistakes: 
    1) don't forget to use strip() and put the fully recvuntil 
    2) use EOFError and break when it's happen that mean the loop is done and 'p.process' ended
    
"""


# POC

import sys
from Crypto.Util.strxor import strxor
from pwn import *

p=process("/challenge/run")

for i in range (10):
    try:
        p.recvuntil(b"- Encrypted String: ")
        encrypted=p.recvline().strip()

        p.recvuntil(b"- XOR Key String: ")
        key=p.recvline().strip()

        decrypted=strxor(encrypted,key)
        p.sendlineafter(b"- Decrypted String?",decrypted)
        print(f"challenge: {i}, Decrypted: {decrypted}")
    except EOFError:
        break
print(p.recvall().decode())
