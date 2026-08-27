"""
#Objective: 
    you've e,d,n,c find the m
    
#Methodology: 
    m=c^d mod n
    convert m form int to hex with hex(m)

#Lesson&Mistakes: 
    1- don't forget to use hex(m) to convert your massege to hex

"""
#POC

from pwn import *

io=process("/challenge/run")
io.recvuntil(b"e: ")
e=int(io.recvline(),16)

io.recvuntil(b"d: ")
d=int(io.recvline(),16)

io.recvuntil(b"n:")
n=int(io.recvline(),16)

io.recvuntil(b"challenge: ")
c=int(io.recvline(),16)

m=pow(c,d,n)

io.sendlineafter(b"response:",str(hex(m)).encode())

val=io.recvall().decode()

print(val)
