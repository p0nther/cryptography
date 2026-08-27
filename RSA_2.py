"""
#Objective: find m you've  q,p,c,e

#Methodology: 

n=p*q
e=
m=c^d mod n

to find d 
d=e^-1 mod phi(n)

phi(n)= (q-1)*(p-1)



#Lesson&Mistakes:
    1- don't forget to convert from int to bytes with   m.to_bytes(256,"little")


"""

from pwn import *

io=process("/challenge/run")

io.recvuntil(b"e = ")
e=int(io.recvline(), 16)

io.recvuntil(b"p = ")
p=int(io.recvline(), 16)

io.recvuntil(b"q = ")
q=int(io.recvline(), 16)

io.recvuntil(b"Flag Ciphertext (hex): ")
c=io.recvline()
c=bytes.fromhex(c.decode())
c=int.from_bytes(c,"little")

phi=(p-1)*(q-1)
d=pow(e,-1,phi)

n=q*p
m=pow(c,d,n)

print(m.to_bytes(256,"little").strip(b"\x00").decode())
