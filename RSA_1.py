"""
#Objective: find m


#Methodology: 
    i have c,d,n 
    m= c^d mod n


#Lesson&Mistakes: 
    1- the problem in conerting from to int,byte
    
"""


from pwn import *

io = process('/challenge/run')

# استقبال الـ values
io.recvuntil(b'n = ')
n = int(io.recvline(), 16)

io.recvuntil(b'e = ')
e = int(io.recvline(), 16)

io.recvuntil(b'd = ')
d = int(io.recvline(), 16)

io.recvuntil(b'Flag Ciphertext (hex): ')
c_hex = io.recvline().strip()

# تحويل الـ ciphertext صح (little-endian)
c = int.from_bytes(bytes.fromhex(c_hex.decode()), "little")

# decrypt
m = pow(c, d, n)

# طباعة الـ flag
print(m.to_bytes(256, "little").strip(b"\x00").decode())
