"""
#Objective: 
    how to create rsa e,n,d from scratch in this challenge you will send the public-key then encrypt the massege with your private-key , after that you'll recive a cipher massege decrypt it with you private key

#Methodology:
    i wanna create e,d,n
    1- send e,n
    2- decrpt the massage with you d and send the value 
    3- recive the last massege that contain the flag dcrypt it with your d to find the flag 'this ct with b64'
    4- decode it b64 then convert it form byte to int to process it with m=c^d mod n
    

#Lesson&Mistakes:   
    1- in this challenge it need n value (2**512 < n < 2**1024) to do that do RSA.generate(1024)
    2- how to convert from int to str with little endain 
    3- don't forget to convert c in io. to in c=int(io.recvline(),16) 
    4- we need to convert from nubmer to readable data so --> flag.to_bytes(256,"little") to convert the flag to 256 byte with little endain 
       the flag len is 50 so we have 206 byte with \x00 to fill | you'll see \x00 when you read to do strip("\x00")    
    5- we use little because in this challenge the server use little ---> ciphertext = pow(int.from_bytes(flag, "little"), e, n).to_bytes(256, "little")

"""

import base64
from Crypto.PublicKey import RSA
from pwn import *

 
key = RSA.generate(1024)

e_int = key.e
n_int = key.n
d_int = key.d

 
io = process("/challenge/run")

 
io.sendlineafter(b"e: ", hex(e_int).encode())
io.sendlineafter(b"n: ", hex(n_int).encode())

 
io.recvuntil(b"challenge: ")
c = int(io.recvline().strip(), 16)

 
m = pow(c, d_int, n_int)
io.sendlineafter(b"response: ", hex(m).encode()) 

 
io.recvuntil(b"secret ciphertext (b64): ")
flag_b64 = io.recvline().strip().decode()

 
flag_bytes = base64.b64decode(flag_b64)
flag_ct = int.from_bytes(flag_bytes, "little")

final_m = pow(flag_ct, d_int, n_int)

 
flag = final_m.to_bytes(256, "little").decode(errors="ignore").strip("\x00")
print(f"My_flag: {flag}")
