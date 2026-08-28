"""
#Objective: 
    PoW creator 'Adam Back, will give me a massege when i will apppend random data to it and do hash must start with 2 null-bytes

#Methodology:
    recive b64 data decode it ,
    do while loop then take the value and append it to the massege ,
    compare if it start with 2 null-bytes fetch this value then encode(b64) it and send to server

#Lesson&Mistakes:
    - hash give you data as raw byte convert it to hex (from raw to hex)
"""

import base64 
from pwn import *
import hashlib

io = process("/challenge/run")

io.recvuntil(b"challenge (b64):")
massege_b64 = io.recvline().strip().decode()
massege = base64.b64decode(massege_b64)

i = 0 
while True:
    print(f"[*] Starting brute force with nonce: {i}", end="\r", flush=True)
    full_payload = massege + str(i).encode()
    result_hash = hashlib.sha256(full_payload).hexdigest()
    
    if result_hash.startswith("0000"):
        print(f"\n[+] Found Solution! Nonce: {i}")
        print(f"[+] Hash: {result_hash}")
        
        PoW = base64.b64encode(str(i).encode())
        io.sendlineafter(b"response (b64):", PoW)
        break 
    
    i += 1

 
print(io.recvall().decode())
