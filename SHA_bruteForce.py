"""
# Objective:
Find a partial hash collision for the SHA256 algorithm based on the first 3 bytes (6 hex characters) required by the challenge to bypass the verification system.

# Methodology:
    1. Receive the target partial hash prefix from the challenge 
    2. Implement a brute-force loop that starts from 0 and increments sequentially.
    3. Encode the integer into bytes and calculate its SHA256 cryptographic hash.
    4. Compare the hex output prefix with the target. Once a match is found, convert the original input data (i) into hex format and send it to the challenge.
    5. challenge take it and do hash for it to ensure that is start with the target prefix

# Lesson & Mistakes:
    - The initial mistake was entering a raw string like "he" when the challenge strictly expected hexadecimal input.
    - Cryptographic hash functions like SHA256 are highly sensitive to any input changes (Avalanche Effect). Brute-forcing is the only practical solution here due to the small search space (3 bytes = 24 bits).
    - Note on Scaling: If the required prefix length increases to 7 bytes instead of 3, the complexity grows exponentially. The search space would become 2^(7*8) = 2^56 total possibilities, which requires significantly more computational power and time to brute-force.
    - in pwntool io.recvuntil(b"'", drop=True) will read until ' then remove it
    
"""
import hashlib
from pwn import *


io = process("/challenge/run")
io.recvuntil(b"flag_hash[:prefix_length]='")

 
target_hash = io.recvuntil(b"'", drop=True).strip().decode()


def brute_force_hash():
    print(f"start brute-force to find hash start with {target_hash} ....")
    i = 0
    while True:
        input_data = str(i).encode()     # 2^24 possibilites for bytes/ 16^6 possibilites for hex  
        current_hash = hashlib.sha256(input_data).hexdigest()  
        if current_hash.startswith(target_hash):
            print(f"🎯 Found collision for input: {i} -> Hash: {current_hash}")
            return input_data.hex().encode()  
            
            
        i += 1

 
hex_val = brute_force_hash()

 
io.sendlineafter(b"Colliding input? ", hex_val)

 
print(io.recvall().decode())
