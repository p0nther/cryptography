"""

what is DHKE: diffie-hellman key exchange --> cryptograhpic protocol that allow 2 parties to securely establish a shared secret over an insecure public channel

How it works : 
    1- Agree on Public Numbers: Alice & Bob agree on a large prime number (P) and base generator (G)
    2- Choose Private Secrets: Alice chooses a secret private number a, and Bob chooses a secret private number b. They keep these strictly to themselves.
    3-Calculate Public Keys: 
        Alice computes her public key: A = G^a (mod p) 
        Bob computes his public key:   B = G^b (mod P)
        
    4- Exchange the public keys [A, B, G, P]
    
    5- calc the secret key 
        Alice --> K=B^a mod p
        Bob   --> K=A^a mod p
        
#Objective:
    in this challenge i enter B,s'secret_key' if secret_key right print flag

#Methodology :
    s=B^a mod p | i know p so what if i enter B as p it will be like s=p^a mod p and that make s=0
    'cause 2^34 mod 2 = 0
    
#Lesson&Mistakes: 
    
    
"""
from pwn import *

p =process("/challenge/run")

p.recvuntil(b"p = ")
prime_p=p.recvline().strip()
p.sendlineafter(b"B? ",prime_p)
p.sendlineafter(b"s? ",b"0")

flag=p.recvall().decode()
print(flag)
