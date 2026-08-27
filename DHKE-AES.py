"""
#Objective: create key to exchange then this key will decrypt the flag

#Methodology: 
    1- it allows you to enter B so enter the same value of p ,to when key will calc it be 0  p^23 mod p 
    2- after known the key=0 use it but with byte *16 b"\x00" *16 
    


#Lesson&Mistakes: 
    1- convert from hex to int with int(hex-value, 16)
    2- don't forget to use the iv in decryption
    3- decrpt first then go to unpad
"""
#POC


from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

io = process("/challenge/run")

io.recvuntil(b"p = ")
p_hex = io.recvline().strip().decode()
p = int(p_hex, 16)

io.sendlineafter(b"B? ", p_hex.encode())

io.recvuntil(b"Flag Ciphertext (hex): ")
ciphertext_hex = io.recvline().strip().decode()
full_data = bytes.fromhex(ciphertext_hex)

key = b'\x00' * 16 # in source it take s.to_bytes and take the first 16 [:16]
iv = full_data[:16]
actual_ciphertext = full_data[16:]

cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
decrypted = cipher.decrypt(actual_ciphertext)
flag = unpad(decrypted, cipher.block_size)

success(f"Flag found: {flag.decode()}")
