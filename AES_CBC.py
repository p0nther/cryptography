"""
#Objective: you've the key_hex, flag_hex find the flag and learn more about CBC

#Methodology:
    encrypt with CBC mode and don't forget to put iv in decryption , you will found  IV in cipher_text first 16 bytes 
    also don't forget to unpad the flag 'cause its have padding
    
#Lesson&Mistakes: 
    1- don't forget to unpad

"""
#POC 


from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def pwnTool():
    p= process("/challenge/run")
    p.recvuntil(b"AES Key (hex): ")
    key_hex=p.recvline().strip().decode()
    
    p.recvuntil(b"Flag Ciphertext (hex): ")
    flag_hex=p.recvline().strip().decode()
    
    p.close()
    return key_hex, flag_hex
    
Key, Flag=pwnTool()
 
key_hex= Key
flag_hex=Flag


key= bytes.fromhex(key_hex)
flag=bytes.fromhex(flag_hex)


IV=flag[:16]
encrypted_data=flag[16:]


cipher = AES.new(key=key, mode=AES.MODE_CBC,iv=IV)


flag = cipher.decrypt(encrypted_data)
flag = unpad(flag, 16)
print("\n",end="\n")
print(flag.decode())
