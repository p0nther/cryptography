"""
#Objective:
    The objective is to perform a CBC Bit-Flipping Attack by manipulating the IV to force the server to decrypt the ciphertext into "flag!" instead of "sleep".

#Methodology:
    take hex_data then convert it to bytes all data is 32 bytes
    cut this data to iv, ciphertext with 16 bytes for each one
    do cipher for it wiht iv
    plain=decrypt ciphertext then do unpad
    if plain =flag : win


    c1 = encrypt(p1 ^ iv)
    decrypt(c1) = p1 ^ iv
    p1 =decrypt(c1) ^ iv
    b'sleep' =decrypt(c1) ^ old_iv
    old_iv = b'sleep' ^ decrypt(c1)

    i have 2 equastion 
    equastion 1 --> decrypt(c1)=old_iv ^ b'sleep'
    i wanna change to flag ---> decrypt(c1)=new_iv ^ b'flag'
    but i can't know the value of decrypt(c1) so let's compensate it from equastion 1
    old_iv ^ b'sleep'= new_iv ^ b'flag'

    new_iv = old_iv ^ b'sleep' ^ b'flag'
    
#Lesson&Mistakes:
    1- (b'\x0b' * 11) not \0xb python read it all after 0 as string it sprate 
    
    

"""
#POC

from Crypto.Util.strxor import strxor
from pwn import *

 
context.log_level = 'error'

def dispatcher():
    p = process("/challenge/dispatcher")
    p.recvuntil(b"TASK: ")
    line = p.recvline().strip().decode()
    p.close()
    return line
    
def worker(value):
    p = process("/challenge/worker")
    p.sendline(f"TASK: {value}".encode())
    
 
    p.recvuntil(b"Victory! Your flag:\n")
    flag = p.recvline().strip().decode()
    p.close()
    return flag

 
cipher_hex = dispatcher()

 
iv_hex = cipher_hex[:32]        
c1_hex = cipher_hex[32:]        

 
old_iv = bytes.fromhex(iv_hex)
c1     = bytes.fromhex(c1_hex)

 
full_sleep = b'sleep' + (b'\x0b' * 11)    
full_flag  = b'flag!' + (b'\x0b' * 11)    

 
result1 = strxor(old_iv, full_sleep)
new_iv  = strxor(result1, full_flag)

 
new_task_hex = (new_iv + c1).hex()

 
flag = worker(new_task_hex)
print(f"[+] Dynamic Victory! Flag is: {flag}")
