"""
#Objective: do CPA on ECB to get the flag, the server give you encrypted flag[index,lenght] and allow you can encrypt any text you want 


#Methedology:
    1- do codebook for all characters
    2- compare  each index,lenght=1 in flag with this charcter
    3- if the this result of index match with any value in this dictionary print it and add it 
    4- loop until find index end with '}'
 
 
#Lesson&Mistakes: i use AI to wirte this Exploit 
    1- Tries:
        1) encrypt all char one by one then compare them with flag index and lenght  "Done" work from frist try
 
    2- practice more to write your exploit and must wirte small function do one thing no 1 or 2 func do all thing
 
"""
 
#POC    

from pwn import *

p = process("/challenge/run")

def encrypt_char(char):
 
    p.sendlineafter(b"Choice? ", b"1")
    p.sendlineafter(b"Data? ", char.encode())
 
    p.recvuntil(b"Result: ")
    c = p.recvline().strip().decode()
    return c

def build_codebook():
 
    codebook = {}
    for i in range(32, 127):
        char = chr(i)
        cipher = encrypt_char(char)
        codebook[char] = cipher
        print(f"[*] '{char}' => {cipher}")
    return codebook

def get_flag_char(index):
 
    p.sendlineafter(b"Choice? ", b"2")
    p.sendlineafter(b"Index? ", str(index).encode())
    p.sendlineafter(b"Length? ", b"1")
    p.recvuntil(b"Result: ")
    value = p.recvline().strip().decode()
    return value

def decrypt_flag():
    print("[*] build the codebook...")
    codebook = build_codebook()
    reverse_book = {v: k for k, v in codebook.items()}
    
    print("\n[*] Getting flag...")
    flag = ""
    i = 0
    
    while True:
        encrypted_char = get_flag_char(i)
        
        if encrypted_char in reverse_book:
            plain = reverse_book[encrypted_char]
            flag += plain
            print(f"[+] Index {i}: {encrypted_char} => '{plain}'")
            
 
            if plain == '}':
                break
        else:
            print(f"[?] Index {i}: {encrypted_char} => NOT FOUND")
            flag += "?"
        
        i += 1
    
    print(f"\n[+] the Flag: {flag}")
    return flag

 

 
TARGET_BLOCKS = [
    "085f9813 c1438f016f6c2ac35",
    "fa7a1cb9 6ff4358ee594558"
]

if __name__ == "__main__":
 
    decrypt_flag()
    
    p.close()

