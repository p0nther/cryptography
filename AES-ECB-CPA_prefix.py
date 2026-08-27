"""
#Objective: you can't control char by char , you have block and can add pad before flag liek "A"+flag

#Methedology: 
    'A'*15 + loop_char if that == 'A'*15+flag then you found the block
    chosen_1:
    Data? 'a'*15 + p
    Result: 461542c883 2 bf12d7b7026c49
    
    chosen_2: data + flag
    Data? 'a'*15
    Result: 461542c88338521f8fbf12d7b7026c49 91b4b8621dc4 35b2bf5c449665b297787380be969500a15 d4e34333a6b0d7d6f1aa66ab1c46f3e4d919477b

    finally block_chosen_1 =blcok_1 

#Lesson&Mistakes:     
    1- add this after recvuntil ---> return p.recvline().strip().decode()

"""
#POC



from pwn import *

p = process('/challenge/run')


def encrypt_pt(data):
    p.sendlineafter(b'Choice? ', b'1')
    p.sendlineafter(b'Data? ', data.encode())

    p.recvuntil(b'Result: ')
    return p.recvline().strip().decode()


def prepend_flag(data):
    p.sendlineafter(b'Choice? ', b'2')
    p.sendlineafter(b'Data? ', data.encode())

    p.recvuntil(b'Result: ')
    return p.recvline().strip().decode()


BLOCK_SIZE = 16

charset = [chr(i) for i in range(32, 127)]

known = ""

while True:

    pad_len = BLOCK_SIZE - 1 - (len(known) % BLOCK_SIZE)

    pad = "A" * pad_len

    block_index = len(known) // BLOCK_SIZE

    target = prepend_flag(pad)

    start = block_index * 32
    end = start + 32

    target_block = target[start:end]

    found = False

    for c in charset:

        crafted = pad + known + c

        attempt = encrypt_pt(crafted)

        attempt_block = attempt[start:end]

        if attempt_block == target_block:

            known += c

            print(f"[+] {known}")

            found = True

            if known.endswith('}'):
                print(f"\nFLAG => {known}")
                p.close()
                exit()

            break

    if not found:
        print("[-] failed")
        break

p.close()
