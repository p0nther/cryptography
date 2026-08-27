"""
#Objective: padding oracle attack

#Methodology: 

    i wanna found p1(original)
    b'flag{flgsflsglfssg}\x04\x04\x04\x04'
    because the unpad work in the value of p1 --> unpad(p1)

    p1 = decrypt(c1) ^ iv 
    change last byte in iv to 0x01
    p1 =i1 ^ iv(new)[last-byte-changed]

    - p1(new)[last-byte-changed] = i1 ^ iv(new)

    if last-byte in p1 "padding" not right padding like if i wanna 3 and the padding in p1 is 0x09 i show an error if not, 
    that mean i have the right padding for plaintext found this what server tell it to me  i have right pading i p1(modified)[last-byte]

    now my work i take the value of p1(modified)[last-byte] and also i know the iv(modified)[last-byte] 
    - i wanna I1 --> I1[last-byte] = p1(modified)[last-byte] XOR  iv(modified)[last-byte] 
    so now i have I1 , 
    - i can found p1(original)[last-byte]= I1[last-byte] ^ iv(original)[last-byte]
________________________________
Ciphertext:  [  C1   ] [  C2   ] [  C3   ]
                 ↓          ↓          ↓
             Decrypt    Decrypt    Decrypt
             with Key   with Key   with Key
                 ↓          ↓          ↓
             [  D1   ] [  D2   ] [  D3   ]  ← Intermediate values
                 ↓          ↓          ↓
             XOR with   XOR with   XOR with
               IV         C1         C2
                 ↓          ↓          ↓
Plaintext:   [Block 1] [Block 2] [Block 3]
__________________________________

#Lesson&Mistakes:
    1- unpad(p1) if the last padding worng i show an error 
    2- if my block is full 16 and don't need any byte the CBC create new block 16 all it contain 0x10 mean 16in hex
"""
#POC 


from pwn import *

BLOCK = 16

# ==========================================
# Start worker
# ==========================================

worker = process("/challenge/worker")

# skip:
# The password is XX bytes long!
worker.recvline()


# ==========================================
# Get encrypted password
# ==========================================

dispatcher = process(["/challenge/dispatcher", "pw"])

line = dispatcher.recvline().decode()

cipher_hex = line.strip().split("TASK: ")[1]

cipher = bytes.fromhex(cipher_hex)

print(f"[+] Ciphertext: {cipher_hex}")



# ==========================================
# Split blocks
# ==========================================

original_iv = cipher[:16]

c1 = cipher[16:32]



# ==========================================
# Oracle
# ==========================================

def oracle(payload):

    worker.sendline(
        b"TASK: " + payload.hex().encode()
    )

    response = worker.recvline()

    if b"Error" in response:
        return False

    return True



# ==========================================
# Padding Oracle Attack
# ==========================================

intermediate = bytearray(BLOCK)

plaintext = bytearray(BLOCK)

fake_iv = bytearray(BLOCK)



for pad_value in range(1, BLOCK + 1):

    index = BLOCK - pad_value


    # fix old bytes
    for j in range(BLOCK - 1, index, -1):

        fake_iv[j] = (
            intermediate[j]
            ^ pad_value
        )


    for guess in range(256):

        fake_iv[index] = guess

        payload = bytes(fake_iv) + c1


        if oracle(payload):

            # avoid false positive
            if pad_value == 1:

                fake_iv2 = bytearray(fake_iv)

                fake_iv2[index - 1] ^= 1

                payload2 = bytes(fake_iv2) + c1

                if not oracle(payload2):
                    continue


            # recover intermediate
            intermediate[index] = (
                guess ^ pad_value
            )

            # recover plaintext
            plaintext[index] = (
                intermediate[index]
                ^ original_iv[index]
            )

            print(
                f"[+] Found byte: "
                f"{bytes([plaintext[index]])}"
            )

            break



print("\n[+] Raw plaintext:")
print(plaintext)



# ==========================================
# Remove PKCS7 padding
# ==========================================

padding_len = plaintext[-1]

password = plaintext[:-padding_len]

password = password.decode()

print(f"\n[+] PASSWORD: {password}")



# ==========================================
# Redeem flag
# ==========================================

redeem = process("/challenge/redeem")

redeem.sendlineafter(
    b"Password? ",
    password.encode()
)

print("\n[+] FLAG:\n")

print(
    redeem.recvall().decode()
)
