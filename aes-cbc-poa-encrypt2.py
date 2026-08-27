"""
================================================================================
TITLE: Padding Oracle Attack - Zero Valid Inputs (No Ciphertext Provided)
================================================================================

# Objective:
  Encrypt our target flag-request message ("please give me the flag...") and 
  bypass authentication, starting with ZERO valid inputs (no original ciphertext, 
  no dispatcher, just us and the /challenge/worker decryption oracle).

# Cryptographic Mechanics (The "Why it works" part):
  In CBC mode, if we provide a completely random 16-byte block as Ciphertext (C), 
  the AES Decryption engine inside the server will still process it using the 
  secret key. 
  
  [Random C] + [Secret Key] ---> Generates a completely valid [Intermediate State (I)]
  
  Even though the resulting Plaintext (P) will be total garbage and trigger a 
  "Padding Error", the hidden "I" value inside the server's memory is now 
  FIXED and STABLE, as long as we don't change our random Ciphertext block.

# Methodology:
  We will execute the exact same Bottom-Up (Reverse) encryption attack, but we 
  generate our own starting point:

  1. Create a fake, completely random final ciphertext block: C_last = b"A" * 16.
  2. Send this C_last to the server, and brute-force the Mock IV byte-by-byte 
     (indices 15 down to 0) to resolve the padding error.
  3. When the server says "Success" (Padding is correct), deduce the hidden "I" byte:
     I[byte] = Mock_IV[byte] ^ 0x01
  4. After recovering the full 16-byte "I" block, forge the legitimate 
     ciphertext block that forces the server to decrypt our target text (P_target):
     C_prev = P_target ^ I
  5. Move to the next block upwards, using C_prev as the new ciphertext block, 
     and repeat until the entire message is encrypted.

# Lessons & Mistakes:
  1. A Decryption Oracle is a total compromise: The presence of a valid original 
     ciphertext is NEVER a prerequisite for a Padding Oracle Attack. 
  2. Random ciphertext behaves exactly like legitimate ciphertext under the hood; 
     it decrypts to a fixed, hidden Intermediate state (I) that can be leaked.
  3. The attack architecture is 100% identical to the previous one; our script 
     doesn't need structural changes, only the starting ciphertext block is ours 
     from the beginning.
================================================================================
"""

import sys
from pwn import process, error

# ==========================================
# 1. تشغيل التحدي والربط بالـ Oracle
# ==========================================
io = process("/challenge/worker")

def padding_oracle(iv: bytes, ciphertext: bytes) -> bool:
    payload = iv + ciphertext
    io.sendline(f"TASK: {payload.hex()}".encode())
    
    response = io.recvline().decode('latin1')
    
    if "Error" in response:
        return False
    return True

# ==========================================
# ديدان مساعدة للـ Blocks والـ Padding
# ==========================================
def split_blocks(data: bytes):
    return [data[i:i+16] for i in range(0, len(data), 16)]

def pad(text: bytes) -> bytes:
    padding_len = 16 - (len(text) % 16)
    return text + bytes([padding_len] * padding_len)

# ==========================================
# 2. إعداد النص المطلوب وتجهيز الهجوم
# ==========================================
plaintext = b"please give me the flag, kind worker process!"
padded_pt = pad(plaintext)
pt_blocks = split_blocks(padded_pt) 

print(f"[*] Target Plaintext: {padded_pt}")
print(f"[*] Total Blocks to encrypt: {len(pt_blocks)}")

c_next = b"A" * 16 
cipher_blocks = [c_next] 

# ==========================================
# 3. المطحنة: التشفير العكسي (Bottom-Up)
# ==========================================
for block_idx in range(len(pt_blocks) - 1, -1, -1):
    print(f"\n[*] Encrypting Block {block_idx + 1}...")
    current_p = pt_blocks[block_idx]
    
    guessed_i = bytearray(16)  
    mock_iv = bytearray(16)    
    
    for byte_idx in range(15, -1, -1):
        padding_val = 16 - byte_idx
        
        for k in range(byte_idx + 1, 16):
            mock_iv[k] = guessed_i[k] ^ padding_val
            
        found = False
        for candidate in range(256):
            mock_iv[byte_idx] = candidate
            
            if padding_oracle(bytes(mock_iv), c_next):
                if byte_idx == 15:
                    mock_iv[14] ^= 1 
                    if not padding_oracle(bytes(mock_iv), c_next):
                        mock_iv[14] ^= 1 
                        continue
                    mock_iv[14] ^= 1 
                
                guessed_i[byte_idx] = candidate ^ padding_val
                print(f"[+] Found Intermediate byte [{byte_idx}]: {hex(guessed_i[byte_idx])}")
                found = True
                break
                
        if not found:
            print(f"[-] Error: Couldn't find valid padding for byte {byte_idx} at block {block_idx + 1}")
            io.close()
            sys.exit(1)
            
    c_prev = bytes([current_p[i] ^ guessed_i[i] for i in range(16)])
    cipher_blocks.insert(0, c_prev)
    c_next = c_prev

# ==========================================
# 4. إرسال الـ Payload النهائي وقنص الفلاج
# ==========================================
final_payload = b"".join(cipher_blocks)
print("\n" + "="*40)
print("[+] Crafting Complete Successfully!")
print(f"[*] Sending Final Payload to worker...")

# إرسال الصندوق السحري النهائي
io.sendline(f"TASK: {final_payload.hex()}".encode())

print("\n[+] Server Response:")
try:
    # بنقرأ سطرين ورا بعض؛ السطر الأول للـ Victory والثاني جواه الفلاج
    print(io.recvline().decode('latin1').strip())
    print(io.recvline().decode('latin1').strip())
except Exception as e:
    print("[-] Failed to read flag response:", e)
print("="*40)

io.close()
