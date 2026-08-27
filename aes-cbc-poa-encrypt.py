"""
================================================================================
TITLE: Padding Oracle Attack (CBC Encryption via Decryption Oracle)
================================================================================

# Objective:
  Force a decryption-only server (/challenge/worker) to encrypt an arbitrary 
  chosen plaintext message ("please give me the flag...") without knowing 
  the secret AES key.

# Cryptographic Mechanics (Inside the Server):
  When the server decrypts a block of ciphertext (C), it processes it through 
  the Block Cipher Decryption algorithm using the secret key. 
  
  Inputs: [Key, Ciphertext (C)] ---> Output: [Intermediate State (I)]
  
  * Note: The Intermediate State (I) is a hidden value inside memory. 
    Because AES decryption takes two arguments (Key and C), every unique 
    ciphertext block we forge will generate a completely unique and new "I" value.

  After generating "I", the server performs the final XOR operation:
  Plaintext (P) = I ^ IV

# Methodology (The Bottom-Up Attack):
  Since we cannot predict "I" directly, we guess it byte-by-byte from right 
  to left (indices 15 down to 0) using a forged Ciphertext block (C) and a 
  brute-forced Mock IV.

  1. Send a random ciphertext block (C) and keep it fixed. This freezes the 
     value of "I" inside the server's memory.
  2. Brute-force the last byte of the Mock IV (from 0x00 to 0xFF).
  3. When the server accepts the input without throwing a "Padding Error", 
     it means the resulting plaintext byte equals the valid padding value (0x01).
     
     Mathematical proof when successful:
     0x01 = I[byte] ^ Mock_IV[byte]
     
  4. Deduce the secret Intermediate byte (I):
     I[byte] = Mock_IV[byte] ^ 0x01

  5. Once the full 16-byte "I" block is recovered, calculate the actual 
     valid Ciphertext/IV required for our target new message (P_new):
     C_prev (or IV_final) = P_new ^ I

# Lessons & Mistakes:
  1. Never confuse "I" (Intermediate) with "P" (Plaintext). The Oracle cracks 
     the hidden "I" state first, then we use "I" to forge our target "P".
  2. Each new forged message/block requires generating a new unique "I" 
     because changing the input "C" alters the block cipher decryption output.
  3. Beware of False Positives on byte 15; always verify that a padding match 
     is genuinely 0x01 by corrupting the adjacent byte (byte 14).

================================================================================

                                HOW ATTACK WORK 
================================================================================
TITLE: Padding Oracle Attack - Zero Valid Inputs & Server Internal Logic
================================================================================

# Objective:
  Force a decryption-only server (/challenge/worker) to execute specific hidden 
  commands (like "sleep" or the flag request string) starting with ZERO valid 
  inputs (no original ciphertext, no dispatcher).

# Cryptographic Mechanics (The "Why it works" part):
  1. We forge a completely random 16-byte Ciphertext block: C1 = b"A" * 16.
  2. When the server decrypts C1 with the secret key, it generates a stable, 
     fixed Intermediate State (I1) inside memory.
  3. We brute-force the Mock IV byte-by-byte from right to left (15 down to 0).
  4. When the padding error is resolved, we deduce the hidden Intermediate block:
     I1[byte] = Mock_IV[byte] ^ Padding_Value
  5. The Core Magic Trick: We do NOT change I1. Instead, we use the recovered I1 
     to craft a custom, forged IV that manipulates the final XOR outcome:
     IV_crafted = I1 ^ Target_Plaintext (e.g., padded "sleep")

# What Happens Inside the Server After Sending the Forged Payload?
  Payload Sent: [IV_crafted] + [C1]
  
  Step 1 (Block Decryption): Server takes C1, decrypts it, and produces the 
                             exact same hidden I1 block we leaked.
  Step 2 (The Final XOR):    Server XORs I1 with our IV_crafted:
                             Plaintext = I1 ^ IV_crafted
                             Plaintext = I1 ^ (I1 ^ Target_Plaintext)
                             Plaintext = Target_Plaintext (The I1 cancels out!)
  Step 3 (Unpadding):        The server's unpad() function automatically strips 
                             the PKCS#7 padding bytes from the end of the block.
  Step 4 (Command Execution):The clean string (e.g., "sleep" or the flag request) 
                             is passed to the if/elif conditions. The server 
                             matches the command and triggers the victory output.

# Lessons & Mistakes:
  1. We never change the Intermediate State (I) of our random block; we exploit 
     our knowledge of it to mold the IV like clay via XOR properties.
  2. The target plaintext MUST be properly padded (e.g., "sleep" + 11 bytes of \x0b) 
     before performing the XOR with I1 so that lengths match perfectly.
  3. This attack completely breaks the system: If you can control the IV and 
     have a Padding Oracle, you can encrypt ANY message without knowing the key.
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
