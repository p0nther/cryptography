"""
how server work 'challenge'

/challenge/dspatcher take one arg if it pw it send to you a password but it give you ciphertext.hex else it send sleep as cihpertext.hex

______
send it to /challenge/worker to decrypt it and see if it pw it tell you correct go to /challeng/redeem if it sleep program will sleep
here it will decrypt the cihper so i can do 2 attacks (edit the plaintext without known the cipher,  know D1 and then know the plaintext)
decrypt(c1)=p1 ^ iv

if i wanna p1=decrypt(c1) ^ iv
but how it work decrypt(c1) with key then give D1 then do D1 ^ iv that gives my p1
p1= D1 ^ iv 
so now it will do XOR byte byte until go to the last byte ,here my work will start i will change the last byte but why ?
if i change the last-byte , when unpad() func work on p1 after changing it make error it last byte not represent how many filed it padding
but if no error so that mean i put the original byte'padding'  we do all that to own 2 var in the equation to find the real D1 NOte: D1 not changing all the time,
so now we have p`1 ,iv` and from that  i can find the original D1 
after find the original D1 use it to find the original p1
p1=D1 ^ iv
__________________
/challenge/redeem  compare the plaintext pw you'll send with file /challenge/.pw if they the same send the flag


---------------------------------------------

i have this cipher TASK: 36dc1d60010db50aecb90 3efd614416fa0665f3e4577dbfa32d9e6b582345acbbcfe03c10a13302
a="36dc1d60010db50aecb909c54a15d5fb16068a3efd6 577dbfa32d9e6b582345acbbcfe03c10a13302"
 a_hex="36dc1d60010db50aecb909c54a15d5fb 0665f3e4577dbfa32d9e6b582345acbbcfe03c10a13302"
 a=bytes.fromhex(a_hex)
 
b'6\xdc\x1d`\x01\r\xb5\n\xec\xb9\t\xc5J\x15\xd5\xfb' | a[16:] 
 print(f"IV: {a[:16]} |C1: {a[16:32]} |C2: {a[32:]} ")
IV: b'6\xdc\x1d`\x01\r\xb5\n\xec\xb9\t\xc5J\x15\xd5\xfb' |C1: b'\x16\x06\x8a>\xfdaD\x16\xfa\x06e\xf3\xe4W}\xbf' |C2: b'\xa3-\x9ekX#E\xac\xbb\xcf\xe0<\x10\xa13\x02' 
  print(f"IV: {a[:16]} \n|C1: {a[16:32]} \n|C2: {a[32:]} ")
IV: b'6\xdc\x1d`\x01\r\xb5\n\xec\xb9\t\xc5J\x15\xd5\xfb' 
|C1: b'\x16\x06\x8a>\xfdaD\x16\xfa\x06e\xf3\xe4W}\xbf' 
|C2: b'\xa3-\x9ekX#E\xac\xbb\xcf\xe0<\x10\xa13\x02' 
 



"""
#POC 



from pwn import *

context.log_level = 'error'

p_disp = process(['/challenge/dispatcher', 'pw'])
disp_output = p_disp.recvall().decode('utf-8', errors='ignore')
p_disp.close()

task_line = [line for line in disp_output.split('\n') if "TASK: " in line][0]
task_hex = task_line.split()[1]

task_bytes = bytes.fromhex(task_hex)
iv_original = task_bytes[:16]
c1 = task_bytes[16:32]

p_work = process(['/challenge/worker'])
p_work.recvline()

def check_padding(iv_mod, ciphertext_block):
    payload = f"TASK: {(iv_mod + ciphertext_block).hex()}\n"
    p_work.sendline(payload.encode())
    output = p_work.recvline().decode('utf-8', errors='ignore')
    if "error" in output.lower() or "padding" in output.lower():
        return False
    return True

d1_extracted = [0] * 16
p1_extracted = [0] * 16

print("[*] Performing Padding Oracle Attack on live cipher...")

for byte_idx in range(15, -1, -1):
    padding_val = 16 - byte_idx
    base_iv = bytearray(16)
    for i in range(byte_idx + 1, 16):
        base_iv[i] = d1_extracted[i] ^ padding_val
        
    found = False
    for candidate in range(256):
        base_iv[byte_idx] = candidate
        
        if check_padding(bytes(base_iv), c1):
            d1_extracted[byte_idx] = candidate ^ padding_val
            p1_extracted[byte_idx] = d1_extracted[byte_idx] ^ iv_original[byte_idx]
            
            char = chr(p1_extracted[byte_idx]) if 32 <= p1_extracted[byte_idx] <= 126 else '?'
            print(f"[+] Byte {byte_idx:02d} | Found: {char}")
            found = True
            break
            
    if not found:
        print(f"[-] Failed at byte {byte_idx}")
        p_work.close()
        exit(1)

p_work.close()

from Crypto.Util.Padding import unpad
try:
    final_pw = unpad(bytes(p1_extracted), 16).decode('latin1')
except Exception:
    final_pw = bytes(p1_extracted).decode('latin1', errors='ignore').strip()

print(f"\n[+] Extracted Password: {final_pw}")
print("[*] Submitting to /challenge/redeem...")

p_red = process(['/challenge/redeem'])
p_red.recvuntil(b"Password? ")
p_red.sendline(final_pw.encode())
flag_output = p_red.recvall().decode('utf-8', errors='ignore')
p_red.close()

print("\n" + flag_output)
