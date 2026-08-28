 
"""
# Objective:
Perform a simplified Transport Layer Security (TLS) handshake acting as the server.
Establish a secure channel using Diffie-Hellman (DH) key exchange, derive an AES-128 
symmetric key, and use it to securely transmit a Root-signed User Certificate and 
a handshake signature proving ownership of the User Private Key.

# Methodology:
1. Parse the DH parameters (p, g), Root CA private key (d), and Root Certificate from the process.
2. Read the client's requested identity (target_name) and the client's DH public value (A).
3. Generate a secret random exponent (b) and compute the server's DH public value: B = g^b mod p.
4. Compute the shared secret: s = A^b mod p, and derive the 128-bit AES key using SHA256(s)[:16].
5. Initialize AES-CBC encryption and decryption channels using an all-zero IV.
6. Generate a fresh 1024-bit RSA key pair for the target identity.
7. Construct the user certificate JSON and digitally sign its SHA256 hash using the Root Private Key (d, n).
8. Construct the handshake transcript block, hash it, and sign it using the new User Private Key (d, n).
9. Encrypt the user certificate, the certificate signature, and the handshake signature using AES-CBC.
10. Transmit the Base64-encoded encrypted payloads to the client and decrypt the final flag payload.

# ==============================================================================
# HOW THE CHALLENGE WORKS (STEP-BY-STEP CONCEPTUAL BREAKDOWN)
# ==============================================================================

1. THE CRYPTOGRAPHIC TUNNEL (Diffie-Hellman Key Exchange):
   - Before sharing any secrets, we must build a secure, encrypted tunnel so no one can eavesdrop.
   - The Server gives us its public parameters (p, g) and its public key (A).
   - We randomly invent a secret number (b) in our head (script) and compute our public key: B = g^b mod p.
   - We send (B) to the server. Now, both sides perform a mathematical trick to derive the exact same 
     shared secret (s = A^b mod p) without ever revealing their private keys to each other!
   - From this shared secret, we extract a 128-bit symmetric key to lock everything from now on with AES-128.

2. THE IDENTITY CARD (The User Certificate):
   - The tunnel is secure (AES), but the server wants to know WHO is inside the tunnel. It asks for a 
     "User Certificate" for a randomized identity (target_name), signed by the trusted Root CA.
   - We invent a brand-new RSA key pair for this user (User Public/Private Key).
   - We write the target name and the NEW User Public Key (e, n) inside a JSON "identity card".
   - To make it official, we sign this card using the official Root CA Private Key (d, n) provided at the start.
   - We encrypt this certificate with AES and pass it through the tunnel. The server verifies the Root signature 
     and now trusts that the public key inside the card belongs to a legitimate user.

3. PROVING OWNERSHIP (The Handshake Signature):
   - The server trusts the certificate, but it thinks: "What if someone stole a copy of this certificate? 
     Does the person inside the tunnel actually hold the Private Key corresponding to this card?"
   - To clear this doubt, the server challenges us to sign the ongoing handshake history (Name, A, B).
   - We take the handshake data, hash it, and sign it using our NEWLY invented User Private Key (user_key.d).
   - We encrypt it with AES and send it as the 'user signature'.
   - The server decrypts it, pulls the User Public Key from the certificate we sent earlier, and verifies the signature. 
     Now the server is 100% sure we are the legitimate owner of both the Root and the User keys!

4. THE REWARD (Decrypting the Flag):
   - Completely satisfied, the server packages the final reward (The Flag).
   - For maximum security, the server encrypts the Flag using the NEW User Public Key we gave it.
   - It sends the ciphertext over the AES tunnel and closes the connection.
   - Since our script is the only entity in the universe that knows the matching User Private Key (user_key.d), 
     we perform the final RSA decryption (M = C^d mod n), print the Flag, and win the challenge!

# Lessons & Mistakes:
1. Layered Cryptography: This challenge beautifully combines asymmetric encryption (RSA for identity/signing), 
   key exchange (Diffie-Hellman for establishing a secret), and symmetric encryption (AES for fast data transfer).
2. Precise State Tracking: Keeping the encryption and decryption states synchronized is critical since AES-CBC 
   maintains an internal state or requires proper block alignment (padding).
3. Transcript Verification: Handshake signatures (Step 5) must cover the exact sequence of parameters (Name, A, B) 
   in the correct byte order ('little-endian') to prevent man-in-the-middle modifications.
"""

import base64
import json
from pwn import *
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ==========================================
# 1. START PROCESS AND FETCH CA DATA
# ==========================================
p = process("/challenge/run")

# Fetch Diffie-Hellman parameters
p.recvuntil(b"p: ")
dh_p = int(p.recvline().strip().decode(), 16)

p.recvuntil(b"g: ")
dh_g = int(p.recvline().strip().decode(), 16)

# Fetch Root CA key components
p.recvuntil(b"root key d: ")
root_d = int(p.recvline().strip().decode(), 16)

p.recvuntil(b"root certificate (b64): ")
root_cert_b64 = p.recvline().strip().decode()

p.recvuntil(b"root certificate signature (b64): ")
root_cert_sig_b64 = p.recvline().strip().decode()

# Fetch the requested target name and Client Public Key (A)
p.recvuntil(b"name: ")
target_name = p.recvline().strip().decode()

p.recvuntil(b"A: ")
crypto_A = int(p.recvline().strip().decode(), 16)

log.info(f"Target Name to certify: {target_name}")
log.info("Successfully gathered DH parameters and Root CA credentials.")

# Extract the Root Modulus (n) from the certificate
root_cert_data = json.loads(base64.b64decode(root_cert_b64).decode())
root_n = root_cert_data["key"]["n"]

# ==========================================
# 2. DIFFIE-HELLMAN KEY EXCHANGE
# ==========================================
# Generate Server Private Key (b) and Public Key (B)
log.info("Computing Diffie-Hellman key exchange...")
b = random.getrandbits(2048)
crypto_B = pow(dh_g, b, dh_p)

# Calculate Shared Secret (s)
shared_secret = pow(crypto_A, b, dh_p)

# Send Server Public Key (B) to the client
p.sendlineafter(b"B: ", hex(crypto_B).encode())

# ==========================================
# 3. DERIVE CRYPTOGRAPHIC AES KEY
# ==========================================
# Derive the AES-128 key matching the challenge specifications
shared_bytes = shared_secret.to_bytes(256, "little")
aes_key = SHA256.new(shared_bytes).digest()[:16]

# Initialize cipher engines (using all-zero IV as seen in the challenge code)
cipher_encrypt = AES.new(key=aes_key, mode=AES.MODE_CBC, iv=b"\0"*16)
cipher_decrypt = AES.new(key=aes_key, mode=AES.MODE_CBC, iv=b"\0"*16)

def encrypt_payload(data: bytes) -> bytes:
    """Helper to pad, encrypt, and base64 encode data for transmission."""
    encrypted = cipher_encrypt.encrypt(pad(data, cipher_encrypt.block_size))
    return base64.b64encode(encrypted)

# ==========================================
# 4. CONSTRUCT AND SIGN USER CERTIFICATE
# ==========================================
# Generate a fresh 1024-bit RSA key pair for the requested identity
log.info("Generating a 1024-bit RSA key pair for the target identity...")
user_key = RSA.generate(1024)

user_certificate = {
    "name": target_name,
    "key": {
        "e": user_key.e,
        "n": user_key.n
    },
    "signer": "root"
}
user_certificate_data = json.dumps(user_certificate).encode()

# Sign the user certificate data using the Root CA Private Key
user_certificate_hash = SHA256.new(user_certificate_data).digest()
hash_int = int.from_bytes(user_certificate_hash, "little")
signature_int = pow(hash_int, root_d, root_n)
user_certificate_signature = signature_int.to_bytes(256, "little")

# ==========================================
# 5. SIGN THE HANDSHAKE DATA
# ==========================================
# Reconstruct the exact handshake structure expected by the client validation
handshake_data = (
    target_name.encode().ljust(256, b"\0") +
    crypto_A.to_bytes(256, "little") +
    crypto_B.to_bytes(256, "little")
)

# Sign the handshake structure using the newly generated User Private Key
handshake_hash = SHA256.new(handshake_data).digest()
handshake_hash_int = int.from_bytes(handshake_hash, "little")
handshake_sig_int = pow(handshake_hash_int, user_key.d, user_key.n)
user_signature = handshake_sig_int.to_bytes(256, "little")

# ==========================================
# 6. ENCRYPT AND SEND RESPONSES
# ==========================================
log.info("Encrypting and transmitting secure handshake packets...")

enc_user_cert = encrypt_payload(user_certificate_data)
enc_user_cert_sig = encrypt_payload(user_certificate_signature)
enc_user_sig = encrypt_payload(user_signature)

p.sendlineafter(b"user certificate (b64): ", enc_user_cert)
p.sendlineafter(b"user certificate signature (b64): ", enc_user_cert_sig)
p.sendlineafter(b"user signature (b64): ", enc_user_sig)

# ==========================================
# 7. CAPTURE AND DECRYPT THE FLAG
# ==========================================
output = p.recvall().decode()

for line in output.split('\n'):
    if "secret ciphertext (b64):" in line:
        ciphertext_b64 = line.split("secret ciphertext (b64): ")[1].strip()
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
        
        # Decrypt the final encrypted layer transmission
        decrypted_padded = cipher_decrypt.decrypt(ciphertext_bytes)
        flag_bytes = unpad(decrypted_padded, cipher_decrypt.block_size)
        
        print("\n" + "="*50)
        print(f"🏁 FLAG FOUND: {flag_bytes.decode().strip()}")
        print("="*50 + "\n")
