"""
# Objective:
Prove control over the Root CA by generating a new valid User Certificate, 
signing it using the provided Root Private Key (d), and sending both to the server.
Once verified, decrypt the captured ciphertext using the newly generated User Private Key to read the flag.

# Methodology:
1. Parse the provided Base64 encoded Root Certificate to extract the Root Modulus (n).
2. Generate a fresh, valid 1024-bit RSA key pair for the User (to satisfy the server's key size constraint: 512 < n < 1024).
3. Construct the user certificate JSON payload with fields: "name": "user", "key": {"e": ..., "n": ...}, "signer": "root".
4. Compute the SHA256 hash of the user certificate data.
5. Create the digital signature by signing the hash with the Root Private Key components (d, n) using RSA: S = M^d mod n.
6. Crucially use "little-endian" byte-order for converting the hash to integer and the signature to bytes, matching the server's implementation.
7. Send the Base64 encoded user certificate and signature to the server to trigger the flag generation.
8. Capture the encrypted ciphertext, and perform RSA decryption using the User Private Key (d, n) to recover the flag.

# Lessons & Mistakes:
1. Endianness Matters: Unlike standard cryptographic protocols that default to "big-endian" (Network Byte Order), 
        this challenge explicitly used "little-endian" for RSA operations. Failing to check the source code (`int.from_bytes(..., "little")`) would lead to bad signatures.
2. Key Size Restraints: Standard RSA uses 2048 or 4096 bits, but the server explicitly rejected n values larger than 2**1024. Generating a standard 2048-bit key causes an immediate crash.
3. Strict JSON Serialization: Any unexpected whitespaces or reordering of keys in the JSON string changes its SHA256 hash completely. Using `json.dumps()` precisely as the server expects is vital for signature verification.
4. Asymmetric Dual-Role: Understood how certificates work in PKI—the User's public key goes inside the certificate data, but the certificate itself must be signed by the CA's private key.


"""



import base64
import json
from pwn import *
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

# ==========================================
# 1. START CHALLENGE AND FETCH DATA
# ==========================================
# Start the challenge process directly from its path
p = process("/challenge/run")

# Read the Root Private Key (d) from the terminal
p.recvuntil(b"root key d: ")
root_d_hex = p.recvline().strip().decode()
root_d = int(root_d_hex, 16)

# Read the Base64 encoded Root Certificate
p.recvuntil(b"root certificate (b64): ")
root_cert_b64 = p.recvline().strip().decode()

# Read the Root Certificate Signature (recved to clear the buffer)
p.recvuntil(b"root certificate signature (b64): ")
root_cert_sig_b64 = p.recvline().strip().decode()

log.info("Successfully fetched Root CA data!")

# ==========================================
# 2. EXTRACT MODULUS AND GENERATE USER KEY
# ==========================================
# Decode the Root Certificate to extract the Modulus (n)
root_cert_data = json.loads(base64.b64decode(root_cert_b64).decode())
root_n = root_cert_data["key"]["n"]

# Generate a new RSA key pair for the user (1024-bit to satisfy server constraints)
log.info("Generating a 1024-bit RSA key pair for the user...")
user_key = RSA.generate(1024)

# ==========================================
# 3. CONSTRUCT AND SIGN USER CERTIFICATE
# ==========================================
# Build the certificate dictionary matching the exact format expected by the server
user_certificate = {
    "name": "user",
    "key": {
        "e": user_key.e,
        "n": user_key.n
    },
    "signer": "root"
}
# Serialize the certificate to a compact JSON string (bytes)
user_certificate_data = json.dumps(user_certificate).encode()

# Compute the SHA256 hash of the certificate data
user_certificate_hash = SHA256.new(user_certificate_data).digest()

# Perform RSA signing (S = M^d mod n) using little-endian byte order
hash_int = int.from_bytes(user_certificate_hash, "little")
signature_int = pow(hash_int, root_d, root_n)
user_certificate_signature = signature_int.to_bytes(256, "little")

# ==========================================
# 4. SEND PAYLOADS TO SERVER
# ==========================================
# Base64 encode the payloads for transmission
user_cert_send = base64.b64encode(user_certificate_data)
user_sign_send = base64.b64encode(user_certificate_signature)

# Send the data automatically when prompted by the server
p.sendlineafter(b"user certificate (b64): ", user_cert_send)
p.sendlineafter(b"user certificate signature (b64): ", user_sign_send)

# ==========================================
# 5. RECEIVE CIPHERTEXT AND DECRYPT THE FLAG
# ==========================================
# Receive all remaining output containing the flag's ciphertext
output = p.recvall().decode()
print("\n=== Challenge Server Output ===")
print(output)

# Parse the output to find the secret ciphertext and decrypt it
for line in output.split('\n'):
    if "secret ciphertext (b64):" in line:
        # Extract and Base64 decode the ciphertext bytes
        ciphertext_b64 = line.split("secret ciphertext (b64): ")[1].strip()
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
        
        # Convert ciphertext bytes to an integer (little-endian)
        c = int.from_bytes(ciphertext_bytes, "little")
        
        # RSA Decryption using User Private Key: M = C^d mod n
        m = pow(c, user_key.d, user_key.n)
        
        # Convert back to bytes and strip any null padding bytes
        flag_decrypted = m.to_bytes(256, "little").strip(b'\x00')
        
        print("=" * 40)
        print(f"🏁 FLAG FOUND: {flag_decrypted.decode(errors='ignore')}")
        print("=" * 40)
