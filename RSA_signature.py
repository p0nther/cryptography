"""

# Objective: Blind Signature for any message (RSA)

# Methodology:
1. Convert the message/command (M) to an integer.
2. Choose a random blinding factor (X) where gcd(X, n) = 1.
3. Blind the message: Calculate Y = (M * X^e) mod n  [where e is the public exponent].
4. Send Y to the server to get it signed: S1 = Y^d mod n.
5. Calculate the modular inverse of X: S2 = X^-1 mod n.
6. Unblind the signature: Multiply S1 * S2 mod n.
   -> (M * X^e)^d * X^-1 
   -> M^d * X * X^-1 = M^d mod n (The valid signature of M).
   
"""
#POC
import subprocess
from base64 import b64encode, b64decode

 
n = int(open("/challenge/key-n").read(), 16)
e = int(open("/challenge/key-e").read(), 16)
M_bytes = b"flag"

 
M = int.from_bytes(M_bytes, "little")

# 2. Blinding Factor
X = 2

# 3. : Y = (M * X^e) % n
Y = (M * pow(X, e, n)) % n
Y_bytes = Y.to_bytes(256, "little")
Y_b64 = b64encode(Y_bytes)

 
print("[+] Sending blinded message to dispatcher...")
res = subprocess.run(["/challenge/dispatcher", Y_b64], capture_output=True, text=True)

 
s1_b64 = res.stdout.strip().split("Signed command (b64): ")[1]
S1 = int.from_bytes(b64decode(s1_b64), "little")

# 5. Unblinding: ضرب التوقيع في المعكوس الضربي لـ X
X_inv = pow(X, -1, n)
S_final = (S1 * X_inv) % n

 
final_signature_b64 = b64encode(S_final.to_bytes(256, "little")).decode()
print(f"[+] Final Signature (b64): {final_signature_b64}")

 
print("[+] Sending final signature to worker:")
subprocess.run(["/challenge/worker", final_signature_b64])
