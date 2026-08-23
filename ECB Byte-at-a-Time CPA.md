
# Deep-Dive: Byte-at-a-Time ECB Decryption Attack

## 0x01 Overview

Electronic Codebook (ECB) mode is the simplest operational mode for symmetric block ciphers like AES. In ECB mode, the input data is split into fixed-size blocks (16 bytes for AES-128), and each block is encrypted independently using the exact same secret key:

$$C_i = E_K(P_i)$$

Because ECB mode is completely **deterministic** and uses **no Initialization Vector (IV)** or block chaining, identical plaintext blocks always result in identical ciphertext blocks:

$$P_i = P_j \implies C_i = C_j$$

This property breaks Indistinguishability under Chosen-Plaintext Attack (**IND-CPA**) and enables a **Byte-at-a-Time Chosen-Plaintext Attack (CPA)** to recover secret data appended to user-controlled inputs.

---

## 0x02 Threat Model & Prerequisites

This attack applies to modern application architectures (such as web endpoints, APIs, or binary utilities) structured around an encryption oracle where:

1. **User Control:** The attacker can inject arbitrary prefix data $P_{\text{user}}$ into the oracle.
2. **Appended Secret:** The oracle appends a hidden secret string $S$ (such as an API key, session token, or database record) to the user input before encrypting.
3. **ECB Mode:** The oracle encrypts $P_{\text{user}} \mathbin{\Vert} S$ using AES-ECB.
4. **Ciphertext Visibility:** The attacker can observe the resulting ciphertext.

```
+-------------------------------------------------------------+
|                      Encryption Oracle                      |
|                                                             |
|   [ User Input: P_user ] + [ Appended Secret: S ]           |
|                                 │                           |
|                                 ▼                           |
|                    AES-128-ECB Encryption                   |
|                                 │                           |
|                                 ▼                           |
|                     [ Returned Ciphertext ]                 |
+-------------------------------------------------------------+

```

---

## 0x03 Attack Mechanics & Alignment Math

### 1. Identifying ECB Mode & Block Size

First, determine the cipher's block size ($B$) by sending increasing lengths of repeated bytes (e.g., `'A' * N`) to the oracle. When the output length jumps (e.g., from 32 bytes to 48 bytes), the difference represents the block size $B = 16$.

To confirm ECB mode, send at least $2 \times B$ identical bytes (`'A' * 32`). If the ciphertext contains two identical 16-byte blocks ($C_1 = C_2$), ECB mode is confirmed.

---

### 2. The Sliding Window & Single-Byte Isolation

Because each 16-byte block encrypts independently, we can force a single unknown byte of the secret $S$ into the 16th position of a target block by controlling the length of $P_{\text{user}}$.

Let $B = 16$. To recover the first byte $S[0]$:

1. **Craft Padding:** Send $B - 1 = 15$ bytes of known pad data (e.g., `'A' * 15`).
2. **Oracle Block Construction:**

$$\text{Block}_1 = \underbrace{\text{\texttt{"AAAAAAAAAAAAAAA"}}}_{15\text{ bytes}} \mathbin{\Vert} \underbrace{S[0]}_{1\text{ byte}}$$


3. **Capture Target Ciphertext:** Record the ciphertext of $\text{Block}_1$ as $C_{\text{target}}$.

```
Target Block (16 Bytes):
[ A | A | A | A | A | A | A | A | A | A | A | A | A | A | A | S[0] ]
<------------------- 15 Bytes Known -------------------> < 1 Byte >

```

---

### 3. Brute-Forcing the Isolated Byte

Because the attacker knows the first 15 bytes of $\text{Block}_1$, they can construct local candidate blocks for every possible byte value $g \in [0, 255]$:

$$\text{Candidate}_g = \text{\texttt{"AAAAAAAAAAAAAAA"}} \mathbin{\Vert} g$$

Send each candidate block through the oracle and compare its first ciphertext block $C_g$ against $C_{\text{target}}$:

$$\text{If } C_g == C_{\text{target}} \implies S[0] = g$$

---

### 4. Decrypting Subsequent Bytes

To recover $S[1]$, shorten the pad to $B - 2 = 14$ bytes:

$$\text{Block}_1 = \underbrace{\text{\texttt{"AAAAAAAAAAAAAA"}}}_{14\text{ bytes}} \mathbin{\Vert} \underbrace{S[0]}_{\text{Known}} \mathbin{\Vert} \underbrace{S[1]}_{\text{Target}}$$

Because $S[0]$ is now known, only $S[1]$ remains unknown. Repeat the 256-byte brute-force search against the target ciphertext block to recover $S[1]$. Continue this process to decrypt $S$ in its entirety.

---

## 0x04 Proof of Concept (Python 3)

The following PoC demonstrates a fully functional local simulation of the attack using `pycryptodome`:

```python
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class EncryptionOracle:
    def __init__(self):
        # Secret 128-bit key unknown to attacker
        self._key = os.urandom(16)
        # Secret string to recover via CPA
        self._secret = b"FLAG{3cb_d3crypt10n_34sy_cpa}"

    def encrypt(self, user_input: bytes) -> bytes:
        data = pad(user_input + self._secret, 16)
        cipher = AES.new(self._key, AES.MODE_ECB)
        return cipher.encrypt(data)

def solve_ecb_secret(oracle: EncryptionOracle) -> bytes:
    block_size = 16
    recovered_secret = b""
    
    # Determine secret length upper bound
    total_len = len(oracle.encrypt(b""))
    
    for i in range(total_len):
        # Calculate pad length needed to isolate target byte at block end
        pad_len = (block_size - 1 - (i % block_size))
        padding = b"A" * pad_len
        
        # Determine target block index
        target_block_idx = i // block_size
        
        # 1. Get reference ciphertext from oracle
        ct = oracle.encrypt(padding)
        target_block = ct[target_block_idx * block_size : (target_block_idx + 1) * block_size]
        
        # 2. Brute-force byte value (0-255)
        found_byte = False
        for g in range(256):
            guess_byte = bytes([g])
            # Construct dictionary payload: padding + known_bytes + guess
            test_prefix = b"A" * pad_len + recovered_secret + guess_byte
            test_ct = oracle.encrypt(test_prefix)
            test_block = test_ct[target_block_idx * block_size : (target_block_idx + 1) * block_size]
            
            if test_block == target_block:
                recovered_secret += guess_byte
                found_byte = True
                break
                
        if not found_byte:
            # End of string or PKCS#7 padding reached
            break
            
    return recovered_secret

if __name__ == "__main__":
    oracle = EncryptionOracle()
    print("[*] Launching Byte-at-a-Time ECB Decryption Attack...")
    decrypted = solve_ecb_secret(oracle)
    print(f"[+] Recovered Secret: {decrypted.decode('utf-8', errors='ignore')}")

```

---

## 0x05 Mitigations & Defensive Strategy

1. **Deprecate ECB Mode:** Never use AES-ECB for encrypting sensitive or structured data.
2. **Use Authenticated Encryption (AEAD):** Implement cipher modes that offer both confidentiality and integrity, such as **AES-GCM** (Galois/Counter Mode) or **ChaCha20-Poly1305**.
3. **Randomized Initialization Vectors (IVs):** If using standard CBC mode, ensure each encryption operation uses a cryptographically secure, unpredictable 16-byte random IV. This ensures $P_1 = P_2 \implies C_1 \neq C_2$, neutralizing Chosen-Plaintext Attacks.

---
