# AES-ECB (Electronic Codebook) — Complete Notes

## What is AES?

AES (**Advanced Encryption Standard**) is a symmetric encryption algorithm.

Symmetric means:

* The same key is used for encryption.
* The same key is used for decryption.

Example:

```text
Plaintext
    │
    ▼
AES + Secret Key
    │
    ▼
Ciphertext
```

To recover the original data:

```text
Ciphertext
    │
    ▼
AES + Same Secret Key
    │
    ▼
Plaintext
```

AES is widely used in:

* HTTPS
* VPNs
* Wi-Fi security
* Encrypted databases
* Password managers

---

# AES Block Cipher Basics

AES is a **block cipher**.

It does not encrypt an entire file at once.

Instead it processes data in fixed-size blocks.

AES block size:

```text
16 bytes
128 bits
```

Example:

```text
HELLO_WORLD_1234
```

Length:

```text
16 bytes
```

AES encrypts it as one block.

If the data is larger:

```text
HELLO_WORLD_1234AAAA_BBBB_CCCC
```

AES splits it:

```text
Block 1
HELLO_WORLD_1234

Block 2
AAAA_BBBB_CCCC...
```

Each block is then encrypted.

---

# Why Encryption Modes Exist

AES only knows how to encrypt a single block.

When we have multiple blocks we need a strategy.

This strategy is called:

```text
Mode of Operation
```

Examples:

* ECB
* CBC
* CTR
* GCM

Each mode handles blocks differently.

---

# What is ECB?

ECB stands for:

**Electronic Codebook**

It is the simplest AES mode.

Process:

```text
Block 1 ── AES(Key) ──► Cipher Block 1

Block 2 ── AES(Key) ──► Cipher Block 2

Block 3 ── AES(Key) ──► Cipher Block 3
```

Each block is encrypted independently.

No block affects another block.

---

# ECB Encryption Formula

For every plaintext block:

```text
Ciphertext = AES(Key, Plaintext)
```

Example:

```text
P1 → AES(Key) → C1
P2 → AES(Key) → C2
P3 → AES(Key) → C3
```

No randomness.

No IV.

No chaining.

---

# The Biggest ECB Problem

Because ECB is deterministic:

```text
Same Plaintext
+
Same Key
=
Same Ciphertext
```

Example:

```text
AES(KEY, "AAAAAAAAAAAAAAAA")
```

Always produces:

```text
8f3c...
```

If encrypted again:

```text
AES(KEY, "AAAAAAAAAAAAAAAA")
```

Result:

```text
8f3c...
```

Exactly the same ciphertext.

---

# Visualizing The Problem

Imagine four identical blocks:

```text
AAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAA
```

ECB encryption:

```text
AAAAAAAAAAAAAAAA → X
AAAAAAAAAAAAAAAA → X
AAAAAAAAAAAAAAAA → X
AAAAAAAAAAAAAAAA → X
```

Ciphertext:

```text
X
X
X
X
```

An attacker immediately knows:

```text
All plaintext blocks were identical
```

Even without knowing the key.

---

# ECB Leaks Patterns

Suppose a database stores user roles.

```text
admin
admin
admin
guest
guest
guest
```

After ECB encryption:

```text
A1
A1
A1
B2
B2
B2
```

The attacker cannot decrypt the values.

However the attacker learns:

```text
Rows 1-3 are identical

Rows 4-6 are identical
```

Information leakage already occurred.

---

# The Famous Penguin Example

The most famous ECB demonstration uses an image.

Original image:

```text
████████████
████████████
████████████
```

Many image regions contain identical data.

ECB encrypts identical blocks identically.

Result:

```text
Encrypted image still reveals shape
```

Even though colors become unreadable.

The overall structure remains visible.

This demonstrates that ECB leaks patterns.

---

# Why Developers Accidentally Use ECB

Many crypto libraries provide ECB because:

* It is simple
* It is easy to implement
* It is useful for teaching

Example:

```python
AES.new(key, AES.MODE_ECB)
```

Developers often choose it because it works.

Unfortunately:

```text
Working
≠
Secure
```

---

# ECB in Web Security

ECB frequently appears in:

* CTF challenges
* Crypto labs
* Legacy applications
* Homegrown encryption systems

A common vulnerable design:

```text
user_input + secret
```

then:

```text
AES-ECB encrypt
```

and return ciphertext.

This often leads to:

```text
Byte-at-a-time attacks
```

---

# Why Byte-at-a-Time Attacks Work

Because ECB encrypts blocks independently.

If we can control part of a block:

```text
AAAAAAAAAAAAAAA?
```

and the application appends:

```text
SECRET
```

we can force unknown bytes into predictable positions.

Then compare ciphertext blocks.

Because:

```text
Same plaintext block
=
Same ciphertext block
```

we can recover secret data one byte at a time.

---

# Detecting ECB

A common detection method:

1. Send repetitive input.
2. Look for repeated ciphertext blocks.

Example plaintext:

```text
AAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAA
```

Ciphertext:

```text
4f2d8a...
4f2d8a...
4f2d8a...
4f2d8a...
```

Repeated blocks strongly indicate ECB.

---

# Manual ECB Detection

Split ciphertext into:

```text
16-byte chunks
```

Example:

```text
ABCD
EFGH
ABCD
EFGH
```

If blocks repeat:

```text
ABCD
ABCD
```

ECB is likely being used.

---

# Typical CTF Methodology

## 1. Determine Block Size

Send:

```text
A
AA
AAA
AAAA
```

Observe ciphertext length.

When ciphertext grows:

```text
Block size discovered
```

Usually:

```text
16 bytes
```

---

## 2. Confirm ECB

Send:

```text
A * 64
```

Example:

```text
AAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAA
```

Repeated ciphertext blocks:

```text
BLOCK1
BLOCK1
BLOCK1
BLOCK1
```

ECB confirmed.

---

## 3. Align Secret Data

Control plaintext until:

```text
Known bytes + Secret Byte
```

occupy one block.

---

## 4. Build Dictionary

Generate:

```text
AAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAB
AAAAAAAAAAAAAAAC
...
```

Encrypt all possibilities.

Store:

```text
Ciphertext Block
→
Candidate Byte
```

---

## 5. Recover Secret

Compare target block against dictionary.

Matching ciphertext reveals:

```text
Unknown byte
```

Repeat until entire secret is recovered.

---

# Why CBC Is Better

CBC introduces chaining.

Instead of:

```text
P1 → AES → C1
P2 → AES → C2
```

CBC uses:

```text
P1 XOR IV → AES → C1

P2 XOR C1 → AES → C2
```

Now identical plaintext blocks produce:

```text
Different ciphertext blocks
```

because previous blocks influence encryption.

---

# Modern Alternatives

Today developers should prefer:

## GCM

```text
AES-GCM
```

Provides:

* Encryption
* Integrity
* Authentication

---

## ChaCha20-Poly1305

Provides:

* Encryption
* Integrity
* High performance

Especially useful on mobile devices.

---

# Vulnerable Python Example

```python
from Crypto.Cipher import AES

cipher = AES.new(key, AES.MODE_ECB)

ciphertext = cipher.encrypt(data)
```

Problem:

```text
ECB leaks plaintext patterns.
```

---

# Secure Python Example

```python
from Crypto.Cipher import AES

cipher = AES.new(key, AES.MODE_GCM)

ciphertext, tag = cipher.encrypt_and_digest(data)
```

Benefits:

```text
Confidentiality
+
Integrity
+
Authentication
```

---

# Real-World Impact

ECB can lead to:

## Pattern Leakage

```text
Repeated data remains visible
```

---

## Sensitive Data Discovery

Attackers may identify:

```text
Repeated records
Repeated fields
Repeated roles
Repeated secrets
```

---

## Oracle Attacks

In some applications:

```text
Attacker Input
        +
Application Secret
        +
AES-ECB
```

can enable:

```text
Byte-at-a-time secret recovery
```

---

# Quick Summary

AES:

* Symmetric encryption algorithm.
* Encrypts data in 16-byte blocks.

ECB:

* Simplest AES mode.
* Encrypts blocks independently.

Problem:

```text
Same Plaintext
+
Same Key
=
Same Ciphertext
```

This leaks patterns.

Detection:

* Look for repeated ciphertext blocks.

Common Exploitation:

* ECB oracle attacks.
* Byte-at-a-time secret recovery.

Defenses:

* Avoid ECB for sensitive data.
* Use AES-GCM or ChaCha20-Poly1305.
* Introduce randomness and authenticated encryption.
