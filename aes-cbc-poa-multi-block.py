"""

TASK: ggg14abf7ec00e4f73198d3ed32eggggg2bcde5a66cf9be33134baa276ggg949e0e86e2a27fcb8bce920cf27e3dfd8c4360bggg7613d1c05da0d43c7035548d33e5953d61fd3f537761aef450d62a82d



a = "gggg4abf7ec00e4fhhhd3ed32egggg b2bcde5hhhcf9be33134baa276480949 e0e86e2a2hhhb8bce920cf27e3dfd8c4..."

    └──────────────┬───────────────┘ └──────────────┬───────────────┘ └──────────────┬───────────────┘
                   │                                │                                │
                   ▼                                ▼                                ▼
              Original IV                       C1 Block                         C2 Block
              (16 Bytes)                       (16 Bytes)                       (16 Bytes)
                   │                                │
                   └─────────── XOR ──────────────┐ │ (Decrypt with Key inside server)
                                                  ▼ ▼
                                            [ Yields P1 ] <─── (This is the hidden D1!)






[ Original IV ]          [ C1 Block ]             [ C2 Block ]
    (16 Bytes)              (16 Bytes)               (16 Bytes)
        │                       │   │                    │   │
        │                       │   └─ Decrypt (Key)     │   └─ Decrypt (Key)
        │                       │            │           │            │
        └───────── XOR ─────────┼──────────┐ │           └──────────┐ │
                                │          ▼ ▼                      ▼ ▼
                                │    [ Yields P1 ]            [ Yields P2 ]
                                │    (Flag Part 1)            (Flag Part 2)
                                │          ▲                        ▲
                                └──────────┘                        │
                                  (Acts as IV for next block) ──────┘

c1= encrypt(p1 ^ iv)
decrypt(c1)=p1 ^iv
p1=D1 ^ iv

"""
#POC 

from pwn import *

p = process("/challenge/worker")

BLOCK = 16


# get ciphertext
d = process(["/challenge/dispatcher","flag"])
cipher = bytes.fromhex(
    d.recvline().decode().split("TASK: ")[1]
)

blocks = [
    cipher[i:i+16]
    for i in range(0, len(cipher), 16)
]


# oracle
def ok(payload):

    p.sendline(
        b"TASK: " + payload.hex().encode()
    )

    return b"Error" not in p.recvline()



flag = b""


# decrypt block by block
for b in range(1, len(blocks)):

    prev = blocks[b-1]
    cur  = blocks[b]

    I  = bytearray(16)
    P  = bytearray(16)

    fake = bytearray(prev)


    for pad in range(1,17):

        idx = 16-pad


        # fix old bytes
        for j in range(15, idx, -1):

            fake[j] = I[j] ^ pad


        # brute-force
        for g in range(256):

            fake[idx] = g

            if ok(bytes(fake)+cur):

                I[idx] = g ^ pad

                P[idx] = I[idx] ^ prev[idx]

                print(bytes([P[idx]]))

                break


    flag += P


# remove padding
pad = flag[-1]

print("\nFLAG:")
print(flag[:-pad].decode())
