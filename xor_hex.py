from pwn import *

# Start the challenge
io = process('/challenge/run')

for i in range(10):
    # Get the hex values from the terminal output
    io.recvuntil(b"The key: ")
    k = io.recvline().strip()
    
    io.recvuntil(b"Encrypted secret: ")
    s = io.recvline().strip()
    
    # Logic: hex( number ^ number )
    # We use int(variable, 16) because the process reads '0xaf' as a string (text), 
    # and we need to convert that text into a math-ready integer.
    ans = hex(int(k, 16) ^ int(s, 16))
    
    # Send the result back to the challenge
    io.sendlineafter(b"Decrypted secret? ", ans)
    
    print(f"Challenge {i}: Sent {ans}")

# Receive and print the final flag
print(io.recvall().decode())
