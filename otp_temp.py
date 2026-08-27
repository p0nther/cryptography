"""
#Objective:  make plaintext = b"flag!" to get your flag

#Methedology: get the key from /challenge/dispatch and use it to encrypt "flag!" and sent the value after hex() to /challenge/worker

#Lesson&Mistakes: 
1) 10 hex chars
   10 / 2 = 5 bytes

2) // from /challenge/dispatcher
   TASK: 586600e4af
   ciphertext = strxor(b"sleep", key[:5])
   key[:5]= c ^ sleep

3) // from /challenge/worker
    plaintext = strxor(data[:cipher_len], key[:cipher_len]) 
    plaintext = strxor(data[:5], key[:5])  // it'll be 5 char for flag!
    data = flag! ^ key[:5] // we can replace key[:5] with his value form /challenge/dispatch
    data = flag! ^ c ^ sleep
    

"""

from Crypto.Util.strxor import strxor

c=bytes.fromhex('586600e4af')
key= strxor(b'sleep',c)
data=strxor(b'flag!', key)

print(f"data will sent: flag! XOR key ---> \nROW: {data} \nsend it with TASK and Hex: \"TASK: {data.hex()}\"")
