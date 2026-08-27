"""
#Objective: you have key and cipher_flag , wanna plain_flag

#Methedology: convert key,flag to bytes then create cipher object to tell python how to process decryption/encryption data with specific mode like(ECB,CBC,...)
    then the final thing decrypt the flag with cipher.decrypt() 
    
#Lesson&Mistakes: 
    1)how ECB works ---> it's encrypt each block individual then collect them to gether 'encrypt all block with the same key'

"""
#POC

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


key_hex = "b5f0a5063250b4 ebae69b"
flag_hex ="995bd747d97778047 4fd1ef38c8627ab39be49ae3e77ef33d7483f8173b3f6e386bfba386d8c0d0831053aa2"

key= bytes.fromhex(key_hex)
flag= bytes.fromhex(flag_hex)

cipher = AES.new(key=key, mode=AES.MODE_ECB)

decrypted_flag=cipher.decrypt(flag)

print(decrypted_flag.decode())
