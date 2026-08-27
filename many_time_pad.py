"""
#Objective: you can encrypt any plaintext and you have encrypted flag if you decrypt it you'll win

#Methedology: craft plaintext with the same length 'char'in flag then sent it with hex to challenge to got it but this time encrypted now you have p and c find key and use the key to decrypt the flag

#Lesson&Mistakes: don't forget to present the flag with  decode()


#POC: 
Flag Ciphertext (hex): a3ed9bc96e39aad8d0f963e807f7e812ed304 595bf2b0f7075db805f8470b98a7dbb719bb180b4ceffc7148696f0232bf8df3a
Plaintext (hex): 61616161616161616161616161616161616161 6161616161616161616161616161616161616161616161616161616161616161
Ciphertext (hex): b2fb94866c37a7d5d4ff67f22bd1c73cdf656f3f35337b 9f2736557cc3837bd741f6ba44eb73809d9ba2d6d0df248db9e80730cec351
 
key= p^c

p_hex="747474747474747474747474747474747 7474747474747474747474747474747474747474747474747474747474747474747474"
c_hex="a7ee81937922b2c0c1ea72e73ec4d229ca707a2a20 54e3af51fe6695888eb7c3c5ca3198acfd1225dbd644"

key =strxor()


"""
# poc
from Crypto.Util.strxor import strxor 

c="a3ed9bc96e39aad8d0f963e807f7e812ed304d3f26212d8af3ce f7075db80 98a7dbb719bb180b4ceffc7148696f0232bf8df3a"
#print(bytes.fromhex(c))
#print(f"len= {len(c)/2} character")
#print(f"sent this 60 char plaintext to encrypt: {(b't'*60).hex()}")

print("-"*88)


#key= p^c

p_hex="74747474747474747474747474747474747474 4747474747474747474747474747474747474747474747474"
c_hex="a7ee81937922b2c0c1ea72e73ec4d229ca707a2 9d6966ec254e3af51fe6695888eb7c3c5ca3198acfd1225dbd644"

p=bytes.fromhex(p_hex)
c=bytes.fromhex(c_hex)

key =strxor(p,c)
#print(key)

flag_hex="a3ed9bc96e39aad8d0f963e807f7e812ed304d3f26212d8af3 805f8470b98a7dbb719bb180b4ceffc7148696f0232bf8df3a"
flag=bytes.fromhex(flag_hex)

print(strxor(flag,key).decode())
