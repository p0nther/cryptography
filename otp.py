"""

#Objective: you have ciphertext,key find the flag


#Methedology: decode them from hex to bytes do strxor.decode()



#Lesson&Mistakes: what is the diff between print VS return in python 
Fun fact: the One-time Pad is the only cryptosystem that humanity has been able to prove is perfectly secure.
If you securely transfer the key, and you only use it for one message, 
it cannot be cracked even by attackers with infinite computational power! We have not been able to make this proof for any other cryptosystem

but if you use it more that one time i can break it :
is the right k=c1^p1
k=c2^p2

c2^p2=c1^p1 --->  c1^c2=p1^p2

"""
from Crypto.Util.strxor import strxor

def solve(otp,flag):
        otp=bytes.fromhex(otp)
        flag=bytes.fromhex(flag)

        return strxor(otp,flag).decode()

print(solve('4c0d44a3b8d8367a0ee35aff62a2a112fc4d5dc6a b8ff04d388c9a 2acfd1700a8183d61b2344','3c7a2a8ddbb75a166b843f 1615162c2ece533da083aa457e9a734b0f284dba 801a44f8c6ac4c5e4e'))
