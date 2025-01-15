"""
Author: Arijit Majumdar
Computer Security
Proof of Concept
"""

import os
import hashlib as h
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes #AES
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC #pbkdf
from cryptography.hazmat.primitives import hashes #sha254 for pbkdf

##############################
## Proof Of Concept Program ##
##############################
# Targets:
## Setup
# 1. get a secret from user
# 2. get a password from user
#
# 3. generate a key from the password using a key-deriv funct
# 4. hash the password (for storage) using a hashing funct
# 5. encrypt the secret (for storage) using a cipher algo
# - make sure neither the key, nor secret, are stored
#
## unlock loop
# 6. get new password from user
# 7. hash new password
# 8. compare new hash to old hash
# 9. if the same, decrypt the secret using same cipher




def encrypt(data,cipher):
    # encrypt data using passed cipher
    e = cipher.encryptor()
    return e.update(data)+e.finalize()
    

def decrypt(data,cipher):
    # decrypt data using passed cipher
    d = cipher.decryptor()
    return d.update(data)+d.finalize()
    

def genKey(password,kdf): 
    # generate key from password using passed kdf
    return kdf.derive(password) # generate key from password

def barray(data):
    return bytearray(data,'utf-8')


def main():
    # instructions and prompts
    print("Instructions:\nFollow the prompts by entering strings.\n")
    secret = str(input("Enter a secret: "))
    pw = str(input("Enter password (note, password cannot be '0'): "))
    print()

    secret = barray(secret) # convert inputs to byte arrays
    pw = barray(pw)

    #customizable values
    keysize = 24    # 24B = 192b key
    kdfiter = 210000    # iterations recommended here: 
                        # https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2

    #random generations
    salt = os.urandom(32)   # random 32char string as salt
    iv = os.urandom(16)     # random 16char as init vector for AES

    print(f"salt fresh: {salt}")
    print(f"iv fresh:{iv}")

    # set up hash function and encryption cipher objects
    kdf = PBKDF2HMAC( hashes.SHA256() , keysize , salt , kdfiter ) #init kdf class
    cipher = Cipher( algorithms.AES(genKey(pw , kdf)) , modes.CTR(iv) ) #init cipher algorithm

    # encrypt data and hash the password for storage
    # only want to store encrypted/hashed values, so replace the variable's original values
    # operated in one-line for "atomic" transaction
    secret , pw = encrypt(secret,cipher) , h.sha512(pw+salt)
    
    print("hexes")
    print(f"     Secret: {secret.hex()}")
    print(f"       salt: {salt.hex()}")
    print(f"init vector: {iv.hex()}")
    print(f"    pw hash: {pw.digest().hex()}")

    print('\nbytes')
    print(f"     Secret: {secret}")
    print(f"       salt: {salt}")
    print(f"init vector: {iv}")
    print(f"    pw hash: {pw.digest()}")
    
    locked = True

    print("\nUnlock:")
    print("To exit, enter '0'. Otherwise, try passwords to unlock the secret.")
    newpassword = ''
    while locked and newpassword!='0': #loop until unlocked
        newpassword = str(input("To unlock secret, enter password: "))

        #hash new password with same salt, compare digests
        newhash = h.sha512(barray(newpassword)+salt) 
        if newhash.digest() == pw.digest():
            locked = False
        elif newpassword!='0':
            print("Wrong password\n")

    if newpassword == '0':
        print("exiting")
    else:
        print(f'\nSecret: {{ {decrypt(secret,cipher).decode()} }}')
    print()
    return


if __name__ == "__main__":
    main()

