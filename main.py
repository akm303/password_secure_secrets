"""
Author: Arijit Majumdar
Secure Storage
- user writes a message to be secured by a password
- message is only decrypted with the correct password

requires installation of hashlib and cryptography modules
`$ pip install hashlib`
`$ pip install cryptography`
"""

import os
import hashlib as h
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes #AES
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC #pbkdf
from cryptography.hazmat.primitives import hashes #sha254 for pbkdf

########################################
##          Helper Functions          ##
########################################

# cryptography functions
def encrypt(data,cipher):
    """encrypt data using passed cipher"""
    e = cipher.encryptor()
    return e.update(data)+e.finalize()
    
def decrypt(data,cipher):
    """decrypt data using passed cipher"""
    d = cipher.decryptor()
    return d.update(data)+d.finalize()
    
def genKey(password,kdf): 
    """generate key from password using passed kdf"""
    return kdf.derive(password) # generate key from password


# conversion functions
def barray(data):
    """convert string or list into array of bytes"""
    return bytearray(data,'utf-8')


# I/O functions
def userin(prompt,exitChar):
    """ take user input, check if it matches 
    the character used as an exit condition.
    returns either the input or an exit flag

    note: 
    entering either the exit character
    or an empty line will trigger the exit 
    conditions since '' evaluates to False 
    in python conditional statements
    """
    i = str(input(f"{prompt}: "))
    if i == exitChar:
        print("exiting: ",end='')
        return False
    return i            

def printHeader(prompt):
    """simple header printing function"""
    print('\n' + '*'*(len(prompt)+6))
    print(f":: {prompt} ::")
    print('*'*(len(prompt)+6))



############################################
##              Main Procedure            ##
############################################
def main():
    ## setup / static values / function
    #config values
    cipherfile = f'cipher.txt' #file where ciphers will be stored
    keysize = 24        # 24B = 192b key
    kdfiter = 210000

    # File I/O functions
    def readFromfile(cf=cipherfile):
        """ reads ciphers from file and returns a list of encrypted data
        tries opening a file and seperating its contents by line, then 
        by ':'delimiter
        otherwise, creates a new file to hold cipher information and 
        appends the premade secrets

        Each line of the cipher file is formatted as follows:
        <salt> : <nonce> : <encrypted secret> : <password hash>
        """
        if not os.path.exists(cf):
            with open(cf,'w') as f:
                #known secret : password = "password123" (without quotes)
                f.write('e755681ee2f50569adb4abdfadb3c8fb2b5557be31d9191a788bbc3f0ef0e0f7:4344fd149558ca7ddf48665ea5748176:02799d2a986fd194dd2bd93304bd4177ec475363a6:8b05110a9b5a8c400a115ad3a0da503d1aa38e003f5a44b9d216c803332572ee79caf5d80d51a5fa9b2350b93d2810e2773839f2b62b13d1215f84bd01301f5b\n')
                #actual secret
                f.write('062e3dd7a884bc4bf4736990eb5efd045cd3a38a7bec397aa4269df2a3fb3b7e:58217185a98f3fc29e2eec1f2092005f:eadc55df049cd5bcfc7d59589576415237920e00dc87cca3a1f0ae5d17870bd7f25fae14945d789f480c80a9642682e347afa2:167b62dd850f88538651597af9f02baec50e66fff29358cb52d050d2d7b4814d14c6d411ed3d762d877e9568a968a2b11df2041529a19e6cefa8e1ad54a6f98e\n')
        with open(cf,'r') as f:
            lines = [line.replace('\n','').split(':') for line in f] #split by delimiter
            return lines

    def writeTofile(cipher,cf=cipherfile):
        """ append a single cipher to cipher file """
        with open(cf,'a') as f:
            f.write(f"{cipher}\n")
    

    # Operational Procedures
    def newSecret():
        """procedure for creating a new secret
        creates a new encrypted secret, tied to a particular 
        password, salt, and nonce"""

        exit = '0'
        printHeader("Creating New Secret")
        print(f"Follow the prompts by entering strings.")
        print(f"To return to main menu at any time, enter {exit}\n")
        
        # get user inputs. exit if necessary
        secret = userin("Enter a secret",exit)
        if not secret: #see userin() definition for additional note
            print("secret not created")
            return
        pw = userin("Enter password",exit)
        if not pw:
            print("secret not created")
            return

        print("\nencrypting...",end='\r')
        # convert inputs (secret,password) to byte arrays
        # and generate randomized byte strings to initialize
        # cryptographic objects
        secret = barray(secret)
        pw = barray(pw)
        salt = os.urandom(32)   # randomized 32B string as salt for password
        nonce = os.urandom(16)  # randomized 16B string as nonce for AES

        # set up hash function and encryption cipher objects
        kdf = PBKDF2HMAC(hashes.SHA256(),keysize,salt,kdfiter)        #init kdf class
        cipher = Cipher(algorithms.AES(genKey(pw,kdf)),modes.CTR(nonce)) #init cipher algorithm

        # encrypt data and hash the password for storage
        # only want to store encrypted/hashed values, so replace the variable's original values
        # operated in one-line for what i hope is a not-necessarily-atomic-but-quick transaction
        # (the goal is to have the unecrypted values in memory for as short a time as possible)
        secret,pw = encrypt(secret,cipher),h.sha512(pw+salt)
        print("secret has been encrypted")

        print("saving secret...",end='\r')
        toWrite = f"{salt.hex()}:{nonce.hex()}:{secret.hex()}:{pw.digest().hex()}"
        writeTofile(toWrite) #write hexes to the file
        print("secret has been saved\n")
        return 
    

    
    def unlockSecret():
        stramt = 10 #change amount of cipher data to be visible
        # procedure for unlocking a prior secret
        exit = '0'
        # read and display all secrets currently in the cipher file
        ciphers = readFromfile()
        printHeader(f"Select a secret, or enter {exit} to exit")
        for i,c in enumerate(ciphers):
            print(f"{i+1}: [{c[0][:stramt]}...{c[0][-stramt:]}]")

        # select a secret to try and decode
        selection = '' #default selection
        while not selection in [str(i) for i in range(len(ciphers)+1)]:
            print(f"\nEnter number in range (1 to {len(ciphers)}), or {exit} to exit")
            selection = userin("Selection",exit)
            if not selection: #see userin() definition for additional note
                print("no secret unlocked")
                return
        
        cipherline = ciphers[int(selection)-1] #cipher selected
        salt,nonce,secret = [bytes(bytearray.fromhex(term)) for term in cipherline[:3]] #split line by delimiter
        pwhash = cipherline[3]

        # print(f"  salt: {salt}")        #debug
        # print(f"    nonce: {nonce}")          #debug
        # print(f"secret: {secret}")      #debug
        # print(f"pwhash: {pwhash}\n")    #debug


        # set up hash function using associated salt. This will be used with
        # the user input to generate a key, hash, and compare to the og key hash
        kdf = PBKDF2HMAC(hashes.SHA256(),keysize,salt,kdfiter)

        locked = True
        while locked: #loop until unlocked
            #user tries inputting passwords until its either correct or they want to exit
            newpassword = userin("Enter password",exit)
            if not newpassword:
                print("no secret unlocked")
                return

            #hash new password with same salt, compare digests
            newhash = h.sha512(barray(newpassword)+salt)

            # print(f"old #: {pwhash[:stramt]}...{pwhash[-stramt:]}") #debug
            # print(f"new #: {newhash.digest().hex()[:stramt]}...{newhash.digest().hex()[-stramt:]}") #debug
            if newhash.digest().hex() == pwhash: #need to verify hashes are the same
                locked = False #unlock
            elif newpassword!='0':
                print("Wrong password\n")

        cipher = Cipher(algorithms.AES(genKey(barray(newpassword),kdf)),modes.CTR(nonce)) #init cipher algorithm with new password, same nonce
        print(f'\nSecret: {{ {decrypt(secret,cipher).decode()} }}\n')
        return


    # main UI procedure
    readFromfile() #confirm cipher file exists, or create it
    selection = True
    while selection:
        mainMenu = ["Exit",("Lock a new secret",newSecret),("Unlock a secret",unlockSecret),]
        # print main menu
        printHeader("  Main Menu  ")
        for i,item in enumerate(mainMenu[1:]): 
            print(f"{i+1}: {item[0]}")    #print each menu item
        print(f"0: {mainMenu[0]}")        #print exit condition

        selection = userin("\nTo select an item, enter a number",'0')
        if selection:  #see userin() definition for additional note about exit conditions
            try:
                mainMenu[int(selection)][1]()
            except ValueError:
                print("invalid selection")

    print("ending program\n")



if __name__ == "__main__":
    main()


