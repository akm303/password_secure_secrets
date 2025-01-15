# HW3 Q3
---
Author: Ari-jit Majumdar
---
### Requirements:
Program is written in python 3.9.6 <br>
User will need to have installed the `cryptography` module and `hashlib` module.

(i.e. `pip install cryptography`, `pip install hashlib`)
- cryptography: https://cryptography.io/en/latest/
- hashlib: https://docs.python.org/3/library/hashlib.html


---
## Table of Contents:
1. **Main Instructions**
2. **Documentation and Notes**
3. **Security Justification**


---
## Main Instructions:
1. Open the terminal/cmd and navigate to the directory containing `main.py`
2. Run `main.py` using the command: `python main.py`
3. Follow the prompts on screen (for more details and specifics, see "***Documentation and Notes***" below)

<br>

## For quickly running the premade secrets:
1. Run `main.py`
2. Enter "2" to unlock a secret 
3. Select "1" to unlock secret 1 (this has a known password)
    - Enter "password123" to see the secret
4. Select "2" to unlock secret 2 (I'm not telling you this password)
    - Good luck, i made it very easy
---
<br>
<br>
<br>
<br>



---
# Documentation and Notes

- I will be refering to Bytes with a capital 'B', and bits with a lowercase 'b' (i.e. 16b = 16 bits)


###  First Run
- The first time user runs `main.py` will generate a file, `cipher.txt` which will contain two preset default secrets.
- Each run of `main.py` checks if `cipher.txt` exists. If it does not, `cipher.txt` will be generated with the default secrets. Therefore, resetting the list is as simple as deleting `cipher.txt`
- Any new secrets will be added to the end of `cipher.txt`


---
### Navigating Menus
- User will be prompted with menus of what they can do via terminal
- To make a selection, user will enter the corresponding number
- To to go back or exit program, user can enter '0', or simply enter nothing


---
### Creating a New Secret (Encrypting and Storing)
#### *UI:*
- Selecting this option, the user will be prompted to enter two strings: a `secret` and a `password`
- The `secret` and `password` can be anything other than a '0' or empty string, (which will always return the user to the main menu)

#### *Operation:*
1. The program generates a randomized `32B salt` and a randomized `16B nonce`
2. `pbkdf2` algorithm  (supplied by the `cryptography` module) is configured with the following attributes to generate a `192b key` based on the user-entered `password`:
    - the randomized `32B salt`
    - a `SHA256` hashing function, 
    - number of iterations = 210,000 (Recommendation from source (1))
3. `AES Cipher` (supplied by the `cryptography` module) is configured with the following attributes:
    - the `pbkdf2` generated `192b key` (this is an `AES-192` implementation)
    - `CTR` mode enabled, using the randomized `16B nonce`
4. The `secret` is encrypted with the cipher and replacees the unencrypted value in `secret`. Note that `secret` is now a `ciphertext`.
5. Simultaneously, the `password` is salted and hashed (using the `hashlib` module's `sha512` function) and replaces the unsalted, unhashed value in `password`.
    * *note*:<br> 
    *Steps 4 & 5 are ideally done atomically, but im not certain python or its underlying C does so. My goal is to minimize the number of instructions during which unencrypted data is exposed in memory. I don't actually know if python does this operation atomically, therefore it may be vulnerable to attack*
6. The following are appended to the last line of `cipher.txt` in the following schema:
<br><t> `<salt>:<nonce>:<ciphertext>:<hashed password>`
<br>


---
### Unlocking a Secret (Decrypting from Storage)
#### *UI:*
- Selecting this option, the user will be offered a list of `secrets` that they can attempt to unlock by entering the correct password
- The user will select a `secret` by number, to which they will be prompted for the appropriate password
- Entering a `password` as a '0' or empty string, will return the user to the main menu
- Otherwise, a user can attempt passwords indefinitely

#### *Operation:*
1. ciphers are read from `cipher.txt`, split by line. Each `cipher line` is further split by delimeter to seperate terms stored in the following schema:
<br><t> `<salt>:<nonce>:<ciphertext>:<hashed password>`

2. Portions of the encoded secrets are listed for the user to select
3. User enters a number for the secret they would like to unlock. The 
4. `pbkdf2` algorithm (supplied by the `cryptography` module) is configured with the following attributes to generate a `192b key` based on a user-entered `password`:
    - the cipher line's `salt` (still 32B)
    - a `SHA256` hashing function, 
    - number of iterations = 210,000 (Recommendation from source (1))
    
    *note:* this is the same configuration as the `pbkdf2` algorithm used to `Create a New Secret` (see above)
5. User enters a loop to enter `passwords`. 
    - i. Each `password` is salted with the cipher line's `salt`, and hashed (using the `hashlib` module's `sha512` function)
    - ii. The `password hash` is compared to the cipher line's `hash`
    - iii. *if the hashes don't match*, the loop continues indifinitely until the user enters an exit condition or guesses correctly
    - nonce. *otherwise, the hashes matched* and the `secret` is *unlocked*.
6. `AES Cipher` (supplied by the `cryptography` module) is reconstructed with the following attributes:
    - a `192b key` generated using the matched `password`
    - `CTR` mode enabled, using the cipher line's `nonce`

    *note:* this is the same configuration as the `AES Cipher` used to `Create a New Secret` (see above)
7. The `secret` is decrypted, and displayed on the terminal.

    *note:* secret is not stored anywhere once decrypted, nor is it removed from the `ciphers.txt` file. User can (and would need to) re-decrypt to see a secret again.
---
<br>

---


Sources:

(1) https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2

(2) https://cryptography.io/en/latest/

(3) https://docs.python.org/3/library/hashlib.html
