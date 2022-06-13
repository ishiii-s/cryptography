# Author: Ishi Sood
import string
import random
import math


#Caeser Cipher
# Arguments: string, integer
# Returns: string
def encrypt_caesar(plaintext, offset):
    #List of encrypted/shifted letters
    newText = []
    for i in plaintext:
        newText.append(shift_letter(i, offset))
    return "".join(newText)

#Arguments: string, string
#Returns: string
def shift_letter(letter, offset):
    alphabet = string.ascii_uppercase

    #check for non-alphabet characters
    if(alphabet.find(letter) < 0):
        return letter
    else:  
        newIndex = (alphabet.find(letter) + offset)
        if newIndex > 25:
            newIndex -= 26
        return alphabet[newIndex]

#Arguments: string, string
#Returns: string
def shift_letter_back(letter, offset):
    alphabet = string.ascii_uppercase

    #check for non-alphabet characters
    if(alphabet.find(letter) < 0):
        return letter
    else:   
        newIndex = (alphabet.find(letter) - offset)
        if newIndex < 0:
            newIndex += 26 
        return alphabet[newIndex]

# Arguments: string, integer
# Returns: string
def decrypt_caesar(ciphertext, offset):
    newText = []
    for i in ciphertext:
        newText.append(shift_letter_back(i, offset))
    return "".join(newText)

#Arguments: string, string
#Returns: string (new ltter after caesar shift)
def get_letter_index(textChar, keyChar):
    alphabet = string.ascii_uppercase
    newIndex = alphabet.find(textChar) + alphabet.find(keyChar)
    #check for valid index
    if newIndex > 25:
        newIndex -= 26
    return alphabet[newIndex] 

#Arguments: string, string
#Returns: string (original character before caesar shift)
def get_ogletter_index(cipherChar, keyChar):
    alphabet = string.ascii_uppercase
    ogIndex = alphabet.find(cipherChar) - alphabet.find(keyChar)
    #check for valid index
    if ogIndex < 0:
        ogIndex = 26 + ogIndex
    return alphabet[ogIndex] 


# Vigenere Cipher
# Arguments: string, string
# Returns: string (encrypted w/ vigenere cipher)
def encrypt_vigenere(plaintext, keyword):
    newText = []
    for x in range(len(plaintext)):
        keyLetter = keyword[x % len(keyword)]
        newText.append(get_letter_index(plaintext[x], keyLetter))
    return "".join(newText)


# Arguments: string, string
# Returns: string (decrypted w/ vigenere cipher)
def decrypt_vigenere(ciphertext, keyword):
    newText = []
    for x in range(len(ciphertext)):
        keyLetter = keyword[x % len(keyword)]
        newText.append(get_ogletter_index(ciphertext[x], keyLetter))
    return "".join(newText)

#Arguments: int
#Returns: tuple (ascii value represented in bits)
def byte_to_bits(int_byte):
    tuple_bits = ()
    bit = int_byte
    for x in range(8):
        tuple_bits = (bit % 2,) + tuple_bits
        bit = bit // 2
    return tuple_bits


# Merkle-Hellman Knapsack Cryptosystem
# Arguments: integer
# Returns: tuple (W, Q, R) - W a length-n tuple of integers, Q and R both integers
def generate_private_key(n=8):
    W = (1)
    for x in range(n):
        total = sum(list(W))
        W += random.randint(total + 1, 2 * total)
    total = sum(list(W))
    q = random.randint(total + 1, 2 * total)
    privKey = (W, q, find_R(q))
    return privKey

#Arguments: integer
#Returns: integer (r for public key)
def find_R(q):
    r = random.randint(2, q - 1)
    while math.gcd(r, q) != 1:
        r = random.randint(2, q - 1)
    return r


# Arguments: tuple (W, Q, R) - W a length-n tuple of integers, Q and R both integers
# Returns: B - a length-n tuple of integers
def create_public_key(private_key):
    B = ()
    W = private_key[0]
    q = private_key[1]
    r = private_key[2]
    for x in range(8):
        B.append(((r * W[x]) % q))
    return B

#Arguments: string, tuple
#Returns: int (single encrypted char)
def compute_c_value(char, public_key):
    c = 0;
    #convert char into bits and binary 
    m = byte_to_bits(ord(char))
    #mi*bi
    for x in range(8):
        c += m[x] * public_key[x]
    return c

# Arguments: string, tuple B
# Returns: list of integers (ie encrypted plaintext chars)
def encrypt_mhkc(plaintext, public_key):
    ciphertext = []
    for x in plaintext:
        ciphertext.append((compute_c_value(x, public_key)))
    return ciphertext

#Arguments: int, int, int
#Returns: int (cPrime for math for decryption)
def get_c_prime(r, q, c):
    rPrime = modInverse(r, q)
    cPrime = c * rPrime % q
    return cPrime

#Arguments: int, int
#Returns: int (value S)
def modInverse(a, m): 
    #original argument m
    mOG = m 
    y = 0
    x = 1
    if (m == 1) : 
        return 0
    while (a > 1) : 
        # q is quotient a / m (w/ integer division)
        q = a // m 
        t = m 
        # m is remainder now (Euclid's algorithm)
        m = a % m
        a = t
        t = y
        # Update x and y
        y = x - q * y
        x = t
    # Make x positive
    if (x < 0) :
        x = x + mOG
    return x

#Arguments: tuple, int
#Return: list of indices from tuple W
def get_indices(W, cPrime):
    indices = []
    i = 7;
    #subset problem 
    while i >= 0:
        if cPrime >= W[i]:
            cPrime -= W[i]
            indices.append(i + 1)
        i = i -1
    return indices

#Arguments: list
#Return: int (ascii value of char)
def compute_ascii(indices):
    asciiValue = 0
    for x in indices:
        asciiValue += 2 ** (8 - x)
    return asciiValue

# Arguments: list of integers, private key (W, Q, R) with W a tuple.
# Returns: bytearray or str of plaintext
def decrypt_mhkc(ciphertext, private_key):
    message = []
    W = private_key[0]
    Q = private_key[1]
    R = private_key[2]

    for x in ciphertext:
        cPrime = get_c_prime(R, Q, x)
        indices = get_indices(W, cPrime)
        asciiValue = compute_ascii(indices)
        message.append(chr(asciiValue))
    return "".join(message)


def main():
    #print(encrypt_caesar("NUM83R5",3))
    #print(decrypt_caesar("QXP83U5", 3))
    #print(encrypt_vigenere("A","ONEINPUT"))
    #print(decrypt_vigenere("LXFOPVEFRNHR", "LEMON"))
    #print(encrypt_mhkc("FOREACHEPSILONGREATERTHANDELTA", (50, 70, 175, 575, 1240, 3385, 7065, 7978)))
    #x = decrypt_mhkc([10520, 19738, 7710, 11433, 8048, 15113, 1310, 11433, 645, 15688, 9288, 4695, 19738, 11760, 18498, 7710, 11433, 8048, 4030, 11433, 7710, 4030, 1310, 8048, 11760, 3455, 11433, 4695, 4030, 8048], ((10, 14, 35, 115, 248, 677, 1413, 3644), 10242, 5))
    #print(x)
    pass
    
if __name__ == '__main__':
    main()
