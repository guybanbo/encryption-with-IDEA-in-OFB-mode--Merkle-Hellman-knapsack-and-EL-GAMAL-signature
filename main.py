# -*- coding: utf-8 -*-
"""
Created on Thu Feb 29 16:29:57 2024

@author: USER
"""

from idea import IDEA
import hellman
from user import User
import os
import signature as sign

def generate_random_iv():
    # Generate a random 64-bit (8-byte) value
    random_iv = os.urandom(8)
    return random_iv


def int_to_binary_string(number):
    # Convert the integer to its binary representation
    binary = bin(number)

    # Strip the '0b' prefix from the binary string
    binary = binary[2:]

    # Convert each character of the binary string to '0' or '1'
    binary_string = ''.join(['0' if bit == '0' else '1' for bit in binary])

    return binary_string



def pad_binary(binary_string, desired_length):
    padding = '0' * (desired_length - len(binary_string))
    padded_binary_string = padding + binary_string
    return padded_binary_string  


def idea_in_ofb(iv,plain,key):
    
    sub_plain = []
    sub_enc = []
    size = plain.bit_length()
    my_IDEA = IDEA(key)

    # Encryption
    x = size // 64
    if size % 64 != 0:
        x += 1
        size += 64 - size % 64
    for i in range(x):
        shift = size - (i+1) * 64
        sub_plain.append((plain >> shift) & 0xFFFFFFFFFFFFFFFF)
        blockCipherEncryption = my_IDEA.encrypt(iv)
        iv= blockCipherEncryption
        Ecrypted_block = sub_plain[i] ^ blockCipherEncryption
        sub_enc.append(Ecrypted_block)
        
        encrypted = 0
    for i in range(x):
        sub_enc[i] = sub_enc[i] << (x - (i + 1)) * 64
        encrypted = encrypted | sub_enc[i]
        
    
    return encrypted


    
    
        
def merkle_hellman_keyGeneration(user,size):
    user.myPrivateHellman,user.myPublicHellman=hellman.generate_keys(size)
    

def merkle_hellman_publicKeyExchange(alice,bob):
    bob.SenderPublicHellman=alice.myPublicHellman
    alice.SenderPublicHellman=bob.myPublicHellman
    

def elGamal_Signature_publicKeyExchange(alice,bob):
    bob.senderPublicSignKey = alice.myPublicSignKey
    alice.senderPublicSignKey = bob.myPublicSignKey
    

def elGamal_Signature_KeyGen(alice,bob,size):
    alice.myPublicSignKey,alice.privateSignKey = sign.elgamal_keygen(size)
    bob.myPublicSignKey,bob.privateSignKey = sign.elgamal_keygen(size) 

    
def merkle_hellman_encrypt(message,publicKey):
    ideaKeyString = lambda number: '{:b}'.format(number).zfill(number.bit_length())
    ideaKeyBin=ideaKeyString(message) 
    paddedIdeaKey=pad_binary(ideaKeyBin, 128)
    ideaKeyEncrypted=hellman.knapsack_encrypt(paddedIdeaKey, publicKey)
    
    return ideaKeyEncrypted

def merkle_hellman_decrypt(encrypted,w,q,r):
    return hellman.knapsack_decrypt(encrypted,w,q,r)



def send_sms(message,sender,receiver):
    
    print(sender.name+": creating initial vector for idea encryption")
    iv = int.from_bytes(generate_random_iv(), byteorder='big')  # Use 'big' or 'little' depending on your byte order
    print("iv created, iv=",hex(iv),"\n")
    print(sender.name,"encrypting message")
    encrypt_idea = idea_in_ofb(iv,message,sender.ideaKey)
    print("the encrypted message after using idea is: ", hex(encrypt_idea))
    sender.mySign = sign.elgamal_sign(encrypt_idea, sender.privateSignKey,  sender.myPublicSignKey)
    print(sender.name," signing message")
    receiver.senderSign = sender.mySign
    print(sender.name+": sending the message and signature to "+ receiver.name)
    ElGamalVerification = sign.elgamal_verify(encrypt_idea, receiver.senderSign, receiver.senderPublicSignKey)
    print("\n"+receiver.name+" verifying encrypted message")
    print(receiver.name+": message verified\n") if ElGamalVerification else print(receiver.name+": message not verified")
    print(receiver.name,"decrypting message:", hex(encrypt_idea))
    decrypt_idea = idea_in_ofb(iv,encrypt_idea,receiver.ideaKey)
    print( "decrypted message is: ",str(decrypt_idea.to_bytes((decrypt_idea.bit_length() + 7) // 8, 'big'), 'ASCII'))
    print("\n")
      

    
def run(alice,bob):
    while True:
        print("--------------------------------------------------------")
        print("                    Secure SMS Messaging")
        print("--------------------------------------------------------")
        print("1. Send SMS")
        print("2. Exit")
        
        choice = input("Choose an option: ")
        
        if choice == "1":
            receiver=input("Send SMS to (alice/bob): ")
            message = input("Enter a message: ")
            message= int.from_bytes(message.encode("ASCII"), 'big')
            if(receiver=="bob"):
                send_sms(message,alice,bob)
            else:
                send_sms(message,bob,alice)
        elif choice == "2":
            print("Exiting secure SMS messaging app. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.\n")


def main():

    alice= User("Alice","0526666666")
    bob= User("Bob","0526666665")
    
    ## Merkle-Hellman Key Generation ##
    merkle_hellman_keyGeneration(alice,128)
    merkle_hellman_keyGeneration(bob,128)
    
    ## Merkle-Hellman Key Exchange
    merkle_hellman_publicKeyExchange(alice,bob)
    
    ## EL-GAMAL Signature Key Generation
    elGamal_Signature_KeyGen(alice,bob,258)
    
    ## EL-GAMAL Signature Public Key Exchange ##
    elGamal_Signature_publicKeyExchange(alice,bob)
    
    key = 0x6E3272357538782F413F4428472B4B62
    message = input("use default key? (y/n): ")
    if (message=="n"):
        keyChoice = input("Enter a 128 bit key in hex:\t\t")
        print("\n")
        key = int(keyChoice, 16)
    alice.ideaKey = key

    ## Alice encrypt IDEA key with Bob's Public key of Merkle-Hellman
    print("--------------------------------------------------------")
    print("          idea key transfer using hellman starts")
    print("--------------------------------------------------------")
    print("Alice: encrypting idea key", hex(key))
    ideaKeyEncrypted = merkle_hellman_encrypt(key,bob.myPublicHellman)
    print("The encrypted idea key using hellman is: ", hex(ideaKeyEncrypted) )
    ## Bob decrypt the message that contain the IDEA key
    print("Bob: decrypting idea key")
    ideaKeyDecrypted = merkle_hellman_decrypt(ideaKeyEncrypted,bob.myPrivateHellman[0],bob.myPrivateHellman[1], bob.myPrivateHellman[2])
    bob.ideaKey = int(ideaKeyDecrypted,2)
    print("The decrypted key is:", hex(bob.ideaKey))
    run(alice,bob)
    
 
 


if __name__ == '__main__':
    main()