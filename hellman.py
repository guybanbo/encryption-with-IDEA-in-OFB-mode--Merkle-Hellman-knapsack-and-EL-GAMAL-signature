# -*- coding: utf-8 -*-
"""
Created on Mon Feb 26 18:05:44 2024

@author: USER
"""

import sys
import random
import math
 
def generate_coprime_pair(wSum):
    # Generate random integers for q and r
    q = random.randint(wSum+1, wSum+1000)  # You can adjust the range as needed
    r = random.randint(2, wSum+1000)
 
    # Ensure that q and r are coprime
    while math.gcd(q, r) != 1:
        r = random.randint(2, wSum+1000)  # You can adjust the range as needed
 
    return q, r

 
# Function to generate a super-increasing sequence for the public key
def generate_super_increasing_sequence(n):
    sequence = [random.randint(1, 100)]
    while len(sequence) < n:
        next_element = sum(sequence) + random.randint(1, 10)
        sequence.append(next_element)
    return sequence
 
# Function to generate the private key from the public key- to remove
#def generate_private_key(public_key, q, r):
   # private_key = [(r * element) % q for element in public_key]
  #  return private_key

def generate_public_key(W, q, r):#ADDED
    public_key = [(r * element) % q for element in W]
    return public_key

def generate_private_key(n):#ADDED
    sequence=generate_super_increasing_sequence(n)
    q,r=generate_coprime_pair(sum(sequence))
    return sequence,q,r
# Function to encrypt the plaintext using the public key
def knapsack_encrypt(plaintext, public_key):
    encrypted_message = sum(public_key[i] for i in range(len(plaintext)) if plaintext[i] == '1')
    return encrypted_message
 
# Function to decrypt the ciphertext using the private key
def knapsack_decrypt(ciphertext, private_key, q,r):# 
    r_inverse = pow(r, -1, q)  # Modular multiplicative inverse of r
    decrypted_message = ''
    cSum=(ciphertext * r_inverse) % q
    for element in reversed(private_key):
        temp=(ciphertext * r_inverse) % q
        if cSum >= element:
            decrypted_message = '1' + decrypted_message
            cSum -= element
        else:
            decrypted_message = '0' + decrypted_message
    return decrypted_message

def generate_keys(n):
    W,q,r= generate_private_key(n)
    public_key=generate_public_key(W, q, r)
    return [W,q,r],public_key 
 