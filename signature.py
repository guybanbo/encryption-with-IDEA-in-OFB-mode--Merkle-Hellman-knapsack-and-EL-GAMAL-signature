# -*- coding: utf-8 -*-
"""
Created on Fri Mar  1 19:05:07 2024

@author: USER
"""

import random
import hashlib

# Function to generate a prime number of at least the specified bit length
def generate_prime(bit_length):
    prime = 4
    while not is_prime(prime):
        prime = random.getrandbits(bit_length)
    return prime

# Miller-Rabin primality test
def is_prime(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False
    return True

# Extended Euclidean Algorithm
def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient * x, x
        y, lasty = lasty - quotient * y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

# Modular inverse using Extended Euclidean Algorithm
def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError('Modular inverse does not exist')
    return x % m

# Function to find primitive root modulo p
def find_primitive_root(p):
    if p == 2:
        return 1
    p1 = 2
    p2 = (p - 1) // p1

    while True:
        g = random.randint(2, p - 1)
        if not pow(g, (p - 1) // p1, p) == 1:
            if not pow(g, (p - 1) // p2, p) == 1:
                return g

# ElGamal key generation
def elgamal_keygen(bit_length):
    p = generate_prime(bit_length)
    g = find_primitive_root(p)
    x = random.randint(1, p - 2)
    y = pow(g, x, p)
    public_key = (p, g, y)
    private_key = x
    return public_key, private_key

# Hash function
def hash_message(message):
    return int(hashlib.sha256(str(message).encode()).hexdigest(), 16)

# ElGamal signature generation
def elgamal_sign(message, private_key, public_key):
    p, g, y = public_key
    x = private_key
    hashed_message = hash_message(message)
    k = random.randint(1, p - 2)
    while gcd(k, p - 1) != 1:
        k = random.randint(1, p - 2)
    r = pow(g, k, p)
    s = (modinv(k, p - 1) * (hashed_message - x * r)) % (p - 1)
    return r, s

# ElGamal signature verification
def elgamal_verify(message, signature, public_key):
    p, g, y = public_key
    r, s = signature
    if not (0 < r < p and 0 < s < p - 1):
        return False
    hashed_message = hash_message(message)
    left = (pow(y, r, p) * pow(r, s, p)) % p
    right = pow(g, hashed_message, p)
    return left == right

# Greatest common divisor
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

