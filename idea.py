class IDEA:
    def __init__(self, key):
        self._keys = None
        self.gen_keys(key)


    # Multiplication modulo
    def mul_mod(self, a, b):
        assert 0 <= a <= 0xFFFF
        assert 0 <= b <= 0xFFFF

        if a == 0:
            a = 0x10000
        if b == 0:
            b = 0x10000

        r = (a * b) % 0x10001

        if r == 0x10000:
            r = 0

        assert 0 <= r <= 0xFFFF
        return r


    # Addition modulo
    def add_mod(self, a, b):
        return (a + b) % 0x10000


    # Additive inverse
    def add_inv(self, key):
        u = (0x10000 - key) % 0xFFFF
        assert 0 <= u <= 0x10000 - 1
        return u


    # Multiplicative inverse
    def mul_inv(self, key):
        a = 0x10000 + 1    #2^16 +1 
        if key == 0:
            return 0
        else:
            x = 0
            y = 0
            x1 = 0
            x2 = 1
            y1 = 1
            y2 = 0
            while key > 0:
                q = a // key
                r = a - q * key
                x = x2 - q * x1
                y = y2 - q * y1
                a = key
                key = r
                x2 = x1
                x1 = x
                y2 = y1
                y1 = y
            d = a
            x = x2
            y = y2
            return y
        
        



    # Encryption / Decryption round
    def round(self, p1, p2, p3, p4, keys):
        k1, k2, k3, k4, k5, k6 = keys

        # Step 1
        p1 = self.mul_mod(p1, k1)
        p4 = self.mul_mod(p4, k4)
        p2 = self.add_mod(p2, k2)
        p3 = self.add_mod(p3, k3)
        # Step 2
        x = p1 ^ p3
        t0 = self.mul_mod(k5, x)
        x = p2 ^ p4
        x = self.add_mod(t0, x)
        t1 = self.mul_mod(k6, x)
        t2 = self.add_mod(t0, t1)
        # Step 3
        p1 = p1 ^ t1
        p4 = p4 ^ t2
        a = p2 ^ t2
        p2 = p3 ^ t1
        p3 = a

        return p1, p2, p3, p4



# /*
# Iterate through 54 iterations (9 rounds * 6 sub-keys per round):
#     - Extract 16 bits from the key based on the current iteration.
#     - The offset is determined by cycling through values 0 to 7 (i % 8) in multiples of 16.
#     - Generate a decreasing value starting at 112, decreasing by 16 every 8 iterations.
#     - Right-shift the bits of the key to isolate 16 bits based on the current iteration.
#     - Perform a bitwise AND operation with 0xFFFF (equivalent to % 0x10000).
#     - Extract the lower 16 bits of the result, ensuring only the least significant bits are retained.
#     - Append the extracted 16 bits to the sub_keys list.
#     - If 8 sub-keys have been processed, perform a key mixing operation.
# Organize sub-keys into sets of 6 for each of the 9 rounds.
# Assign the keys as a tuple of tuples to the _keys attribute of the class.
# */
    # Key generation
    def gen_keys(self, key):
        assert 0 <= key < (1 << 128) #verifing that the size of the key is corrected 
        modulus = 1 << 128 # 2^128

        sub_keys = []
        for i in range(9 * 6): #54 times 
            sub_keys.append((key >> (112 - 16 * (i % 8))) % 0x10000) #The purpose of this entire expression is to extract 16 bits from the original key based on the current iteration i. This is done in a cyclic manner, with different sets of 16 bits being extracted in each iteration. The extracted 16 bits are then appended to the sub_keys list, forming the sub-keys used in the subsequent cryptographic key generation process
            if i % 8 == 7:
                key = ((key << 25) | (key >> 103)) % modulus  # every time that we collect 16 sub keys to are array we shift left the key in 25 positions  like circle and return to the loop with the shifted key 

        keys = []
        for i in range(9):
            round_keys = sub_keys[6 * i: 6 * (i + 1)] # {0,6} for the first round  [6,12] to the secound round ..... [48,54] for round 8
            keys.append(tuple(round_keys))
        self._keys = tuple(keys)
     

    # Encryption
    def  encrypt(self, plain):
        p1 = (plain >> 48) & 0xFFFF
        p2 = (plain >> 32) & 0xFFFF  #takes the 16 relevent bits from input 64 bits every time. this the the (16bit)(this 16bit!!! )(16bit)(16bit)
        p3 = (plain >> 16) & 0xFFFF
        p4 = plain & 0xFFFF
        
        # All 8 rounds
        for i in range(8):
            keys = self._keys[i]
            p1, p2, p3, p4 = self.round(p1, p2, p3, p4, keys)
        
        # Final output transformation
        k1, k2, k3, k4, x, y = self._keys[8]
        y1 = self.mul_mod(p1, k1)
        y2 = self.add_mod(p3, k2)
        y3 = self.add_mod(p2, k3)
        y4 = self.mul_mod(p4, k4)

        encrypted = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4
        return encrypted


    # Decryption
    def decrypt(self, encrypted):
        p1 = (encrypted >> 48) & 0xFFFF
        p2 = (encrypted >> 32) & 0xFFFF
        p3 = (encrypted >> 16) & 0xFFFF
        p4 = encrypted & 0xFFFF

        # Round 1
        keys = self._keys[8]
        k1 = self.mul_inv(keys[0])
        if k1 < 0:
            k1 = 0x10000 + 1 + k1
        k2 = self.add_inv(keys[1])
        k3 = self.add_inv(keys[2])
        k4 = self.mul_inv(keys[3])
        if k4 < 0:
            k4 = 0x10000 + 1 + k4
        keys = self._keys[7]
        k5 = keys[4]
        k6 = keys[5]
        keys = [k1, k2, k3, k4, k5, k6]
        p1, p2, p3, p4 = self.round(p1, p2, p3, p4, keys)

        # Other rounds
        for i in range(1, 8):
            keys = self._keys[8-i]
            k1 = self.mul_inv(keys[0])
            if k1 < 0:
                k1 = 0x10000 + 1 + k1
            k2 = self.add_inv(keys[2])
            k3 = self.add_inv(keys[1])
            k4 = self.mul_inv(keys[3])
            if k4 < 0:
                k4 = 0x10000 + 1 + k4
            keys = self._keys[7-i]
            k5 = keys[4]
            k6 = keys[5]
            keys = [k1, k2, k3, k4, k5, k6]
            p1, p2, p3, p4 = self.round(p1, p2, p3, p4, keys)
        
        # Final output transformation
        keys = self._keys[0]
        k1 = self.mul_inv(keys[0])
        if k1 < 0:
            k1 = 0x10000 + 1 + k1
        k2 = self.add_inv(keys[1])
        k3 = self.add_inv(keys[2])
        k4 = self.mul_inv(keys[3])
        if k4 < 0:
            k4 = 0x10000 + 1 + k4
        y1 = self.mul_mod(p1, k1)
        y2 = self.add_mod(p3, k2)
        y3 = self.add_mod(p2, k3)
        y4 = self.mul_mod(p4, k4)
        decrypted = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4
        return decrypted
