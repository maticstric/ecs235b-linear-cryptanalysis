# This a simple "toy" cipher. Taken from http://theamazingking.com/crypto-diff.php

""" --- You can edit the variables below --- """

SBOX = [0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7]
#SBOX = [0x3, 0xe, 0x1, 0xa, 0x4, 0x9, 0x5, 0x6, 0x8, 0xb, 0xf, 0x2, 0xd, 0xc, 0x0, 0x7]

KEY0 = 0x7
KEY1 = 0xe

""" ---------------------------------------- """


def main():
    state = 0x4

    encrypted_state = encrypt(state, SBOX, KEY0, KEY1)

    print(encrypted_state)


""" Toy Cipher """

def encrypt(state, sbox, key0, key1):
    state = add_round_key(state, key0)
    state = sub(state, sbox)
    state = add_round_key(state, key1)

    return state

def sub(state, sbox):
    return sbox[state]

def add_round_key(state, key):
    return state ^ key

if __name__=="__main__":
    main()
