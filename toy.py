# This a simple "toy" cipher. Taken from http://theamazingking.com/crypto-diff.php
from itertools import combinations

""" --- You can edit the variables below --- """

SBOX = [0x9, 0xb, 0xc, 0x4, 0xa, 0x1, 0x2, 0x6, 0xd, 0x7, 0x3, 0x8, 0xf, 0xe, 0x0, 0x5]
#SBOX = [0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7]
#SBOX = [0x3, 0xe, 0x1, 0xa, 0x4, 0x9, 0x5, 0x6, 0x8, 0xb, 0xf, 0x2, 0xd, 0xc, 0x0, 0x7]

KEY0 = 0x7
KEY1 = 0xe

""" ---------------------------------------- """


def main():
    state = 0x4

    linear_approximation_table = build_linear_approximation_table(SBOX)
    print(linear_approximation_table)

    #print(encrypt(state, SBOX, KEY0, KEY1))

def build_linear_approximation_table(sbox):
    linear_approximation_table = [[0 for i in range(16)] for j in range(16)]

    for input_sum in range(16):
        for output_sum in range(16):

            input_sum_bits = nibble_to_bits(input_sum)
            output_sum_bits = nibble_to_bits(output_sum)

            xor_0_counter = 0

            for input in range(16):
                output = substitute(input, sbox)

                input_bits = nibble_to_bits(input)
                output_bits = nibble_to_bits(output)

                bit_list = []

                for index, bit in enumerate(input_sum_bits):
                    if bit == 1:
                        bit_list.append(input_bits[index])

                for index, bit in enumerate(output_sum_bits):
                    if bit == 1:
                        bit_list.append(output_bits[index])

                xor = xor_bit_list(bit_list)

                if xor == 0:
                    xor_0_counter += 1

            linear_approximation_table[input_sum][output_sum] = xor_0_counter - 8;

    return linear_approximation_table


""" Toy Cipher """

def encrypt(state, sbox, key0, key1):
    state = add_round_key(state, key0)
    state = substitute(state, sbox)
    state = add_round_key(state, key1)

    return state

def substitute(state, sbox):
    return sbox[state]

def add_round_key(state, key):
    return state ^ key


""" Helper Functions """

def nibble_to_bits(nibble):
    bit_array = []

    bit_array.append((nibble >> 3) & 1)
    bit_array.append((nibble >> 2) & 1)
    bit_array.append((nibble >> 1) & 1)
    bit_array.append(nibble & 1)

    return bit_array

def xor_bit_list(bit_list):
    xor = 0

    for bit in bit_list:
        xor ^= bit

    return xor


if __name__=="__main__":
    main()
