import random
import operator

""" --- You can edit the variables below --- """

#SBOX = [0x9, 0xb, 0xc, 0x4, 0xa, 0x1, 0x2, 0x6, 0xd, 0x7, 0x3, 0x8, 0xf, 0xe, 0x0, 0x5]
#SBOX = [0x3, 0xe, 0x1, 0xa, 0x4, 0x9, 0x5, 0x6, 0x8, 0xb, 0xf, 0x2, 0xd, 0xc, 0x0, 0x7]
SBOX = [0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7]
INV_SBOX = [0xe, 0x3, 0x4, 0x8, 0x1, 0xc, 0xa, 0xf, 0x7, 0xd, 0x9, 0x6, 0xb, 0x2, 0x0, 0x5]
PBOX = [0x0, 0x4, 0x8, 0xc, 0x1, 0x5, 0x9, 0xd, 0x2, 0x6, 0xa, 0xe, 0x3, 0x7, 0xb, 0xf]
INV_PBOX = [0x0, 0x4, 0x8, 0xc, 0x1, 0x5, 0x9, 0xd, 0x2, 0x6, 0xa, 0xe, 0x3, 0x7, 0xb, 0xf] # PBOX and INV_PBOX are the same in this case

KEY0 = [0x1, 0xa, 0x6, 0xd]
KEY1 = [0x2, 0xa, 0xc, 0x2]
KEY2 = [0x4, 0x5, 0x2, 0xf]
KEY3 = [0x6, 0xf, 0xf, 0x1]
KEY4 = [0xb, 0x5, 0x2, 0x0]

""" ---------------------------------------- """


def main():
    #state = [0x4, 0xb, 0x1, 0xd];
    #encrypted_state = encrypt(state, SBOX, PBOX, KEY0, KEY1, KEY2, KEY3, KEY4);
    #print(state)
    #print(encrypted_state)

    linear_approximation_table = build_linear_approximation_table(SBOX)
    best_linear_approximations = sort_linear_approximations(linear_approximation_table)
    print(best_linear_approximations)

    num_of_linear_approximations = 100
    #most_probable_linear_approximations = find_most_probable_linear_approximations(linear_approximation_table, num_of_linear_approximations)

    #break_keys()

def sort_linear_approximations(linear_approximation_table):
    table_copy = [r.copy() for r in linear_approximation_table]
    sorted_linear_approximations = []


    max = 0
    max_row = None
    max_col = None

    while True: # We'll return once max < 4
        for row in range(len(table_copy)):
            for col in range(len(table_copy[row])):
                if row == 0 and col == 0: continue

                if abs(table_copy[row][col]) > max:
                    max = abs(table_copy[row][col])
                    max_row = row
                    max_col = col


        if max < 4: # Ignore anything less than 4. It's probably not biased enough
            return sorted_linear_approximations
        else:
            sorted_linear_approximations.append((max_row, max_col, linear_approximation_table[max_row][max_col]))
            table_copy[max_row][max_col] = 0
            max = 0



#def find_most_probable_linear_approximations(linear_approximation_table, num_of_linear_approximations):
#    linear_approximations = []
#
#    for i in range(16):
#        for j in range(16):
#            for k in range(16):
#                for l in range(16):
#                    if i == 0 and j == 0 and k == 0 and l == 0: continue
#
#                    input_xor = [i, j, k, l]
#                    most_probable_output_xor, probability = find_differential_trail(input_xor, diff_dist_table, round_num)
#
#                    differential_trails.append((probability, input_xor, most_probable_output_xor))
#
#    differential_trails.sort(reverse=True)
#
#    return differential_trails[:num_of_linear_approximations]

#def break_keys():
#    key_count_dict = {}
#
#    for i in range(10000):
#        plaintext = choose_random_plaintext()
#        ciphertext = encrypt(plaintext, SBOX, PBOX, KEY0, KEY1, KEY2, KEY3, KEY4);
#
#        for first_key_bits in range(16):
#            for second_key_bits in range(16):
#                first = ciphertext[1]
#                second = ciphertext[3]
#                
#                first = first ^ first_key_bits
#                second = second ^ second_key_bits
#
#                first = INV_SBOX[first]
#                second = INV_SBOX[second]
#
#                first_bits = nibble_to_bits(first)
#                second_bits = nibble_to_bits(second)
#                plaintext_bits = nibble_to_bits(plaintext[1])
#
#                bits = [first_bits[1], first_bits[3],
#                        second_bits[1], second_bits[3],
#                        plaintext_bits[0], plaintext_bits[2], plaintext_bits[3]]
#
#                xor = xor_bit_list(bits)
#                key_guess = str([0, first_key_bits, 0, second_key_bits])
#
#                if xor == 1:
#                    if key_guess not in key_count_dict:
#                        key_count_dict[key_guess] = 1
#                    else:
#                        key_count_dict[key_guess] += 1
#
#    sorted_d = sorted(key_count_dict.items(), key=operator.itemgetter(1))
#    print(sorted_d)
                     

def build_linear_approximation_table(sbox):
    linear_approximation_table = [[0 for i in range(16)] for j in range(16)]

    for input_sum in range(16):
        for output_sum in range(16):

            input_sum_bits = nibble_to_bits(input_sum)
            output_sum_bits = nibble_to_bits(output_sum)

            xor_0_counter = 0

            for input in range(16):
                output = sbox[input]

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

""" SPN """

def encrypt(state, sbox, pbox, key0, key1, key2, key3, key4):
    new_state = state.copy()

    new_state = add_round_key(new_state, key0)
    new_state = substitute(new_state, sbox)
    new_state = permutate(new_state, pbox)

    new_state = add_round_key(new_state, key1)
    new_state = substitute(new_state, sbox)
    new_state = permutate(new_state, pbox)

    new_state = add_round_key(new_state, key2)
    new_state = substitute(new_state, sbox)
    new_state = permutate(new_state, pbox)

    new_state = add_round_key(new_state, key3)
    new_state = substitute(new_state, sbox)

    new_state = add_round_key(new_state, key4)

    return new_state

def substitute(state, sbox):
    new_state = state.copy()
    
    for i in range(len(state)):
        new_state[i] = SBOX[state[i]]

    return new_state
def permutate(state, pbox):
    state_as_bits = split_nibbles_into_bits(state)
    new_state_as_bits = state_as_bits.copy()

    for i in range(len(state_as_bits)):
        new_state_as_bits[PBOX[i]] = state_as_bits[i]

    return combine_bits_into_nibbles(new_state_as_bits)

def add_round_key(state, key):
    new_state = state.copy()

    for i in range(len(key)):
        new_state[i] = state[i] ^ key[i]

    return new_state


""" Helper Functions """

def nibble_to_bits(nibble):
    bit_array = []

    bit_array.append((nibble >> 3) & 1)
    bit_array.append((nibble >> 2) & 1)
    bit_array.append((nibble >> 1) & 1)
    bit_array.append(nibble & 1)

    return bit_array

def bits_to_nibble(bits):
    nibble = bits[0] << 3 | bits[1] << 2 | bits[2] << 1 | bits[3]

    return nibble

def split_nibbles_into_bits(nibble_array):
    bit_array = []

    for nibble in nibble_array:
        bit_array += nibble_to_bits(nibble)

    return bit_array

def combine_bits_into_nibbles(bits_array):
    nibble_array = []

    for i in range(0, len(bits_array), 4):
        nibble = bits_to_nibble(bits_array[i:i + 4])
        nibble_array.append(nibble)

    return nibble_array

def xor_bit_list(bit_list):
    xor = 0

    for bit in bit_list:
        xor ^= bit

    return xor

def choose_random_plaintext():
    return [random.randrange(16) for n in range(4)]

# Normal printing is going to print integers in decimal. For debugging, hex is much easier
def print_1d_hex(arr):
    print(get_string_1d_hex(arr))

# Normal printing is going to print integers in decimal. For debugging, hex is much easier
def print_2d_hex(arr):
    print(get_string_2d_hex(arr))

def get_string_2d_hex(arr):
    string = '[\n'

    for i in range(len(arr)):
        string += '  ['
        for j in range(len(arr[i])):
            string += '{:#02x}'.format(arr[i][j]) + ', '

        string = string[:-2] # remove the ', ' from last element
        string += ']\n'

    string += ']'

    return string

def get_string_1d_hex(arr):
    string = '['

    for i in range(len(arr)):
        string += '{:#02x}'.format(arr[i]) + ', '

    string = string[:-2] # remove the ', ' from last element
    string += ']'

    return string

if __name__=="__main__":
    main()
