import random
import operator
import ast
import time

""" --- You can edit the variables below --- """

#SBOX = [0x9, 0xb, 0xc, 0x4, 0xa, 0x1, 0x2, 0x6, 0xd, 0x7, 0x3, 0x8, 0xf, 0xe, 0x0, 0x5]
#SBOX = [0x3, 0xe, 0x1, 0xa, 0x4, 0x9, 0x5, 0x6, 0x8, 0xb, 0xf, 0x2, 0xd, 0xc, 0x0, 0x7]
#INV_SBOX = [0xe, 0x2, 0xb, 0x0, 0x4, 0x6, 0xf, 0x8, 0x5, 0x3, 0x9, 0xd, 0xc, 0x1, 0xa]
SBOX = [0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7]
INV_SBOX = [0xe, 0x3, 0x4, 0x8, 0x1, 0xc, 0xa, 0xf, 0x7, 0xd, 0x9, 0x6, 0xb, 0x2, 0x0, 0x5]
PBOX = [0x0, 0x4, 0x8, 0xc, 0x1, 0x5, 0x9, 0xd, 0x2, 0x6, 0xa, 0xe, 0x3, 0x7, 0xb, 0xf]
INV_PBOX = [0x0, 0x4, 0x8, 0xc, 0x1, 0x5, 0x9, 0xd, 0x2, 0x6, 0xa, 0xe, 0x3, 0x7, 0xb, 0xf] # PBOX and INV_PBOX are the same in this case

KEY0 = [0x1, 0xa, 0x6, 0xd]
KEY1 = [0x2, 0xa, 0xc, 0x2]
KEY2 = [0x4, 0x5, 0x2, 0xf]
KEY3 = [0x6, 0xf, 0xf, 0x1]
KEY4 = [0xb, 0x5, 0x2, 0x0]

KEY0_INT = 0x1a6d
KEY1_INT = 0x2ac2
KEY2_INT = 0x452f
KEY3_INT = 0x6ff1
KEY4_INT = 0xb520

""" ---------------------------------------- """


def main():
    #state = [0x4, 0xb, 0x1, 0xd]
    #encrypted_state = encrypt(state, SBOX, PBOX, KEY0, KEY1, KEY2, KEY3, KEY4)

    # Find linear approximations for the SBOX
    linear_approximation_table = build_linear_approximation_table(SBOX)
    best_linear_approximations = sort_linear_approximation_table(linear_approximation_table)

    # Find linear approximations for the whole cipher
    #all_linear_approximations = find_all_linear_approximations(best_linear_approximations, 1)
    f = open('linear-approximations/3-sorted-linear-approximations', 'r')
    content = f.read()
    three_sorted_linear_approximations = ast.literal_eval(content) # convert string representation of list, back into list
    f.close()

    f = open('linear-approximations/2-sorted-linear-approximations', 'r')
    content = f.read()
    two_sorted_linear_approximations = ast.literal_eval(content) # convert string representation of list, back into list
    f.close()

    f = open('linear-approximations/1-sorted-linear-approximations', 'r')
    content = f.read()
    one_sorted_linear_approximations = ast.literal_eval(content) # convert string representation of list, back into list
    f.close()

    #breaking_key_bits = find_which_key_bits_will_be_broken(sorted_linear_approximations[27][1])
    #break_key_bits(sorted_linear_approximations[27], breaking_key_bits)

    round_keys = [[], [], [], [], []]
    start = time.time()

    fifth_round_key_possibilities = break_round_key(three_sorted_linear_approximations, 3, round_keys)
    #fifth_round_key_possibilities = [[11, 5, 2, 0]]

    for k5 in fifth_round_key_possibilities:
        round_keys[4] = k5

        fourth_round_key_possibilities = break_round_key(two_sorted_linear_approximations, 2, round_keys)
        #fourth_round_key_possibilities = [[6, 15, 15, 1]]
        
        for k4 in fourth_round_key_possibilities:
            round_keys[3] = k4

            third_round_key_possibilities = break_round_key(one_sorted_linear_approximations, 1, round_keys)
            #third_round_key_possibilities = [[4, 5, 2, 15]]

            for k3 in third_round_key_possibilities:
                round_keys[2] = k3
                
                # We have to use a special process for the last two
                # We could also brute force them, but it would take a while
                get_last_two_keys(round_keys)

                if validate_round_keys(round_keys):
                    end = time.time()
                    print('\nFound all round keys in ' + str(round(end - start, 2)) + ' seconds!\n') 
                    print(round_keys)

                    return


def validate_round_keys(round_keys):
    for i in range(30): # 30 is enough plaintexts to check if the keys are correct
        plaintext = choose_random_plaintext()
        ciphertext = encrypt(plaintext, SBOX, PBOX, KEY0, KEY1, KEY2, KEY3, KEY4)
        ciphertext_guess = encrypt(plaintext, SBOX, PBOX, round_keys[0], round_keys[1], round_keys[2], round_keys[3], round_keys[4])

        if ciphertext != ciphertext_guess:
            return False

    return True

def get_last_two_keys(round_keys):
    k1_1, k2_1 = get_last_two_key_nibbles(0, round_keys)
    k1_2, k2_2 = get_last_two_key_nibbles(1, round_keys)
    k1_3, k2_3 = get_last_two_key_nibbles(2, round_keys)
    k1_4, k2_4 = get_last_two_key_nibbles(3, round_keys)

    k1 = [k1_1, k1_2, k1_3, k1_4]

    k2 = []

    for i in range(len(k2_1)):
        k2.append(k2_1[i] | k2_2[i] | k2_3[i] | k2_4[i])

    k2 = combine_bits_into_nibbles(k2)

    round_keys[1] = k2
    round_keys[0] = k1

def get_last_two_key_nibbles(nibble_num, round_keys):
    plaintext = choose_random_plaintext()

    for k2_nibble in range(16):
        ciphertext = encrypt(plaintext, SBOX, PBOX, KEY0, KEY1, KEY2, KEY3, KEY4)
        partially_decrypted = split_nibbles_into_bits(partially_decrypt(ciphertext, 1, round_keys))

        nibble = partially_decrypted[INV_PBOX[nibble_num * 4]] << 3
        nibble |= partially_decrypted[INV_PBOX[nibble_num * 4 + 1]] << 2
        nibble |= partially_decrypted[INV_PBOX[nibble_num * 4 + 2]] << 1
        nibble |= partially_decrypted[INV_PBOX[nibble_num * 4 + 3]]

        after_key = nibble ^ k2_nibble

        k1_nibble = INV_SBOX[after_key] ^ plaintext[nibble_num]

        if validate_last_two_key_nibbles(nibble_num, k1_nibble, k2_nibble, round_keys):
            k2_bits = 16 * [0]
            k2_bits[INV_PBOX[nibble_num * 4]]     |= ((k2_nibble & 8) >> 3)
            k2_bits[INV_PBOX[nibble_num * 4 + 1]] |= ((k2_nibble & 4) >> 2)
            k2_bits[INV_PBOX[nibble_num * 4 + 2]] |= ((k2_nibble & 2) >> 1)
            k2_bits[INV_PBOX[nibble_num * 4 + 3]] |= (k2_nibble & 1)

            return (k1_nibble, k2_bits)

    return (0, 16 * [0])

def validate_last_two_key_nibbles(nibble_num, k1_nibble, k2_nibble, round_keys):
    for i in range(30): # 30 is enough plaintexts to check if the keys are correct
        plaintext = choose_random_plaintext()
        ciphertext = encrypt(plaintext, SBOX, PBOX, KEY0, KEY1, KEY2, KEY3, KEY4)
        partially_decrypted = split_nibbles_into_bits(partially_decrypt(ciphertext, 1, round_keys))

        nibble = partially_decrypted[INV_PBOX[nibble_num * 4]] << 3
        nibble |= partially_decrypted[INV_PBOX[nibble_num * 4 + 1]] << 2
        nibble |= partially_decrypted[INV_PBOX[nibble_num * 4 + 2]] << 1
        nibble |= partially_decrypted[INV_PBOX[nibble_num * 4 + 3]]

        after_key = nibble ^ k2_nibble

        plaintext_guess = k1_nibble ^ INV_SBOX[after_key]

        if plaintext[nibble_num] != plaintext_guess:
            return False

    return True

def break_round_key(sorted_linear_approximations, round_num, round_keys):
    possible_round_keys = [[0] * 16]
    sboxes_already_used = [False, False, False, False]

    while not all(sboxes_already_used):
        useful_linear_approximation = find_useful_linear_approximation(sorted_linear_approximations, sboxes_already_used)
        print('Found useful linear approximation: ' + get_string_1d_hex(useful_linear_approximation[0]) + ' -> ' + get_string_1d_hex(useful_linear_approximation[1]))
        print(useful_linear_approximation)

        breaking_key_bits = find_which_key_bits_will_be_broken(useful_linear_approximation[1], round_num)
        broken_key_bits = break_key_bits(useful_linear_approximation, breaking_key_bits, round_num, round_keys)

        new_possible_round_keys = []

        for j in range(len(broken_key_bits)):
            possible_round_key = [0] * 16

            # Set the keybits which were broken
            for i in range(len(breaking_key_bits)):
                if breaking_key_bits[i] == 1:
                    possible_round_key[i] = broken_key_bits[j][i]

            # Combine the old prks with the current ones
            for old_prk in possible_round_keys:
                new_prk = [0] * 16

                for i in range(16):
                    new_prk[i] = old_prk[i] | possible_round_key[i]

                new_possible_round_keys.append(new_prk)

        possible_round_keys = new_possible_round_keys[:]

        # Mark which sboxes this used up
        for i in range(4):
            if useful_linear_approximation[1][i] != 0:
                sboxes_already_used[i] = True

    # We want it as list of nibbles at the end
    for i in range(len(possible_round_keys)):
        possible_round_keys[i] = combine_bits_into_nibbles(possible_round_keys[i])

    #print('*************************************')
    #print('  Found KEY' + ' = ' + get_string_1d_hex(round_key))
    #print('*************************************')

    #print(possible_round_keys)

    return possible_round_keys

def find_useful_linear_approximation(sorted_linear_approximations, sboxes_already_used):
    for la in sorted_linear_approximations:

        # Check if this linear approximation will use any sboxes which we haven't used already
        for i in range(4):
            if la[1][i] != 0 and sboxes_already_used[i] == False: # Hit! We can use this one
                return la

def break_key_bits(linear_approximation, breaking_key_bits, round_num, round_keys):
    key_count_dict = {}

    num_plaintexts = get_num_plaintexts(abs(linear_approximation[2]))
    print(num_plaintexts)

    for i in range(num_plaintexts):
        plaintext = choose_random_plaintext()
        ciphertext = encrypt(plaintext, SBOX, PBOX, KEY0, KEY1, KEY2, KEY3, KEY4)

        # This will modify the key_count_dict after key guesses
        guess_key_bits(linear_approximation, plaintext, ciphertext, key_count_dict, breaking_key_bits, round_num, round_keys)

    for (k, v) in key_count_dict.items():
        key_count_dict[k] = abs(v - (num_plaintexts // 2))
        
    sorted_d = sorted(key_count_dict.items(), key=operator.itemgetter(1))

    most_probable_keys = []

    # Count for the most likely key out of the dictonary
    max = sorted_d[-1][1]

    # There might be other keys which are equally likely
    for e in sorted_d:
        if e[1] == max:
            most_probable_keys.append(e[0])

    # Put keys back into list form, since it was a string in the dict
    for i in range(len(most_probable_keys)):
        most_probable_keys[i] = list(map(int, most_probable_keys[i].split(' ')))

    # We want it as array of bits, not nibbles
    final_key_guesses = []

    for k in most_probable_keys:
        final_key_guesses.append(split_nibbles_into_bits(k))

    return final_key_guesses

def get_num_plaintexts(p):
    # This equation comes from multiple example points
    #num_plaintexts = (-3.62998 * pow(10, 10) * pow(p, 5)) + (1.58026 * pow(10, 10) * pow(p, 4)) - (2.551 * pow(10, 9) * pow(p, 3)) + (1.89757 * pow(10, 8) * pow(p, 2)) - (6.5479 * pow(10, 6) * p) + 86173.6
    num_plaintexts = (-7.60197 * pow(10, 10) * pow(p, 5)) + (3.34827 * pow(10, 10) * pow(p, 4)) - (5.48666 * pow(10, 9) * pow(p, 3)) + (4.15299 * pow(10, 8) * pow(p, 2)) - (1.45375 * pow(10, 7) * p) + 190506

    # We want an integer
    num_plaintexts = round(num_plaintexts)

    # We want even since we'll be dividing by two later
    if num_plaintexts % 2 == 1:
        num_plaintexts += 1

    # Don't want anything less than 100
    if num_plaintexts < 100:
        num_plaintexts = 100

    return num_plaintexts

def guess_key_bits(linear_approximation, plaintext, ciphertext, key_count_dict, breaking_key_bits, round_num, round_keys):
    total_needed_key_guesses = 1

    for bit in breaking_key_bits:
        if bit == 1:
            total_needed_key_guesses *= 2

    for i in range(total_needed_key_guesses):
        key_guess_bits = [0] * 16
        div = total_needed_key_guesses / 2

        # This for loop is hard to understand but it loops thorough all possible
        # keys only for the bits where breaking_key_bits is set
        for j in range(len(breaking_key_bits)):
            if breaking_key_bits[j] == 1:
                if i > div - 1 and i % (div * 2) >= div:
                    key_guess_bits[j] = 1

                div /= 2

        key_guess = combine_bits_into_nibbles(key_guess_bits)
        key_as_string = ' '.join(map(str, key_guess))

        round_keys[round_num + 1] = key_guess

        partially_decrypted = partially_decrypt(ciphertext, round_num, round_keys)
        bits = []

        for i in range(len(linear_approximation[0])):
            la_nibble = linear_approximation[0][i]
            pt_nibble = plaintext[i]

            la_bits = nibble_to_bits(la_nibble)
            pt_bits = nibble_to_bits(pt_nibble)

            for j in range(len(la_bits)):
                if la_bits[j] == 1:
                    bits.append(pt_bits[j])

        for i in range(len(linear_approximation[1])):
            la_nibble = linear_approximation[1][i]
            pd_nibble = partially_decrypted[i]

            la_bits = nibble_to_bits(la_nibble)
            pd_bits = nibble_to_bits(pd_nibble)

            for j in range(len(la_bits)):
                if la_bits[j] == 1:
                    bits.append(pd_bits[j])

        xor = xor_bit_list(bits)

        if xor == 1:
            if key_as_string not in key_count_dict:
                key_count_dict[key_as_string] = 1
            else:
                key_count_dict[key_as_string] += 1
    

def find_which_key_bits_will_be_broken(ciphertext, round_num):
    breaking_key_bits = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    for i in range(len(ciphertext)):
        if ciphertext[i] != 0:
            breaking_key_bits[i * 4] = 1
            breaking_key_bits[i * 4 + 1] = 1
            breaking_key_bits[i * 4 + 2] = 1
            breaking_key_bits[i * 4 + 3] = 1

    if round_num < 3: # If round_num < 3 we need to take the permutation into account
        tmp = breaking_key_bits.copy()

        for i in range(len(breaking_key_bits)):
            breaking_key_bits[i] = tmp[INV_PBOX[i]]
        
    return breaking_key_bits

def partially_decrypt(ciphertext, round_num, round_keys):
    partially_decrypted_ciphertext = ciphertext[:]

    if round_num <= 3:
        partially_decrypted_ciphertext = add_round_key(partially_decrypted_ciphertext, round_keys[4])
        partially_decrypted_ciphertext = substitute(partially_decrypted_ciphertext, INV_SBOX)
    if round_num <= 2:
        partially_decrypted_ciphertext = add_round_key(partially_decrypted_ciphertext, round_keys[3])
        partially_decrypted_ciphertext = permutate(partially_decrypted_ciphertext, INV_PBOX)
        partially_decrypted_ciphertext = substitute(partially_decrypted_ciphertext, INV_SBOX)
    if round_num <= 1:
        partially_decrypted_ciphertext = add_round_key(partially_decrypted_ciphertext, round_keys[2])
        partially_decrypted_ciphertext = permutate(partially_decrypted_ciphertext, INV_PBOX)
        partially_decrypted_ciphertext = substitute(partially_decrypted_ciphertext, INV_SBOX)
    if round_num <= 0:
        partially_decrypted_ciphertext = add_round_key(partially_decrypted_ciphertext, round_keys[1])
        partially_decrypted_ciphertext = permutate(partially_decrypted_ciphertext, INV_PBOX)
        partially_decrypted_ciphertext = substitute(partially_decrypted_ciphertext, INV_SBOX)

    return partially_decrypted_ciphertext


def sort_linear_approximations(all_linear_approximations):
    all_linear_approximations_copy = all_linear_approximations[:]
    sorted_linear_approximations = []

    # subtract 0.5 from probability since we want to sort by how
    # far away the probability is from 0.5
    for la in all_linear_approximations_copy:
        la[2] = la[2] - 0.5

    # if there are a lot of active SBOXes in the output, it'll be difficult to
    # brute force. So we say that if there's only one or two active SBOXes,
    # we'll keep the probability the same. If three, divide by 5. If 4, set
    # to 0; those won't be useful
    for la in all_linear_approximations_copy:
        zeros = 0

        for nibble in la[1]:
            if nibble == 0:
                zeros += 1

        if zeros == 1:
            la[2] /= 5
        elif zeros == 0:
            la[2] = 0

    while len(all_linear_approximations_copy) > 0:
        max_la = all_linear_approximations_copy[0]

        for la in all_linear_approximations_copy:
            if abs(la[2]) > abs(max_la[2]):
                max_la = la

        sorted_linear_approximations.append(max_la[:])
        all_linear_approximations_copy.remove(max_la)

    return sorted_linear_approximations

def find_linear_approximation(input_mask, best_linear_approximations, round_num, active_sboxes, total_bias, trails):
    # Base case
    if round_num == 0:
        # Now we use the pilling-up lemma to figure out the probability; used to rank approximations
        
        trail_probability = 0.5 + pow(2, active_sboxes - 1) * total_bias

        trails.append([input_mask, trail_probability])

        return

    possible_outputs = get_possible_outputs(input_mask, best_linear_approximations)

    for output0 in possible_outputs[0]:
        for output1 in possible_outputs[1]:
            for output2 in possible_outputs[2]:
                for output3 in possible_outputs[3]:
                    output_mask = []

                    output_mask.append(output0[0])
                    output_mask.append(output1[0])
                    output_mask.append(output2[0])
                    output_mask.append(output3[0])

                    # setup a bunch of variables for recursion
                    new_input_mask = permutate(output_mask, PBOX)
                    new_active_sboxes = 0
                    new_bias = 1

                    for nibble in output_mask:
                        if nibble != 0:
                            new_active_sboxes += 1

                    if output0[0] != 0: new_bias *= output0[1]
                    if output1[0] != 0: new_bias *= output1[1]
                    if output2[0] != 0: new_bias *= output2[1]
                    if output3[0] != 0: new_bias *= output3[1]

                    active_sboxes += new_active_sboxes
                    total_bias *= new_bias

                    find_linear_approximation(new_input_mask, best_linear_approximations, round_num - 1, active_sboxes, total_bias, trails)

                    active_sboxes -= new_active_sboxes
                    total_bias /= new_bias

def get_possible_outputs(input_mask, best_linear_approximations):
    possible_outputs = [[(0, 0)], [(0, 0)], [(0, 0)], [(0, 0)]]

    for i, nibble in enumerate(input_mask):
        for la in best_linear_approximations:
            sbox_input_mask = la[0]
            sbox_output_mask = la[1]
            entry = la[2]

            if sbox_input_mask == nibble:
                if possible_outputs[i][0] == (0, 0): # Replace default (0, 0)
                    possible_outputs[i][0] = (sbox_output_mask, entry / 16) # entry / 16 gives the bias
                else:
                    possible_outputs[i].append((sbox_output_mask, entry / 16)) # entry / 16 gives the bias

    return possible_outputs

def remove_very_low_probabilities(linear_approximations, rounds):
    better_linear_approximations = []

    very_low = 0

    if rounds == 3:
        very_low = 0.01
    elif rounds == 2:
        very_low = 0.06
    elif rounds == 1:
        very_low = 0.1

    for la in linear_approximations:
        if abs(la[2] - 0.5) > very_low:
            better_linear_approximations.append(la)

    return better_linear_approximations

def find_all_linear_approximations(best_linear_approximations, rounds):
    for i in range(16):
        all_trails = []

        for j in range(16):
            for k in range(16):
                print(i, j, k)
                for l in range(16):
                    input_mask = [i, j, k, l]

                    if input_mask == [0, 0, 0, 0]: continue

                    trails = []
                    find_linear_approximation(input_mask, best_linear_approximations, rounds, 0, 1, trails)
                    
                    for m, t in enumerate(trails):
                        t.insert(0, list(input_mask)) # insert the input_mask at the start
                        trails[m] = t
                    
                    all_trails += list(trails)


        # Because there are too many, and it takes a very long time, we will save
        # each of them, for each i value, into their own file, and combine them later
        # We also remove very low probabilites to conserve space/time
        # We also sort them by their probabilities
        better_linear_approximations = remove_very_low_probabilities(all_trails, rounds)
        print(len(better_linear_approximations))
        sorted_linear_approximations = sort_linear_approximations(better_linear_approximations)

        f = open(f'la-{rounds}-{i}', 'w')
        f.write(str(sorted_linear_approximations))
        f.close()

    all_trails = []

    for i in range(16):
        f = open(f'la-{rounds}-{i}', 'r')
        content = f.read()
        lst = ast.literal_eval(content) # convert string representation of list, back into list
        print(len(lst))
        f.close()

        all_trails = merge_linear_approximation_lists(all_trails, lst)

    print(len(all_trails))

    f = open(f'{rounds}-sorted-linear-approximations', 'w')
    f.write(str(all_trails))
    f.close()

    #for i in range(4):
    #    input_mask = [0, 0, 0, 0]

    #    for nibble in range(16):
    #        input_mask[i] = nibble

    #        if input_mask == [0, 0, 0, 0]: continue

    #        trails = []
    #        find_linear_approximation(input_mask, best_linear_approximations, 3, 0, 1, trails)
    #        
    #        for j, t in enumerate(trails):
    #            t.insert(0, list(input_mask)) # insert the input_mask at the start
    #            trails[j] = t
    #        
    #        all_trails += list(trails)

    return all_trails

def merge_linear_approximation_lists(lst1, lst2):
    i = 0
    j = 0

    merged_list = []

    while i < len(lst1) and j < len(lst2):
        if abs(lst1[i][2]) > abs(lst2[j][2]):
            #print(lst1[i])
            merged_list.append(lst1[i])
            i += 1
        else:
            #print(lst2[j])
            merged_list.append(lst2[j])
            j += 1

    while i < len(lst1):
        merged_list.append(lst1[i])
        i += 1

    while j < len(lst2):
        merged_list.append(lst2[j])
        j += 1

    return merged_list

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

            linear_approximation_table[input_sum][output_sum] = xor_0_counter - 8

    return linear_approximation_table

def sort_linear_approximation_table(linear_approximation_table):
    table_copy = [r[:] for r in linear_approximation_table]
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

""" SPN """

def quick_encrypt(state, sbox, pbox, key0, key1, key2, key3, key4):
    # state is just an integer which will make this quicker but less readable
    state ^= key0
    state = quick_substitute(state, sbox)
    state = quick_permutate(state, pbox)

    state ^= key1
    state = quick_substitute(state, sbox)
    state = quick_permutate(state, pbox)

    state ^= key2
    state = quick_substitute(state, sbox)
    state = quick_permutate(state, pbox)

    state ^= key3
    state = quick_substitute(state, sbox)

    state ^= key4

    return state

def quick_permutate(state, pbox):
    new_state = 0

    for i in pbox:
        new_state |= ((state >> i) & 1) << pbox[i]

    return new_state

def quick_substitute(state, sbox):
    # state is just an integer which will make this quicker but less readable

    new_state = sbox[state >> 12] << 12
    new_state |= sbox[(state & 0x0f00) >> 8] << 8
    new_state |= sbox[(state & 0x00f0) >> 4] << 4
    new_state |= sbox[(state & 0x000f)]

    return new_state

def encrypt(state, sbox, pbox, key0, key1, key2, key3, key4):
    new_state = state[:]

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
    new_state = state[:]
    
    for i in range(len(state)):
        new_state[i] = sbox[state[i]]

    return new_state
def permutate(state, pbox):
    state_as_bits = split_nibbles_into_bits(state)
    new_state_as_bits = state_as_bits[:]

    for i in range(len(state_as_bits)):
        new_state_as_bits[pbox[i]] = state_as_bits[i]

    return combine_bits_into_nibbles(new_state_as_bits)

def add_round_key(state, key):
    new_state = state[:]

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
