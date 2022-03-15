# ECS 235B — Linear Cryptanalysis
This repo contains all the code for the ECS 235B (winter 2022) quarter-long project on linear cryptanalysis.

# How to Run the Code
Note that Python 3 is required.

For the sake of simplicity, the script doesn't take command line arguments. Instead, you may directly modify certain variables in the code if you want to change them from their default values. This README specifies which variables you can edit (they are also marked in the file). Since this was purely an educational exercise, we don't check that the variables that you change will be of the correct type/length/format. Please be nice to the scripts (we are well aware of the irony of saying this while taking a security class).

There are two major parts to the code:
1. Everything in the `linear-approximations` directory
2. Breaking an SPN with differential cryptanalysis

## `linear-approximations`
This directory includes the precomputed linear approximations for the default SBOXes and PBOXes in `spn.py`. As explained in the associated paper, computing these can take a long time. We wanted to make running the SPN breaker as easy as possible so, instead of computing them every time, we precompute them and save the results into files located in this directory.

The three important files in the directory are `3-sorted-linear-approximations`, `2-sorted-linear-approximations`, and `1-sorted-linear-approximations`. These include the 3-, 2-, and 1-round linear approximations sorted by their bias. The other files in the subdirectories are simply there because we use them to compute the important ones. They could be deleted but we decided to keep them for debugging purposes.

If you change the SBOX or PBOX for the cipher, the linear approximations will have to be recomputed. You can find the code to do so in the `spn.py` file (it is commented out). There are a few things to note if you do this:

1. The files will simply go to the root of the repo (we didn't want to overwrite them by default in case something went wrong) so, after running the code to compute them, you'll have to manually move them into the correct directory (remember that the only ones that are actually used are the three important ones mentioned earlier. You can simply delete the other ones if you want).

2. Because of issues mentioned in the paper, we had to create a piecewise function to calculate how many known plaintexts are used given a bias. If some new linear approximation gives a bias which isn't defined in the function, it will likely return something nonsensical (it's a polynomial), and the code will likely not work. We realize this is a major problem but we ran out of time to fix it. If you want to play around with how to do this better, the function to modify is `get_num_plaintexts` in `spn.py`. The function takes in a bias `p` and calculates the minimum amount of plaintexts it needs to have a high probability of breaking the key. The current polynomial which you'll find in that function is based on a lot of trial and error.

## SPN
All of the SPN code can be found in the [spn.py](./spn.py) file:

1. `spn.py`

    To run this simply run `python3 spn.py`. The `main` function will run the step outlined in the paper and print out the broken keys. It takes ~1-2 min to break them, though it might be more or less depending on the machine, and depending on the order in which it tries the possible round keys.

    There are no command-line arguments. Instead, you can feel free to edit the following variables in the file directly:
    1. `KEY0` — array of nibbles (of length 4): the first round key
    2. `KEY1` — array of nibbles (of length 4): the second round key
    3. `KEY2` — array of nibbles (of length 4): the third round key
    4. `KEY3` — array of nibbles (of length 4): the fourth round key
    5. `KEY4` — array of nibbles (of length 4): the fifth round key

    You can also edit the variables below. However, you should read the `linear-approximations` section of this README before doing so:
    1. `SBOX` & `INV_SBOX` — array of nibbles (of length 16): the SBOX and INV_SBOX for the cipher. Make sure `INV_SBOX` is actually the inverse of `SBOX` if you make manual changes
    2. `PBOX` & `INV_PBOX` — array of nibbles (of length 16): the PBOX and INV_PBOX for the cipher. Make sure `INV_PBOX` is actually the inverse of `PBOX` if you make manual changes

    Some commented out KEYs are there if you want to test something different. Of course, you can also create your own, just make them the right size.

    If you run this and the keys aren't being broken correctly, just run it again. Differential cryptanalysis is probabilistic so it won't work everytime.
