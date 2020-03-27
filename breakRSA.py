#!/usr/bin/env python3
import sys
import numpy as np
from PrimeGenerator import *
from BitVector import *
from rsa import bgcd
from gmpy2 import root

# Author: Tanmay Prakash
#         tprakash at purdue dot edu
# Solve x^p = y for x
# for integer values of x, y, p
# Provides greater precision than x = pow(y,1.0/p)
# Example:
# >>> x = solve_pRoot(3,64)
# >>> x
# 4L
def solve_pRoot(p,y):
    p = int(p)
    y = int(y)
    # Initial guess for xk
    try:
        xk = int(pow(y, 1.0/p))
    except:
        # Necessary for larger value of y
        # Approximate y as 2^a * y0
        y0 = y
        a = 0
        while y0 > sys.float_info.max:
            y0 = y0 >> 1
            a += 1
        # log xk = log2 y / p
        # log xk = (a + log2 y0) / p
        xk = int(pow(2.0, (a + np.log2(float(y0)))/p))

    # Solve for x using Newton's Method
    err_k = int(pow(xk,p))-y
    while abs(err_k) > 1:
        gk = p*int(pow(xk, p-1))
        err_k = int(pow(xk, p))-y
        xk = int(-err_k/gk) + xk
    return xk


def key_generate():
    e = 3

    # generate p and q that satisfies all 3 conditions
    while True:
        p = PrimeGenerator(bits=128).findPrime()
        q = PrimeGenerator(bits=128).findPrime()
        if BitVector(intVal=p)[0] and BitVector(intVal=p)[0]:
            if p != q:
                if bgcd(p - 1, e) == bgcd(q - 1, e) == 1:
                    break

    n = p * q
    totient = (p - 1) * (q - 1)
    d = int(BitVector(intVal=e).multiplicative_inverse(BitVector(intVal=totient)))
    public_key = [e, n]
    private_key = [d, n]
    return public_key, private_key, p, q, d, n


def encrypt(infile, outfile, public_key):
    e, n = public_key

    bv_plaintext = BitVector(filename=infile)
    with open(outfile, "wb") as f:
        while bv_plaintext.more_to_read:
            block = bv_plaintext.read_bits_from_file(128)
            if block.length() != 128:
                block += BitVector(size=(128-block.length()))

            # padding 128 bit of 0s from left
            block = BitVector(size=128) + block
            # block cipher: encrypting by c = m^e % n
            c = BitVector(intVal=(pow(int(block), e, n)), size=256)
            # write output binary to file
            c.write_to_file(f)
    return


def CRT(int_block, p, q, d, n):
    Vp = pow(int_block, d, p)
    Vq = pow(int_block, d, q)
    Xp = q * int(BitVector(intVal=q).multiplicative_inverse(BitVector(intVal=p)))
    Xq = p * int(BitVector(intVal=p).multiplicative_inverse(BitVector(intVal=q)))
    return (Vp * Xp + Vq * Xq) % n


def decrypt(infile, outfile, p, q, d, n):
    with open(outfile, "wb") as f:
        bv_cipher = BitVector(filename=infile)
        while bv_cipher.more_to_read:
            block = bv_cipher.read_bits_from_file(256)
            int_decrypted = CRT(int(block), p, q, d, n)
            decrypted = BitVector(intVal=int_decrypted, size=256)[128:]
            decrypted.write_to_file(f)
    return


if __name__ == "__main__":
    public_key, _, p, q, d, n = key_generate()
    encrypt("message.txt", "encrypted0.txt", public_key)
    public_key1 = key_generate()[0]
    encrypt("message.txt", "encrypted1.txt", public_key1)
    public_key2 = key_generate()[0]
    encrypt("message.txt", "encrypted2.txt", public_key2)
    #
    # print(public_key)
    # print(public_key1)
    # print(public_key2)

    # calculate N; public_key = [e, n]
    N = public_key[1] * public_key1[1] * public_key2[1]
    N1 = public_key1[1] * public_key2[1]
    N2 = public_key[1] * public_key2[1]
    N3 = public_key[1] * public_key1[1]

    MI = int(BitVector(intVal=N1).multiplicative_inverse(BitVector(intVal=public_key[1])))
    MI1 = int(BitVector(intVal=N2).multiplicative_inverse(BitVector(intVal=public_key1[1])))
    MI2 = int(BitVector(intVal=N3).multiplicative_inverse(BitVector(intVal=public_key2[1])))

    bv = BitVector(filename="encrypted0.txt")
    bv1 = BitVector(filename="encrypted1.txt")
    bv2 = BitVector(filename="encrypted2.txt")
    with open("cracked.txt", "wb") as f:
        while bv.more_to_read:
            block = bv.read_bits_from_file(256)
            block1 = bv1.read_bits_from_file(256)
            block2 = bv2.read_bits_from_file(256)

            # CRT
            decrypted = (int(block) * N1 * MI + int(block1) * N2 * MI1 + int(block2) * N3 * MI2) % N
            # take cube root
            # print("number:", decrypted)
            decrypted1 = solve_pRoot(3, decrypted)
            # decrypted1 = int(root(decrypted, 3))
            # print("cube root:", decrypted1)
            # remove padding
            plain = BitVector(intVal=decrypted1, size=256)[128:]
            print("plain:", plain)
            plain.write_to_file(f)



    # decrypt("encrypted0.txt", "decrypted.txt", p, q, d, n)