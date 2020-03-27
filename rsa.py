#!/usr/bin/env python

import sys
from PrimeGenerator import *
from BitVector import *


# lecture 5 gcd algorithm
def bgcd(a, b):
    if a == b: return a  # (A)
    if a == 0: return b  # (B)
    if b == 0: return a  # (C)
    if (~a & 1):  # (D)
        if (b & 1):  # (E)
            return bgcd(a >> 1, b)  # (F)
        else:  # (G)
            return bgcd(a >> 1, b >> 1) << 1  # (H)
    if (~b & 1):  # (I)
        return bgcd(a, b >> 1)  # (J)
    if (a > b):  # (K)
        return bgcd((a - b) >> 1, b)  # (L)
    return bgcd((b - a) >> 1, a)  # (M)


def key_generate():
    e = 65537

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

    # key arrangement is p q e d n
    with open("p.txt", "w") as f:
        f.write(str(p))
    with open("q.txt", "w") as f:
        f.write(str(q))
    with open("e.txt", "w") as f:
        f.write(str(e))
    with open("d.txt", "w") as f:
        f.write(str(d))
    with open("n.txt", "w") as f:
        f.write(str(n))

    return public_key, private_key


def encrypt(infile, outfile):
    # key_generate()
    public_key, _ = key_generate()
    e, n = public_key

    bv_plaintext = BitVector(filename=infile)
    with open(outfile, "a") as f_hex, open("encrypted_binary.txt", "ab") as f_bin:
        while bv_plaintext.more_to_read:
            block = bv_plaintext.read_bits_from_file(128)
            if block.length() != 128:
                block += BitVector(size=(128-block.length()))

            # padding 128 bit of 0s from left
            block = BitVector(size=128) + block
            # block cipher: encrypting by c = m^e % n
            c = BitVector(intVal=(pow(int(block), e, n)), size=256)
            # write to file binary and hexstring
            c.write_to_file(f_bin)
            f_hex.write(c.get_bitvector_in_hex())

    return


def CRT(int_block, p, q, d, n):
    Vp = pow(int_block, d, p)
    Vq = pow(int_block, d, q)
    Xp = q * int(BitVector(intVal=q).multiplicative_inverse(BitVector(intVal=p)))
    Xq = p * int(BitVector(intVal=p).multiplicative_inverse(BitVector(intVal=q)))
    return (Vp * Xp + Vq * Xq) % n


def decrypt(infile, outfile):
    with open("p.txt", "r") as pf, open("q.txt", "r") as qf, open("d.txt", "r") as df, open("n.txt", "r") as nf:
        p = int(pf.read())
        q = int(qf.read())
        d = int(df.read())
        n = int(nf.read())

    with open(outfile, "ab") as f:
        bv_cipher = BitVector(filename=infile)
        while bv_cipher.more_to_read:
            block = bv_cipher.read_bits_from_file(256)
            int_decrypted = CRT(int(block), p, q, d, n)
            decrypted = BitVector(intVal=int_decrypted, size=256)[128:]
            decrypted.write_to_file(f)
    return


if __name__ == "__main__":
    # if len(sys.argv) != 4 or sys.argv[1] != "-e" or sys.argv[1] != "-d":
    #     print(len(sys.argv))
    #     print("0:", sys.argv[0], "1:", sys.argv[1], "2:", sys.argv[2], "3:", sys.argv[3])
    #     sys.exit("error")
    # if sys.argv[1] == "-e":
    #     encrypt(sys.argv[2], sys.argv[3])
    # else:
    #     decrypt(sys.argv[2], sys.argv[3])

    # -e message.txt encrypted.txt
    # -d encrypted.txt decrypted.txt
    import os
    if os.path.isfile("encrypted_binary.txt"):
        os.remove("encrypted_binary.txt")
    encrypt("message.txt", "encrypted.txt")

    if os.path.isfile("decrypted.txt"):
        os.remove("decrypted.txt")
    if os.path.isfile("decrypted_hex.txt"):
        os.remove("decrypted_hex.txt")
    decrypt("encrypted_binary.txt", "decrypted.txt")

