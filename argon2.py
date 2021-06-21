import math
from binascii import hexlify
from hashlib import blake2b

import numpy as np


def argon2(P: bytes,
           S: bytes,
           p: int,
           tau: int,
           m: int,
           t: int,
           v: int = 16,
           K: bytes = b"",
           X: bytes = b"",
           y: int = 0):
    """

    :param P: Message can have any length from 0 to 2^32 − 1 bytes
    :param S: Nonce can have any length from 8 to 2^32 − 1 bytes
    :param p: Degree of parallelism determines how many independent (but synchronizing) computational chains can be run.
              It can be any integer value from 1 to 2^24 − 1
    :param tau: Length of output. It can be any integer number of bytes from 4 to 2^32 − 1
    :param m: Memory size can be any integer number of kilobytes from 8p to 2^32 − 1 (p: degree of parallelism)
    :param t: Number of iterations can be any integer number from 1 to 2^32 − 1
    :param v: version number one byte 0x10
    :param K: Secret value can have any length from 0 to 32 bytes
    :param X: Associated data can have any length from 0 to 2^32 − 1 bytes
    :param y: Argon Type:
                - for Argon2d: 0
                - for Argon2i: 1

    :return:
    """

    # check the required conditions:
    # message length: 0 to 2^32 − 1 bytes
    assert 0 <= len(P) < 2 ** 32
    # salt/nonce: 8 to 2^32 − 1 bytes
    assert 8 <= len(S) < 2 ** 32
    # parallelism degree: 1 to 2^24 − 1
    assert 1 <= p < 2 ** 24
    # output length: 4 to 2^32 − 1
    assert 4 <= tau < 2 ** 32
    # memory size: 8p to 2^32 − 1 (p: degree of parallelism)
    assert 8 * p <= m < 2 ** 32
    # iterations: 1 to 2^32 − 1
    assert 1 <= t < 2 ** 32
    # argon2 version: 16
    assert v == 16
    # secret value length: 0 to 32 bytes
    assert 0 <= len(K) <= 32
    # associated data length: 0 to 2^32 − 1 bytes
    assert 0 <= len(X) < 2 ** 32

    # create first H_0 block
    h = p.to_bytes(4, byteorder="little") \
        + tau.to_bytes(4, byteorder="little") \
        + m.to_bytes(4, byteorder="little") \
        + t.to_bytes(4, byteorder="little") \
        + v.to_bytes(4, byteorder="little") \
        + y.to_bytes(4, byteorder="little")

    h += len(P).to_bytes(4, byteorder="little") + P
    h += len(S).to_bytes(4, byteorder="little") + S
    h += len(K).to_bytes(4, byteorder="little") + K
    h += len(X).to_bytes(4, byteorder="little") + X

    b = blake2b(digest_size=64)
    b.update(h)
    H_0 = b.digest()

    # create the B matrix
    m_p = math.floor(m / 4 * p) * 4 * p
    q = int(m_p / p)
    B = [[None for _ in range(q)] for _ in range(p)]

    for i in range(0, p):
        B[i][0] = H(H_0 + b'\0\0\0\0' + i.to_bytes(4, byteorder="little"), 1024)
        B[i][1] = H(H_0 + b'\1\0\0\0' + i.to_bytes(4, byteorder="little"), 1024)

    # this value is named S in the paper; renamed to not override nonce S
    N_VERT_SLICES = 4
    segment_length = int(q / N_VERT_SLICES)

    for r in range(0, t):
        vert_slice_start = 0
        if r == 0:
            vert_slice_start = 1
        for vert_slice in range(vert_slice_start, N_VERT_SLICES):
            for i in range(0, p):
                # i is the absolute row index
                for segment_col_idx in range(segment_length):
                    # segment_col_idx is the local column index inside the segement

                    # calculate the absolute col idx j from the internal segment column idx
                    j = vert_slice * segment_length + segment_col_idx

                    if y == 0:
                        # Argon2d
                        J_1 = int.from_bytes(B[i][(j - 1) % q][:32], "little")
                        J_2 = int.from_bytes(B[i][(j - 1) % q][32:], "little")
                    elif y == 1:
                        # Argon2i
                        pass

                    # mapping J_1 and J_2 to the reference block index
                    # i_p is named l for the lane in the paper
                    if r == 0 and vert_slice == 0:
                        i_p = i
                    else:
                        i_p = J_2 % p

                    # start and end are mark the set of indices used for determining
                    # the reference block (in the paper it is named R)
                    # (see 3.3 mapping indices in th paper)
                    end = 0

                    if r == 0:
                        start = 0

                        # first iteration
                        if i == i_p:
                            end = vert_slice * segment_length * segment_col_idx - 1
                        else:
                            if segment_col_idx == 0:
                                end = vert_slice * segment_length - 1
                            else:
                                end = vert_slice * segment_length
                    else:
                        start = ((vert_slice + 1) * segment_length) % q

                        # current lane is l
                        if i == i_p:
                            end = q - segment_length + segment_col_idx - 1
                        else:
                            if segment_col_idx == 0:
                                end = q - segment_length + segment_col_idx - 1
                            else:
                                end = q - segment_length

                    x = (J_1 ** 2) / (2 ** 32)
                    y = (end * x) / (2 ** 32)
                    z = end - 1 - y
                    j_p = int((start + z) % q)

                    if r == 0:
                        B[i][j] = C(B[i][j - 1], B[i_p][j_p])
                    else:
                        if j == 0:
                            # use column number for the index of one of the block
                            B[i][j] = xor(C(B[i][q - 1], B[i_p][j_p]), B[i][j])
                        else:
                            B[i][j] = xor(C(B[i][j - 1], B[i_p][j_p]), B[i][j])

    # calculate xor of the last column
    B_final = B[0][q - 1]
    for i in range(0, p):
        B_final = xor(B_final, B[i][q - 1])

    return H(B_final, tau)


def H(X: bytes, tau: int) -> bytes:
    if tau <= 64:
        b = blake2b(digest_size=tau)
        b.update(tau.to_bytes(4, byteorder="little") + X)
        return b.digest()
    else:
        # generate 64 byte blocks
        r = math.ceil(tau / 32) - 2

        b = blake2b(digest_size=64)
        b.update(tau.to_bytes(4, byteorder="little") + X)
        V_i = b.digest()

        A = V_i[:32]

        for i in range(1, r):
            b = blake2b(digest_size=64)
            b.update(V_i)
            V_i = b.digest()
            A += V_i[:32]

        # now hash the last partially remaining block
        b = blake2b(digest_size=tau - 32 * r)
        b.update(V_i)
        V_i = b.digest()
        # add the whole hashed value not only the first 32 bytes
        A += V_i

        return A


def xor(x, y):
    x = int.from_bytes(x, byteorder="little")
    y = int.from_bytes(y, byteorder="little")
    z = x ^ y
    return z.to_bytes(1024, byteorder="little")


def C(X: bytes, Y: bytes):
    """
    Compression function.

    :param X: 1024 byte block
    :param Y: 1024 byte block
    :return:
    """

    R = xor(X, Y)

    Q = []

    for k in range(0, 1024, 128):
        S = []
        for i in range(k, k + 128, 16):
            S.append(R[i: i + 16])
        Q.extend(argon2pure._P(*S))

    Z = []
    for i in range(8):
        S = []
        for k in range(i, 64, 8):
            S.append(Q[k])
        Z.append(argon2pure._P(*S))

    Z = np.array(Z).flatten("F")

    return xor(Z, R)


def P(S_0, S_1, S_2, S_3, S_4, S_5, S_6, S_7):
    # S_i = v_{2*i+1} || v_{2*i}

    #  v_0  v_1  v_2  v_3
    #  v_4  v_5  v_6  v_7
    #  v_8  v_9 v_10 v_11
    # v_12 v_13 v_14 v_15

    # S_0 = v_1 || v_0
    # S_1 = v_3 || v_2
    # S_2 = v_5 || v_4
    # S_3 = v_7 || v_6
    # S_4 = v_9 || v_8
    # S_5 = v_11 || v_10
    # S_6 = v_13 || v_12
    # S_7 = v_15 || v_14

    v_0 = int.from_bytes(S_0[:8], "little")
    v_1 = int.from_bytes(S_0[8:], "little")
    v_2 = int.from_bytes(S_1[:8], "little")
    v_3 = int.from_bytes(S_1[8:], "little")
    v_4 = int.from_bytes(S_2[:8], "little")
    v_5 = int.from_bytes(S_2[8:], "little")
    v_6 = int.from_bytes(S_3[:8], "little")
    v_7 = int.from_bytes(S_3[8:], "little")
    v_8 = int.from_bytes(S_4[:8], "little")
    v_9 = int.from_bytes(S_4[8:], "little")
    v_10 = int.from_bytes(S_5[:8], "little")
    v_11 = int.from_bytes(S_5[8:], "little")
    v_12 = int.from_bytes(S_6[:8], "little")
    v_13 = int.from_bytes(S_6[8:], "little")
    v_14 = int.from_bytes(S_7[:8], "little")
    v_15 = int.from_bytes(S_7[8:], "little")

    def _G(a, b, c, d):
        # lowest 32 bits mask 0xffffffff for an int
        # TODO: fix
        a = (a + b + 2 * (a & 0xffffffff) * (b & 0xffffffff)) % (2 ** 64)
        d = np.bitwise_xor(d, a) >> 32
        c = (c + d + 2 * (c & 0xffffffff) * (d & 0xffffffff)) % (2 ** 64)
        b = np.bitwise_xor(b, c) >> 24

        a = (a + b + 2 * (a & 0xffffffff) * (b & 0xffffffff)) % (2 ** 64)
        d = np.bitwise_xor(d, a) >> 16
        c = (c + d + 2 * (c & 0xffffffff) * (d & 0xffffffff)) % (2 ** 64)
        b = np.bitwise_xor(b, c) >> 63
        return a, b, c, d

    v_0, v_4, v_8, v_12 = _G(v_0, v_4, v_8, v_12)
    v_1, v_5, v_9, v_13 = _G(v_1, v_5, v_9, v_13)
    v_2, v_6, v_10, v_14 = _G(v_2, v_6, v_10, v_14)
    v_3, v_7, v_11, v_15 = _G(v_3, v_7, v_11, v_15)

    v_0, v_5, v_10, v_15 = _G(v_0, v_5, v_10, v_15)
    v_1, v_6, v_11, v_12 = _G(v_1, v_6, v_11, v_12)
    v_2, v_7, v_8, v_13 = _G(v_2, v_7, v_8, v_13)
    v_3, v_4, v_9, v_14 = _G(v_3, v_4, v_9, v_14)

    return np.array([v_0, v_1]), \
           np.array([v_2, v_3]), \
           np.array([v_4, v_5]), \
           np.array([v_6, v_7]), \
           np.array([v_8, v_9]), \
           np.array([v_10, v_11]), \
           np.array([v_12, v_13]), \
           np.array([v_14, v_15])


if __name__ == "__main__":
    import argon2pure

    X = bytes("a" * 1024, "utf8")
    Y = bytes("b" * 1024, "utf8")

    my_res = argon2(P=b"mypassword",
                    S=b"mysecretsalt",
                    p=1,
                    tau=8,
                    m=8,
                    t=1)
    print(hexlify(my_res))

    lib_res = argon2pure.argon2(b'mypassword',
                                b'mysecretsalt',
                                time_cost=1,
                                memory_cost=8,
                                parallelism=1,
                                tag_length=8,
                                type_code=argon2pure.ARGON2D)
    print(hexlify(lib_res))

    print(my_res == lib_res)
