import math
from itertools import repeat
from multiprocessing import Pool

import numpy as np

from blake import Blake2b


def argon2(P: bytes,
           S: bytes,
           p: int,
           tau: int,
           m: int,
           t: int,
           V: int = 19,
           K: bytes = b"",
           X: bytes = b"",
           Y: int = 0,
           force_single_process=False):
    """

    :param P: Message can have any length from 0 to 2^32 − 1 bytes
    :param S: Nonce can have any length from 8 to 2^32 − 1 bytes
    :param p: Degree of parallelism determines how many independent (but synchronizing) computational chains can be run.
              It can be any integer value from 1 to 2^24 − 1
    :param tau: Length of output. It can be any integer number of bytes from 4 to 2^32 − 1
    :param m: Memory size can be any integer number of kilobytes from 8p to 2^32 − 1 (p: degree of parallelism)
    :param t: Number of iterations can be any integer number from 1 to 2^32 − 1
    :param V: version number 19
    :param K: Secret value can have any length from 0 to 32 bytes
    :param X: Associated data can have any length from 0 to 2^32 − 1 bytes
    :param Y: Argon Type:
                - for Argon2d: 0
                - for Argon2i: 1

    :param force_single_process: custom argument for benchmarking

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
    # argon2 version: 19
    assert V == 19
    # secret value length: 0 to 32 bytes
    assert 0 <= len(K) <= 32
    # associated data length: 0 to 2^32 − 1 bytes
    assert 0 <= len(X) < 2 ** 32

    # create first H_0 block
    h = p.to_bytes(4, byteorder="little") \
        + tau.to_bytes(4, byteorder="little") \
        + m.to_bytes(4, byteorder="little") \
        + t.to_bytes(4, byteorder="little") \
        + V.to_bytes(4, byteorder="little") \
        + Y.to_bytes(4, byteorder="little")

    h += len(P).to_bytes(4, byteorder="little") + P
    h += len(S).to_bytes(4, byteorder="little") + S
    h += len(K).to_bytes(4, byteorder="little") + K
    h += len(X).to_bytes(4, byteorder="little") + X

    H_0 = Blake2b.hash(h, hash_length=64)

    # create the B matrix
    m_p = math.floor(m / (4 * p)) * 4 * p
    q = int(m_p / p)
    B = [[None for _ in range(q)] for _ in range(p)]

    # generate the first 2 columns
    for i in range(0, p):
        B[i][0] = H(H_0 + b'\0\0\0\0' + i.to_bytes(4, byteorder="little"), 1024)
        B[i][1] = H(H_0 + b'\1\0\0\0' + i.to_bytes(4, byteorder="little"), 1024)

    # this value is named S in the paper; renamed to not override nonce S
    N_VERT_SLICES = 4
    segment_length = int(q / N_VERT_SLICES)

    if p > 1 and not force_single_process:
        multiprocessing_pool = Pool(processes=p)

    for r in range(0, t):
        for vert_slice in range(0, N_VERT_SLICES):
            if p > 1 and not force_single_process:
                # run the block update for each segment in an own process
                args = repeat(vert_slice), repeat(segment_length), repeat(r), repeat(Y), repeat(p), repeat(q), repeat(B)
                segm_updates = multiprocessing_pool.starmap(update_segment, zip(range(0, p), *args))

                # update B matrix in them main process
                for update in segm_updates:
                    if update:
                        B_new, idxs = update
                        for i, j in idxs:
                            B[i][j] = B_new[i][j]
            else:
                for i in range(0, p):
                    # drop the return value since we dont have to merge the results
                    update_segment(i, vert_slice, segment_length, r, Y, p, q, B)

    if p > 1 and not force_single_process:
        multiprocessing_pool.close()

    # calculate xor of the last column
    B_final = B[0][q - 1]
    for i in range(1, p):
        B_final = xor(B_final, B[i][q - 1])

    return H(B_final, tau)


def update_segment(i, vert_slice, segment_length, r, Y, p, q, B):
    """
    Updates all column in the segment, this function can run in an own process/thread
    because the B matrix segments are independent.
    """

    block_idxs = []
    # update each column of the segment
    for segment_col_idx in range(segment_length):
        j = vert_slice * segment_length + segment_col_idx
        # in the first round we do not need update the first to column, so skip them
        if (r == 0 and j >= 2) or r > 0:
            block_idxs.append((i, j))
            update_block(j, segment_length, segment_col_idx, vert_slice, r, Y, i, p, q, B)

    if len(block_idxs) > 0:
        return B, block_idxs


def update_block(j, segment_length, segment_col_idx, vert_slice, r, Y, i, p, q, B):
    """
    Update the given block with indices i,j
    """

    if Y == 0:
        if not B[i][(j - 1)]:
            print(1)
        # Argon2d
        J_1 = int.from_bytes(B[i][(j - 1)][:4], "little")
        J_2 = int.from_bytes(B[i][(j - 1)][4:8], "little")
    elif Y == 1:
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
    if r == 0:
        start = 0

        # first iteration
        if i == i_p:
            end = j - 1
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
                end = q - segment_length - 1
            else:
                end = q - segment_length

    x = int((J_1 ** 2) / (2 ** 32))
    y = int((end * x) / (2 ** 32))
    z = end - 1 - y
    j_p = int((start + z) % q)

    if r == 0:
        # for the first round we only need the compress function
        B[i][j] = C(B[i][j - 1], B[i_p][j_p])
    else:
        B[i][j] = xor(C(B[i][j - 1], B[i_p][j_p]), B[i][j])


def H(X: bytes, tau: int) -> bytes:
    """
     Custom Argon2 hash function. Uses internal the Blake2b hash function.
    """

    if tau <= 64:
        return Blake2b.hash(tau.to_bytes(4, byteorder="little") + X, hash_length=tau)
    else:
        # generate 64 byte blocks
        r = math.ceil(tau / 32) - 2

        V_i = Blake2b.hash(tau.to_bytes(4, byteorder="little") + X, hash_length=64)

        A = V_i[:32]

        for i in range(1, r):
            V_i = Blake2b.hash(V_i, hash_length=64)
            A += V_i[:32]

        # now hash the last partially remaining block
        V_i = Blake2b.hash(V_i, hash_length=tau - 32 * r)
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
    :return: compression of X and Y
    """

    R = xor(X, Y)

    Q = []

    for k in range(0, 1024, 128):
        S = []
        for i in range(k, k + 128, 16):
            S.append(R[i: i + 16])
        Q.extend(P(*S))

    Z = []
    for i in range(8):
        S = []
        for k in range(i, 64, 8):
            S.append(Q[k])
        Z.append(P(*S))

    Z = np.array(Z).flatten("F")

    return xor(Z, R)


def P(S_0, S_1, S_2, S_3, S_4, S_5, S_6, S_7):
    """
    Permutation function P.
    """

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
        """
        Mixing function G based on Blake2b mix function G.
        """

        a = (a + b + 2 * (a & 0xffffffff) * (b & 0xffffffff)) % (2 ** 64)
        d = rotate_xor((d ^ a) % (2 ** 64), 32)
        c = (c + d + 2 * (c & 0xffffffff) * (d & 0xffffffff)) % (2 ** 64)
        b = rotate_xor((b ^ c) % (2 ** 64), 24)

        a = (a + b + 2 * (a & 0xffffffff) * (b & 0xffffffff)) % (2 ** 64)
        d = rotate_xor((d ^ a) % (2 ** 64), 16)
        c = (c + d + 2 * (c & 0xffffffff) * (d & 0xffffffff)) % (2 ** 64)
        b = rotate_xor((b ^ c) % (2 ** 64), 63)

        return a, b, c, d

    v_0, v_4, v_8, v_12 = _G(v_0, v_4, v_8, v_12)
    v_1, v_5, v_9, v_13 = _G(v_1, v_5, v_9, v_13)
    v_2, v_6, v_10, v_14 = _G(v_2, v_6, v_10, v_14)
    v_3, v_7, v_11, v_15 = _G(v_3, v_7, v_11, v_15)

    v_0, v_5, v_10, v_15 = _G(v_0, v_5, v_10, v_15)
    v_1, v_6, v_11, v_12 = _G(v_1, v_6, v_11, v_12)
    v_2, v_7, v_8, v_13 = _G(v_2, v_7, v_8, v_13)
    v_3, v_4, v_9, v_14 = _G(v_3, v_4, v_9, v_14)

    v_0 = v_0.to_bytes(8, byteorder="little")
    v_1 = v_1.to_bytes(8, byteorder="little")
    v_2 = v_2.to_bytes(8, byteorder="little")
    v_3 = v_3.to_bytes(8, byteorder="little")
    v_4 = v_4.to_bytes(8, byteorder="little")
    v_5 = v_5.to_bytes(8, byteorder="little")
    v_6 = v_6.to_bytes(8, byteorder="little")
    v_7 = v_7.to_bytes(8, byteorder="little")
    v_8 = v_8.to_bytes(8, byteorder="little")
    v_9 = v_9.to_bytes(8, byteorder="little")
    v_10 = v_10.to_bytes(8, byteorder="little")
    v_11 = v_11.to_bytes(8, byteorder="little")
    v_12 = v_12.to_bytes(8, byteorder="little")
    v_13 = v_13.to_bytes(8, byteorder="little")
    v_14 = v_14.to_bytes(8, byteorder="little")
    v_15 = v_15.to_bytes(8, byteorder="little")

    return v_0 + v_1, \
           v_2 + v_3, \
           v_4 + v_5, \
           v_6 + v_7, \
           v_8 + v_9, \
           v_10 + v_11, \
           v_12 + v_13, \
           v_14 + v_15


def rotate_xor(x, r):
    x = np.uint64(x)
    r = np.uint64(r)
    return int((x >> r) ^ (x << (np.uint64(64) - r)))
