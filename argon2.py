import math
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

    b = blake2b(digest_size=tau)
    b.update(h)
    H_0 = b.digest()
    print(H_0)

    # create the B matrix
    q = int(math.floor((m / 4 * p) * 4 * p) / p)
    B = [[None for _ in range(q)] for _ in range(p)]

    for i in range(p):
        B[i][0] = H(H_0 + b'\x00\x00\x00\x00' + i.to_bytes(4, byteorder="little"), 1024)
        B[i][1] = H(H_0 + b'\x01\x00\x00\x00' + i.to_bytes(4, byteorder="little"), 1024)

    for i in range(p):
        for j in range(q):
            B[i][j] = G(B[i][j - 1], B[i][j])

    for _ in range(2, t):
        for i in range(p):
            for j in range(q):
                B[i][j] = G(B[i][j - 1], B[i][j])

    # calculate xor of the last column
    B_final = B[0][q - 1]
    for i in range(1, p):
        B_final = np.xor(B_final, B_final[i][q - 1])

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

        for i in range(2, r):
            b = blake2b(digest_size=64)
            b.update(V_i)
            V_i = b.digest()
            A += V_i[:32]

        # now hash the last partially remaining block
        b = blake2b(digest_size=tau - 32 * r)
        b.update(V_i)
        V_i = b.digest()
        A += V_i[:32]

        return A + V_i


def G(X: bytes, Y: bytes):
    """

    :param X: 1024 byte block
    :param Y: 1024 byte block
    :return:
    """

    R = np.xor(X, Y)

    return np.xor(Z, R)


def P(S_0, S_1, S_2, S_3, S_4, S_5, S_6, S_7):
    class Number:
        def __init__(self, number: int):
            self.number = number

        def __add__(self, other):
            if isinstance(other, Number):
                return (self.number + other.number) % (2 ** 64)
            else:
                return (self.number + other) % (2 ** 64)

        def __rshift__(self, other):
            return self.number >> other

        def __mul__(self, other):
            if isinstance(other, Number):
                return self.number * other.number
            else:
                return self.number * other

        def __getitem__(self, s):
            return self.number.to_bytes(8, byteorder="little")[s]

    def G(a, b, c, d):
        a = Number(a)
        b = Number(b)
        c = Number(c)
        d = Number(d)

        a = a + b + 2 * a[:32] * b[:32]
        d = np.xor(d, a) >> 32
        c = c + d + 2 * c[:32] * d[:32]
        b = np.xor(b, c) >> 24
        a = a + b + 2 * a[:32] * b[:32]
        d = np.xor(d, a) >> 16
        c = c + d + 2 * c[:32] * d[:32]
        b = np.xor(b, c) >> 63
        return a, b, c, d


if __name__ == "__main__":
    import argon2pure
    from binascii import hexlify

    my_res = argon2(P=b"mypassword",
                    S=b"mysecretsalt",
                    p=1,
                    tau=32,
                    m=8,
                    t=1)
    print(hexlify(my_res))

    lib_res = argon2pure.argon2(b'mypassword',
                                b'mysecretsalt',
                                time_cost=1,
                                memory_cost=8,
                                parallelism=1,
                                tag_length=32)

    print(hexlify(lib_res))

    print(my_res == lib_res)
