import struct

import numpy as np


class Blake2b:
    """
    The implementation follows the specification of Blake2b described in https://www.blake2.net/blake2.pdf
    """

    SIGMA = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ]

    IV = [
        0x6A09E667F3BCC908,
        0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1,
        0x510E527FADE682D1,
        0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B,
        0x5BE0CD19137E2179
    ]

    R1 = np.uint64(32)
    R2 = np.uint64(24)
    R3 = np.uint64(16)
    R4 = np.uint64(63)

    w = 64
    r = 12

    @staticmethod
    def hash(message: bytes = b'', hash_length: int = 64):
        """
        Hashes the message with Blake2b to the desired hash length.

        :param message: bytes of message to be hashed
        :param hash_length: length of the resulting hash, can be any value from 1 to 64

        :return: hash of message with length of hash_length
        """

        assert 0 <= len(message) <= 2 ** 128
        assert 1 <= hash_length <= 64

        # init state vector h with IV values
        h = Blake2b.IV[0:8]
        # mix the first state vector entry with hash_length
        h[0] = h[0] ^ 0x0000000001010000 ^ hash_length

        size_counter = 0

        # remaining chunk size when message is divided into 128 chunks
        remaining = len(message) % 128

        # hash each 128 bytes chunk
        for start, end in enumerate(range(0, len(message) - remaining, 128)):
            chunk = message[start * 128:end + 128]
            size_counter += len(chunk)
            h = Blake2b._F(h, chunk, size_counter, False)

        # pad remaining unused message part to 128 bytes
        remaining_chunk = message[-remaining:]
        chunk = remaining_chunk + b"\0" * (128 - remaining)
        size_counter += len(remaining_chunk)
        # hash the last padded chunk
        h = Blake2b._F(h, chunk, size_counter, True)

        # return the desired hash_length size from the state vector h
        return struct.pack("<8Q", *h)[0:hash_length]

    @staticmethod
    def _G(v, a, b, c, d, x, y):
        """
        Mix the given state vector v entries at index a, b, c, d with offset x and y.

        :param v: state vector
        :param a: index one
        :param b: index two
        :param c: index three
        :param d: index four
        :param x: first offset used by mixing
        :param y: second offset used by mixing

        :return: updated state vector
        """

        # mix values with offset x
        v[a] = (v[a] + v[b] + x) % 2 ** Blake2b.w
        v[d] = Blake2b._rotate_xor(v[d] ^ v[a], Blake2b.R1)
        v[c] = (v[c] + v[d]) % 2 ** Blake2b.w
        v[b] = Blake2b._rotate_xor(v[b] ^ v[c], Blake2b.R2)

        # mix values with offset y
        v[a] = (v[a] + v[b] + y) % 2 ** Blake2b.w
        v[d] = Blake2b._rotate_xor(v[d] ^ v[a], Blake2b.R3)
        v[c] = (v[c] + v[d]) % 2 ** Blake2b.w
        v[b] = Blake2b._rotate_xor(v[b] ^ v[c], Blake2b.R4)

        return v

    @staticmethod
    def _rotate_xor(x, r):
        x = np.uint64(x)
        return int((x >> r) ^ (x << (np.uint64(64) - r)))

    @staticmethod
    def _F(h, c, t, f):
        """
        Compression function.

        :param h: current state vector
        :param c: chunk which should be used
        :param t: length of the real data inside the chunk
        :param f: bool if the chunk is the last chunk from the message

        :return: updated state vector h
        """

        # init temporary state vector v
        v = h[0:8]
        v += Blake2b.IV[0:8]

        # mix entries 12 and 13 with the chunk data size and 64
        v[12] = v[12] ^ (t % (2 ** Blake2b.w))
        v[13] = v[13] ^ (t >> Blake2b.w)

        # check if the last chunk is used
        if f:
            v[14] = v[14] ^ 0xffffffffffffffff

        # split chunk into 16 x 8 bytes parts
        m = []
        for start, end in enumerate(range(0, 128, 8)):
            m.append(int.from_bytes(c[start * 8: end + 8], "little"))

        # do the 12 rounds mix
        for i in range(Blake2b.r):
            # get the offset which is used in _G from SIGMA
            s = Blake2b.SIGMA[i % 10][0:16]

            # mix the temporary state vector with the mix function G
            v = Blake2b._G(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            v = Blake2b._G(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            v = Blake2b._G(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            v = Blake2b._G(v, 3, 7, 11, 15, m[s[6]], m[s[7]])

            v = Blake2b._G(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            v = Blake2b._G(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            v = Blake2b._G(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            v = Blake2b._G(v, 3, 4, 9, 14, m[s[14]], m[s[15]])

        # finally mix
        for i in range(8):
            h[i] = h[i] ^ v[i] ^ v[i + 8]

        return h[0:8]
