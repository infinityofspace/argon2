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
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
    ]

    R1 = np.uint64(32)
    R2 = np.uint64(24)
    R3 = np.uint64(16)
    R4 = np.uint64(63)

    w = 64
    r = 12

    @staticmethod
    def hash(message=b'', key=b'', hash_length=64):
        assert 0 <= len(message) <= 2 ** 128
        assert 0 <= len(key) <= 64
        assert 1 <= hash_length <= 64

        h = Blake2b.IV[0:8]
        h[0] = h[0] ^ 0x0000000001010000 ^ (len(key) << 8) ^ hash_length

        # add zero prepended key to message
        if key:
            message = b"\0" * (128 - len(key)) + message

        remaining = len(message) % 128

        size_counter = 0

        for start, end in enumerate(range(0, len(message) - remaining, 128)):
            chunk = message[start * 128:end + 128]
            size_counter += len(chunk)
            h = Blake2b._F(h, chunk, size_counter, False)

        # pad remaining unused message part to 128
        remaining_chunk = message[-remaining:]
        chunk = remaining_chunk + b"\0" * (128 - remaining)
        size_counter += len(remaining_chunk)
        h = Blake2b._F(h, chunk, size_counter, True)

        return struct.pack("<8Q", *h)[0:hash_length]

    @staticmethod
    def _G(v, a, b, c, d, x, y):
        v[a] = (v[a] + v[b] + x) % 2 ** Blake2b.w
        v[d] = Blake2b._rotate_xor(v[d] ^ v[a], Blake2b.R1)
        v[c] = (v[c] + v[d]) % 2 ** Blake2b.w
        v[b] = Blake2b._rotate_xor(v[b] ^ v[c], Blake2b.R2)

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
        v = h[0:8]
        v += Blake2b.IV[0:8]

        v[12] = v[12] ^ (t % (2 ** Blake2b.w))
        v[13] = v[13] ^ (t >> Blake2b.w)

        if f:
            v[14] = v[14] ^ 0xffffffffffffffff

        m = []
        for start, end in enumerate(range(0, 128, 8)):
            m.append(int.from_bytes(c[start * 8: end + 8], "little"))

        for i in range(Blake2b.r):
            s = Blake2b.SIGMA[i % 10][0:16]

            v = Blake2b._G(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            v = Blake2b._G(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            v = Blake2b._G(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            v = Blake2b._G(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            v = Blake2b._G(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            v = Blake2b._G(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            v = Blake2b._G(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            v = Blake2b._G(v, 3, 4, 9, 14, m[s[14]], m[s[15]])

        for i in range(8):
            h[i] = h[i] ^ v[i] ^ v[i + 8]

        return h[0:8]
