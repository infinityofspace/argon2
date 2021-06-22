from binascii import hexlify

from argon import argon2

if __name__ == "__main__":
    # paper recommends tag and salt length of 128 bits (16 bytes)
    password = b"password"
    salt = b"yMff87RYR9oaYb0e"
    time_cost = 16
    memory_cost = 8
    parallelism = 1
    hash_len = 16

    hash = argon2(
        P=password,
        S=salt,
        p=parallelism,
        tau=hash_len,
        m=memory_cost,
        t=time_cost)

    print(len(hash))
    print(hash)
    print(hexlify(hash))
