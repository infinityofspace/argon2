from binascii import hexlify

from argon import argon2

if __name__ == "__main__":
    # paper recommends tag and salt length of 128 bits (16 bytes)
    password = b"password"
    salt = b"securesalt"
    time_cost = 2
    memory_cost = 16
    parallelism = 2
    hash_len = 128

    hash = argon2(
        P=password,
        S=salt,
        p=parallelism,
        tau=hash_len,
        m=memory_cost,
        t=time_cost,
        force_single_process=True)

    print(len(hash))
    print(hash)
    print(hexlify(hash))
