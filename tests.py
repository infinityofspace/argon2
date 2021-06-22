import unittest
from binascii import hexlify
from hashlib import blake2b

import argon2

import argon
from blake import Blake2b


class Argon2dTest(unittest.TestCase):
    def test_simple(self):
        password = b"password"
        salt = b"salt1234"
        time_cost = 1
        memory_cost = 8
        parallelism = 1
        hash_len = 8
        argon_type = argon2.low_level.Type.D

        hash_c = argon2.hash_password_raw(
            password=password,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=argon_type
        )
        print(hexlify(hash_c))

        hash = argon.argon2(
            P=password,
            S=salt,
            p=parallelism,
            tau=hash_len,
            m=memory_cost,
            t=time_cost)
        print(hexlify(hash))

        assert hash_c == hash

    def test_time_cost(self):
        password = b"password"
        salt = b"salt1234"
        time_cost = 5
        memory_cost = 8
        parallelism = 1
        hash_len = 8
        argon_type = argon2.low_level.Type.D

        hash_c = argon2.hash_password_raw(
            password=password,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=argon_type
        )
        print(hexlify(hash_c))

        hash = argon.argon2(
            P=password,
            S=salt,
            p=parallelism,
            tau=hash_len,
            m=memory_cost,
            t=time_cost)
        print(hexlify(hash))

        assert hash_c == hash

    def test_hash_len(self):
        password = b"password"
        salt = b"salt1234"
        time_cost = 1
        memory_cost = 8
        parallelism = 1
        hash_len = 64
        argon_type = argon2.low_level.Type.D

        hash_c = argon2.hash_password_raw(
            password=password,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=argon_type
        )
        print(hexlify(hash_c))

        hash = argon.argon2(
            P=password,
            S=salt,
            p=parallelism,
            tau=hash_len,
            m=memory_cost,
            t=time_cost)
        print(hexlify(hash))

        assert hash_c == hash

    def test_memory_cost(self):
        password = b"password"
        salt = b"salt1234"
        time_cost = 1
        memory_cost = 16
        parallelism = 1
        hash_len = 64
        argon_type = argon2.low_level.Type.D

        hash_c = argon2.hash_password_raw(
            password=password,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=argon_type
        )
        print(hexlify(hash_c))

        hash = argon.argon2(
            P=password,
            S=salt,
            p=parallelism,
            tau=hash_len,
            m=memory_cost,
            t=time_cost)
        print(hexlify(hash))

        assert hash_c == hash


class Blake2bTest(unittest.TestCase):

    def test_simple(self):
        hash_std_lib = blake2b(b"abc").digest()
        print(hexlify(hash_std_lib))
        hash_own_impl = Blake2b.hash(b"abc")
        print(hexlify(hash_own_impl))

        assert hash_std_lib == hash_own_impl

    def test_message(self):
        hash_std_lib = blake2b(b"password123456").digest()
        print(hexlify(hash_std_lib))
        hash_own_impl = Blake2b.hash(b"password123456")
        print(hexlify(hash_own_impl))

        assert hash_std_lib == hash_own_impl

    def test_empty_message(self):
        hash_std_lib = blake2b(b"").digest()
        print(hexlify(hash_std_lib))
        hash_own_impl = Blake2b.hash(b"")
        print(hexlify(hash_own_impl))

        assert hash_std_lib == hash_own_impl

    # def test_key(self):
    #     hash_std_lib = blake2b(b"password", key=b"super-secret-key").digest()
    #     print(hexlify(hash_std_lib))
    #     hash_own_impl = Blake2b.hash(b"password", key=b"super-secret-key")
    #     print(hexlify(hash_own_impl))
    #
    #     assert hash_std_lib == hash_own_impl

    def test_lower_hash_len(self):
        hash_std_lib = blake2b(b"abc", digest_size=32).digest()
        print(hexlify(hash_std_lib))
        hash_own_impl = Blake2b.hash(b"abc", hash_length=32)
        print(hexlify(hash_own_impl))

        assert hash_std_lib == hash_own_impl

        hash_std_lib = blake2b(b"abc", digest_size=16).digest()
        print(hexlify(hash_std_lib))
        hash_own_impl = Blake2b.hash(b"abc", hash_length=16)
        print(hexlify(hash_own_impl))

        assert hash_std_lib == hash_own_impl

        hash_std_lib = blake2b(b"abc", digest_size=8).digest()
        print(hexlify(hash_std_lib))
        hash_own_impl = Blake2b.hash(b"abc", hash_length=8)
        print(hexlify(hash_own_impl))

        assert hash_std_lib == hash_own_impl

        hash_std_lib = blake2b(b"abc", digest_size=4).digest()
        print(hexlify(hash_std_lib))
        hash_own_impl = Blake2b.hash(b"abc", hash_length=4)
        print(hexlify(hash_own_impl))

        assert hash_std_lib == hash_own_impl

        hash_std_lib = blake2b(b"abc", digest_size=2).digest()
        print(hexlify(hash_std_lib))
        hash_own_impl = Blake2b.hash(b"abc", hash_length=2)
        print(hexlify(hash_own_impl))

        assert hash_std_lib == hash_own_impl

        hash_std_lib = blake2b(b"abc", digest_size=1).digest()
        print(hexlify(hash_std_lib))
        hash_own_impl = Blake2b.hash(b"abc", hash_length=1)
        print(hexlify(hash_own_impl))

        assert hash_std_lib == hash_own_impl


if __name__ == '__main__':
    unittest.main()
