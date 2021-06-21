from argon2pure import _compress

from argon2 import G

if __name__ == "__main__":
    X = bytes("ausdnaodsnaoidna8djs09asdj0aisnd", "utf-8")
    Y = bytes("suandiuab9sudna9osudnaoudnaoudna", "utf-8")
    R1 = _compress(X, Y)

    R2 = G(X,Y)

    assert R1 == R2
