# Argon2d

The argon.py file contains the Argon2d password hashing algorithm in version 19 and uses Blake2 inside the hash function
H.

## Usage

The algorithm code requires `numpy` to run. Moreover, the test cases and the benchmarks requires `matplotlib`
and `argon2_cffi`.

The required python version is 3.6+.

Clone the project:

```commandline
git clone https://github.com/infinityofspace/argon2.git
```

You can install everything with:

```commandline
pip install -r requirements.txt
```

The file `simple_test.py` contains a simple usage example how to use the implementation.

## Benchmarks

The file `bechnmark.py` provides the following compute time benchmarks categories:

- multiprocessing vs single process
- hash length and compute time
- this implementation vs C CFFI lib provided by argon2_cffi 

## License

This project is licensed under the MIT License - see the [License](License) file for details.
