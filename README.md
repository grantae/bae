# Bae: Basic Authenticated Encryption

Also known as *Blob Authenticated Encryption*


Bae is a simple C++ interface to encrypt data with powerful modern encryption.
It supports symmetric encryption with authenticated AES (using Galois counter
mode) with 256-bit keys and 128-bit tags. It also provides password-based key
derivation with PBKDF2/SHA256.

Bae is built upon [Blobs](https://github.com/grantae/blob) for simple data
management and uses well-established crypto libraries (currently
[cryptopp](https://github.com/weidai11/cryptopp)), but its interface
is library-independent.

## Quick Start

1. Clone the repo: `git clone https://github.com/grantae/bae.git`.
2. Build and test: `make test`.

Alternatively you can copy the directory `src/crypto` to your project
(as well as any needed dependent files in the `external` directory).

## Example usage

See [main.cc](https://github.com/grantae/bae/blob/master/src/main.cc)
for examples.

## Requirements

* A C++11 (or later) compiler
* [GMP](https://gmplib.org) (GNU Multiple Precision Arithmetic Library) for
data conversion routines (e.g. to base 58).
* [GNU Make](https://www.gnu.org/software/make/) is required to build the
example code and tests.

The project will download and build the following additional dependencies:
* [Blob](https://github.com/grantae/blob)
* [Cryptopp](https://github.com/weidai11/cryptopp)
* [Google Test](https://github.com/google/googletest)

## Creators

**Grant Ayers**

* <https://github.com/grantae>

## Copyright and license

Code and documentation copyright 2015 Grant Ayers. Code released under
[the MIT license](https://github.com/grantae/bae/bae/master/LICENSE)
