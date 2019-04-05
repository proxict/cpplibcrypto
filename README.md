[![Build Status](https://travis-ci.org/proxict/cpplibcrypto.svg?branch=develop)](https://travis-ci.org/proxict/cpplibcrypto) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/33a6770ae69840728e2053596b0f6885)](https://app.codacy.com/app/proxict/cpplibcrypto?utm_source=github.com&utm_medium=referral&utm_content=proxict/cpplibcrypto&utm_campaign=badger)

What is cpplibcrypto?
---------------------

cpplibcrypto is a cryptographic library with ease-of-use in mind.

 - Written in a modern C++14 standard
 - Implements custom allocator for secure memory management
 - 3-Clause BSD License
 
 Supported algorithms:
 - AES with 128/192/256 bits key size
 - CBC mode of operation for block ciphers
 - PKCS#7 padding
 - MD5 hashing function
 - SHA1 hashing function
 - PBKDF key derivation function
 
Building cpplibcrypto
---------------------
 - `git clone git@github.com:proxict/cpplibcrypto.git`
 - `cd cpplibcrypto`
 - `mkdir build && cd build`
 - `cmake --DCMAKE_BUILD_TYPE=Release ..`
 - `make -j$(nproc)`
 
**Please, keep in mind, this is more intended for educational purposes rather than for use in any kind of a production environment.**
