#!/bin/bash

# shell folder
shell_folder=$(cd "$(dirname "$0")" || exit;pwd)

# Build mbedtls lib
make

#make check
#make clean

# Build mbedtls test
rm -rf ${shell_folder}/tests/crypto/ctest

gcc -g -o tests/crypto/ctest tests/crypto/ctest.c \
    tests/crypto/crypto_data.c tests/crypto/crypto_util.c \
    tests/crypto/crypto_hash_test.c \
	-L ${shell_folder}/library -lmbedcrypto -lmbedx509 -lmbedtls \
	-I ${shell_folder}/include
