#!/bin/bash

# shell folder
shell_folder=$(cd "$(dirname "$0")" || exit;pwd)

# Build mbedtls lib
make clean
make DEBUG=1 -j8
#make check

# Build mbedtls test
rm -rf ${shell_folder}/tests/crypto/ctest

gcc -g -static -o tests/crypto/ctest tests/crypto/ctest.c \
    tests/crypto/crypto_data.c tests/crypto/crypto_util.c \
    tests/crypto/crypto_hash_test.c \
    tests/crypto/crypto_aes_test.c \
	-L ${shell_folder}/library -lmbedcrypto -lmbedx509 -lmbedtls \
	-I ${shell_folder}/include

rm -rf ${shell_folder}/tests/crypto/ctest.asm
objdump -xdS ${shell_folder}/tests/crypto/ctest > ${shell_folder}/tests/crypto/ctest.asm
