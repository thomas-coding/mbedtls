#!/bin/bash

# shell folder
shell_folder=$(cd "$(dirname "$0")" || exit;pwd)

# Run gdb
gdb ./tests/crypto/ctest
