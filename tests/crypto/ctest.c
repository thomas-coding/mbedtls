/*
 * Copyright (c) 2021-2031, Jinping Wu (wunekky@gmail.com). All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include "crypto_util.h"
#include "crypto_hash_test.h"
#include "crypto_aes_test.h"

int main(void)
{
	int ret;
	printf("=== Crypto Test Begin ===\n");
	printf("\n");

	crypto_hash_test();
	crypto_aes_test();

	printf("\n");
	printf("=== Crypto Test End ===\n");
	return 0;
}
