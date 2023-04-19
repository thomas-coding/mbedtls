/*
 * Copyright (c) 2021-2031, Jinping Wu (wunekky@gmail.com). All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <assert.h>
#include "crypto_data.h"
#include "crypto_util.h"
#include "crypto_hash_test.h"
#include "psa/crypto.h"
#include "mbedtls/md5.h"

void sha256_test(void) {
    psa_status_t status;
    psa_algorithm_t alg = PSA_ALG_SHA_256;
	const size_t hash_size = PSA_HASH_LENGTH(alg);
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    //unsigned char input[] = { 'a', 'b', 'c' };
    unsigned char actual_hash[hash_size];
    size_t actual_hash_len;

    //printf("Hash a message...\t");
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Compute hash of message  */
    status = psa_hash_setup(&operation, alg);
    if (status != PSA_SUCCESS) {
        printf("Failed to begin hash operation\n");
        return;
    }
    status = psa_hash_update(&operation, sha256_msg, sizeof(sha256_msg));
    if (status != PSA_SUCCESS) {
        printf("Failed to update hash operation\n");
        return;
    }
    status = psa_hash_finish(&operation, actual_hash, sizeof(actual_hash),
                             &actual_hash_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to finish hash operation\n");
        return;
    }

    //printf("Hashed a message\n");
	memory_hex_dump("hashed message", actual_hash, hash_size);
	status =  hex_compare(actual_hash, sha256_digest, hash_size);
	if (status < 0)
		printf(RED"[%s] FAIL\n"COLOR_NONE, __func__);
	else
		printf(GREEN"[%s] SUCCESS\n"COLOR_NONE, __func__);

    /* Clean up hash operation context */
    psa_hash_abort(&operation);

    mbedtls_psa_crypto_free();

}

void crypto_hash_test(void) {
	//mbedtls_md5_self_test(1);	
#if CONFIG_HASH_SHA256 == 1
    sha256_test();
#endif
}