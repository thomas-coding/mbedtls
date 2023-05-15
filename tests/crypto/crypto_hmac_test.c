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
#include "crypto_hmac_test.h"
#include "psa/crypto.h"

void hmac_sign_verify_test() {
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t signature[PSA_SIGNATURE_MAX_SIZE] = {0};
    size_t signature_length;
    psa_key_id_t key_id;

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* sign -------------------------------------------------------------*/
    /* Set key attributes */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    //psa_set_key_bits(&attributes, 2048);

    /* Import the key */
    status = psa_import_key(&attributes, hmac_key_data.x, hmac_key_data.len, &key_id);
    if (status != PSA_SUCCESS) {
        printf("Failed to import key\n");
        return;
    }

    /* Sign message using the key */
    status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), 
        hmac_message_data.x, hmac_message_data.len, signature, sizeof(signature), &signature_length);
    if (status != PSA_SUCCESS) {
        printf("Failed to sign\n");
        return;
    }

    memory_hex_dump("hmac:", signature, signature_length);
    status =  hex_compare(signature, hmac_sha256_expected_data.x, hmac_sha256_expected_data.len);
    if (status != PSA_SUCCESS) {
        printf("Failed to get expected hmac\n");
        return;
    }

    /* Free the attributes */
    psa_reset_key_attributes(&attributes);

    /* Destroy the key */
    psa_destroy_key(key_id);

    /* verify -------------------------------------------------------------*/
	psa_key_id_t pub_key_id;

	/* Set key attributes */
	psa_key_attributes_t pubkey_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&pubkey_attributes, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&pubkey_attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	psa_set_key_type(&pubkey_attributes, PSA_KEY_TYPE_HMAC);

	/* Import the key, HMAC used same for sign and verify */
	status = psa_import_key(&pubkey_attributes, hmac_key_data.x, hmac_key_data.len, &pub_key_id);
	if (status != PSA_SUCCESS) {
		printf("Failed to import public key\n");
		return;
	}

	status = psa_mac_verify(pub_key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), 
            hmac_message_data.x, hmac_message_data.len, hmac_sha256_expected_data.x, hmac_sha256_expected_data.len);
    if (status < 0)
        printf(RED"[%-50s] FAIL\n"COLOR_NONE, __func__);
    else
        printf(GREEN"[%-50s] SUCCESS\n"COLOR_NONE, __func__);

    /* Free the attributes */
    psa_reset_key_attributes(&pubkey_attributes);

    /* Destroy the key */
    psa_destroy_key(pub_key_id);

    mbedtls_psa_crypto_free();
}

void crypto_hmac_test(void) {
#if CONFIG_HMAC == 1
    hmac_sign_verify_test();
#endif
}