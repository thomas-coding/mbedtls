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
#include "crypto_chachapoly_test.h"
#include "psa/crypto.h"
#include "mbedtls/platform.h"

void chachapoly_encrypt_test() {
    psa_status_t status;
    psa_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    unsigned char      * output_data   = NULL;
    size_t               output_size   = 0;
    size_t               output_length = 0;

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Encrypt -------------------------------------------------------------*/
    /* Prepare key attributes */
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CHACHA20_POLY1305);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_CHACHA20);
    //psa_set_key_bits(&attributes, 256);

    status = psa_import_key(&attributes, chacha20_poly1305_key_data.x, chacha20_poly1305_key_data.len, &key);
    if (status != PSA_SUCCESS) {
        printf("Failed to import a key %d\n", status);
        return;
    }

    size_t key_bits = psa_get_key_bits(&attributes);
    output_size = chacha20_poly1305_plaintext_data.len + PSA_AEAD_TAG_LENGTH(PSA_KEY_TYPE_CHACHA20, key_bits, PSA_ALG_CHACHA20_POLY1305);
    
    output_data = mbedtls_calloc(output_size, 1);
    if (output_data == NULL) {
        printf("Failed to malloc %ld\n", output_size);
        return;
    }

    status = psa_aead_encrypt(key, PSA_ALG_CHACHA20_POLY1305, chacha20_poly1305_nonce_data.x, chacha20_poly1305_nonce_data.len,
                            chacha20_poly1305_additional_data.x, chacha20_poly1305_additional_data.len,
                            chacha20_poly1305_plaintext_data.x, chacha20_poly1305_plaintext_data.len,
                            output_data, output_size, &output_length);
    if (status != PSA_SUCCESS) {
        printf("Failed to encrypt\n");
        mbedtls_free(output_data);
        return;
    }

    memory_hex_dump("aead encrypt output", output_data, output_length);
    status =  hex_compare(output_data, chacha20_poly1305_ciphertext_data.x, chacha20_poly1305_ciphertext_data.len);
    if (status < 0)
        printf(RED"[%-50s] FAIL\n"COLOR_NONE, __func__);
    else
        printf(GREEN"[%-50s] SUCCESS\n"COLOR_NONE, __func__);

    /* Free the attributes */
    psa_reset_key_attributes(&attributes);

    /* Destroy the key */
    psa_destroy_key(key);

    mbedtls_free(output_data);
    mbedtls_psa_crypto_free();

}

void chachapoly_decrypt_test() {
    psa_status_t status;
    psa_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    unsigned char      * output_data   = NULL;
    size_t               output_size   = 0;
    size_t               output_length = 0;

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Encrypt -------------------------------------------------------------*/
    /* Prepare key attributes */
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CHACHA20_POLY1305);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_CHACHA20);
    //psa_set_key_bits(&attributes, 256);

    status = psa_import_key(&attributes, chacha20_poly1305_key_data.x, chacha20_poly1305_key_data.len, &key);
    if (status != PSA_SUCCESS) {
        printf("Failed to import a key %d\n", status);
        return;
    }

    size_t key_bits = psa_get_key_bits(&attributes);
    output_size = chacha20_poly1305_ciphertext_data.len - PSA_AEAD_TAG_LENGTH(PSA_KEY_TYPE_CHACHA20, key_bits, PSA_ALG_CHACHA20_POLY1305);
    
    output_data = mbedtls_calloc(output_size, 1);
    if (output_data == NULL) {
        printf("Failed to malloc %ld\n", output_size);
        return;
    }

    status = psa_aead_decrypt(key, PSA_ALG_CHACHA20_POLY1305, chacha20_poly1305_nonce_data.x, chacha20_poly1305_nonce_data.len,
                            chacha20_poly1305_additional_data.x, chacha20_poly1305_additional_data.len,
                            chacha20_poly1305_ciphertext_data.x, chacha20_poly1305_ciphertext_data.len,
                            output_data, output_size, &output_length);
    if (status != PSA_SUCCESS) {
        printf("Failed to decrypt\n");
        mbedtls_free(output_data);
        return;
    }

    memory_hex_dump("aead decrypt output", output_data, output_length);
    status =  hex_compare(output_data, chacha20_poly1305_plaintext_data.x, chacha20_poly1305_plaintext_data.len);
    if (status < 0)
        printf(RED"[%-50s] FAIL\n"COLOR_NONE, __func__);
    else
        printf(GREEN"[%-50s] SUCCESS\n"COLOR_NONE, __func__);

    /* Free the attributes */
    psa_reset_key_attributes(&attributes);

    /* Destroy the key */
    psa_destroy_key(key);

    mbedtls_free(output_data);
    mbedtls_psa_crypto_free();
}

void crypto_chachapoly_test(void) {
#if CONFIG_CHACHAPOLY == 1
    chachapoly_encrypt_test();
    chachapoly_decrypt_test();
#endif
}