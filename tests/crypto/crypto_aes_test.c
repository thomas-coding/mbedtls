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
#include "crypto_aes_test.h"
#include "psa/crypto.h"

void aes_cbc_encrypt_test(void) {

    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_AES),
    };
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;
    uint8_t output[block_size];
    size_t output_len;
    size_t total_output_len = 0;
    psa_key_id_t key_id;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;


    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS)
    {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Import a key */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    status = psa_import_key(&attributes, aes_cbc_128_key, sizeof(aes_cbc_128_key), &key_id);
    if (status != PSA_SUCCESS) {
        printf("Failed to import a key\n");
        return;
    }
    psa_reset_key_attributes(&attributes);

    /* Encrypt the plaintext */
    status = psa_cipher_encrypt_setup(&operation, key_id, alg);
    if (status != PSA_SUCCESS) {
        printf("Failed to begin cipher operation\n");
        return;
    }

    //status = psa_cipher_generate_iv(&operation, iv, sizeof(iv), &iv_len);
    status = psa_cipher_set_iv(&operation, aes_cbc_128_iv, sizeof(aes_cbc_128_iv));
    if (status != PSA_SUCCESS) {
        printf("Failed to set IV\n");
        return;
    }

    status = psa_cipher_update(&operation, aes_cbc_128_plaintext, sizeof(aes_cbc_128_plaintext),
                               output, sizeof(output), &output_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to update cipher operation\n");
        return;
    }
    total_output_len += output_len;

    status = psa_cipher_finish(&operation, output + output_len,
                               sizeof(output) - output_len, &output_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to finish cipher operation\n");
        return;
    }
    total_output_len += output_len;

    memory_hex_dump("aes cbc encrypted data", output, total_output_len);
    status =  hex_compare(output, aes_cbc_128_ciphertext, total_output_len);
    if (status < 0)
        printf(RED"[%-50s] FAIL\n"COLOR_NONE, __func__);
    else
        printf(GREEN"[%-50s] SUCCESS\n"COLOR_NONE, __func__);

    /* Clean up cipher operation context */
    psa_cipher_abort(&operation);

    /* Destroy the key */
    psa_destroy_key(key_id);

    mbedtls_psa_crypto_free();

}

void aes_cbc_decrypt_test(void) {
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_AES),
    };
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    uint8_t output[block_size];
    size_t output_len;
    psa_key_id_t key_id;
    size_t total_output_len = 0;

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS)
    {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Import a key */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    status = psa_import_key(&attributes, aes_cbc_128_key, sizeof(aes_cbc_128_key), &key_id);
    if (status != PSA_SUCCESS) {
        printf("Failed to import a key\n");
        return;
    }
    psa_reset_key_attributes(&attributes);

    /* Decrypt the ciphertext */
    status = psa_cipher_decrypt_setup(&operation, key_id, alg);
    if (status != PSA_SUCCESS) {
        printf("Failed to begin cipher operation\n");
        return;
    }

    status = psa_cipher_set_iv(&operation, aes_cbc_128_iv, sizeof(aes_cbc_128_iv));
    if (status != PSA_SUCCESS) {
        printf("Failed to set IV\n");
        return;
    }

    status = psa_cipher_update(&operation, aes_cbc_128_ciphertext, sizeof(aes_cbc_128_ciphertext),
                               output, sizeof(output), &output_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to update cipher operation\n");
        return;
    }
    total_output_len += output_len;

    status = psa_cipher_finish(&operation, output + output_len,
                               sizeof(output) - output_len, &output_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to finish cipher operation\n");
        return;
    }
    total_output_len += output_len;

    memory_hex_dump("aes cbc decrypted data", output, total_output_len);
    status =  hex_compare(output, aes_cbc_128_plaintext, total_output_len);
    if (status < 0)
        printf(RED"[%-50s] FAIL\n"COLOR_NONE, __func__);
    else
        printf(GREEN"[%-50s] SUCCESS\n"COLOR_NONE, __func__);

    /* Clean up cipher operation context */
    psa_cipher_abort(&operation);

    /* Destroy the key */
    psa_destroy_key(key_id);

    mbedtls_psa_crypto_free();
}

void crypto_aes_test(void) {
#if CONFIG_AES_CBC == 1
    aes_cbc_encrypt_test();
    aes_cbc_decrypt_test();
#endif
}