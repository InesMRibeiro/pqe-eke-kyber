#include "common.h"
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>

#define PBKDF2_ITERS 100000   

/*
 * Derive a key from a password using PBKDF2-HMAC-SHA256
 */
void derive_key_pbkdf2(const char *password,
                       const uint8_t *salt,
                       size_t salt_len,
                       uint8_t *out_key) {

    if (!PKCS5_PBKDF2_HMAC(password,
                           strlen(password),
                           salt,
                           salt_len,
                           PBKDF2_ITERS,
                           EVP_sha256(),
                           AES_KEY_LEN,
                           out_key)) {
        printf("PKCS5_PBKDF2_HMAC failed\n");
    }
}
