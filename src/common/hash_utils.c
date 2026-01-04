#include "common.h"
#include <openssl/evp.h>
#include <string.h>

void hash_password(const char *password, uint8_t *output_key) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, output_key, NULL);

    EVP_MD_CTX_free(mdctx);
}

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n\n");
}