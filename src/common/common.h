#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>

#define HASH_LEN 32      // SHA-256 produces 32 bytes
#define AES_KEY_LEN 32   // AES-256 requires 32 bytes
#define AES_IV_LEN 16    // AES IV is always 16 bytes

// SHA-256: Transforms password into binary key
void hash_password(const char *password, uint8_t *output_key);

// AES-256-CBC: Encryption and Decryption
int aes_encrypt(const uint8_t *plaintext, int plaintext_len, const uint8_t *key, 
                const uint8_t *iv, uint8_t *ciphertext);

int aes_decrypt(const uint8_t *ciphertext, int ciphertext_len, const uint8_t *key, 
                const uint8_t *iv, uint8_t *plaintext);

void print_hex(const char *label, const uint8_t *data, size_t len);

#endif