#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include "../common/common.h"

// Simulation of DH key generation (simplified for this example)
void generate_dh_public_key_sim(uint8_t *pub_out, size_t len) {
    for(size_t i=0; i<len; i++) pub_out[i] = 0xAA + i;
}

int main() {
    printf("--- Classical EKE (Diffie-Hellman + AES-256) ---\n\n");

    // Password definition 
    const char *password = "very_strong_password_2026";
    uint8_t password_key[AES_KEY_LEN];
    uint8_t iv[AES_IV_LEN] = {0}; // Fixed IV for testing
    
    hash_password(password, password_key);
    printf("[Setup] Chosen Password: %s\n", password);
    print_hex("Derived Key from Password", password_key, AES_KEY_LEN);

    // Alice: Generate DH public key
    size_t dh_pub_len = 256;
    uint8_t alice_pub_raw[256];
    generate_dh_public_key_sim(alice_pub_raw, dh_pub_len);
    printf("[Alice] Generated DH Public Key (unencrypted).\n");

    //Alice encrypts the PK with the Password before "sending"
    uint8_t encrypted_pub[512]; 
    int encrypted_len = aes_encrypt(alice_pub_raw, (int)dh_pub_len, password_key, iv, encrypted_pub);
    
    printf("\n[ALICE -> BOB] Sending Protected Public Key...\n");
    print_hex("Content passing through the channel (Encrypted)", encrypted_pub, encrypted_len);

    //BOB Receives and tries to decrypt
    printf("[Bob] Received the package. Trying to decrypt with the password...\n");
    uint8_t decrypted_pub[512];
    int decrypted_len = aes_decrypt(encrypted_pub, encrypted_len, password_key, iv, decrypted_pub);

    if (decrypted_len > 0) {
        printf("[Success] Bob decrypted Alice's key!\n");
    } else {
        printf("[Error] Bob failed to decrypt. Incorrect password?\n");
    }

    printf("\n--- End of Simulation V1 ---\n");
    return 0;
}