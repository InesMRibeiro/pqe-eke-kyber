#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include "../common/common.h"
#include "../kyber/ref/api.h"
#include "../kyber/ref/kem.h"

int main(void) {

    printf("--------------- EKE-KYBER DEMO ---------------\n");

    /* -----------------------------------------
     * 1) Shared password -> PBKDF2 key (pw_key)
     * ----------------------------------------- */
    const char *password = "sirs20252026";

    uint8_t salt[16];
    uint8_t pw_bob[AES_KEY_LEN];   /* 32 bytes */
    uint8_t pw_alice[AES_KEY_LEN]; /* 32 bytes */

    if (RAND_bytes(salt, (int)sizeof(salt)) != 1) {
        printf("RAND_bytes(salt) failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    derive_key_pbkdf2(password, salt, sizeof(salt), pw_bob);

    printf("The password is: %s\n", password);
    print_hex("Salt", salt, sizeof(salt));
    print_hex("[BOB] Derived key (PBKDF2)", pw_bob, sizeof(pw_bob));

    /* -----------------------------------------
     * 2) Bob generates Kyber keypair
     * ----------------------------------------- */
    uint8_t pk_Bob[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk_Bob[CRYPTO_SECRETKEYBYTES];

    if (crypto_kem_keypair(pk_Bob, sk_Bob) != 0) {
        printf("crypto_kem_keypair failed\n");
        return 1;
    }
    printf("\n[Bob] Kyber keypair generated.\n");

    /* -----------------------------------------
     * 3) Bob encrypts pk_Bob with AES-256-GCM under pw_bob
     *    Output: iv_pk, ct_pk, tag_pk
     * ----------------------------------------- */
    uint8_t iv_pk[12];
    uint8_t tag_pk[16];
    uint8_t ct_pk[CRYPTO_PUBLICKEYBYTES];

    int ct_pk_len = aes_gcm_encrypt(
        pk_Bob, CRYPTO_PUBLICKEYBYTES,
        pw_bob,
        iv_pk,
        ct_pk,
        tag_pk
    );

    if (ct_pk_len != CRYPTO_PUBLICKEYBYTES) {
        printf("aes_gcm_encrypt(pk_Bob) failed or length mismatch\n");
        return 1;
    }

    printf("\n[Bob -> Alice] Sent: salt || iv_pk || ct_pk || tag_pk\n");

    /* -----------------------------------------
     * 4) Alice decrypts pk_Bob using pw_alice
     * ----------------------------------------- */
    printf("\n[Alice] Received: salt || iv_pk || ct_pk || tag_pk\n");

    derive_key_pbkdf2(password, salt, sizeof(salt), pw_alice);
    print_hex("[Alice] Derived key (PBKDF2)", pw_alice, sizeof(pw_alice));

    uint8_t pk_Bob_dec[CRYPTO_PUBLICKEYBYTES];

    /*tag_pk[0] ^= 0x01;*/ /* Uncomment to test decryption failure on tampering */
    
    int pk_dec_len = aes_gcm_decrypt(ct_pk, ct_pk_len, pw_alice, iv_pk, tag_pk, pk_Bob_dec);

    if (pk_dec_len < 0) {
        printf("[Alice] Decryption failed (wrong password or tampering)\n");
        return 1;
    }
    if (pk_dec_len != CRYPTO_PUBLICKEYBYTES) {
        printf("[Alice] Decrypted pk length mismatch!\n");
        return 1;
    }

    printf("[Alice] Decrypted pk_Bob successfully.\n");

    /* -----------------------------------------
     * 5) Alice encapsulates using decrypted pk_Bob
     * ----------------------------------------- */
    uint8_t ct_K[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss_A[CRYPTO_BYTES];

    if (crypto_kem_enc(ct_K, ss_A, pk_Bob_dec) != 0) {
        printf("crypto_kem_enc failed\n");
        return 1;
    }

    printf("\n[Alice] Encapsulated: produced ct_K and ss_A.\n");
    printf("[Alice -> Bob] Sends ct_K to Bob and keeps ss_A.\n");

    /* -----------------------------------------
     * 6) Bob decapsulates ct_K using sk_Bob
     * ----------------------------------------- */
    uint8_t ss_B[CRYPTO_BYTES];

    if (crypto_kem_dec(ss_B, ct_K, sk_Bob) != 0) {
        printf("crypto_kem_dec failed\n");
        return 1;
    }

    printf("\n[Bob] Decapsulated: produced ss_B.\n");

    /* -----------------------------------------
     * Demo checks
     * ----------------------------------------- */
    /* Check PBKDF2-derived keys match */
    if (memcmp(pw_bob, pw_alice, AES_KEY_LEN) == 0)
        printf("[OK] pw_bob == pw_alice (same password+salt)\n");
    else
        printf("[FAIL] pw_bob != pw_alice\n");

    /* Check Kyber shared secret matches */
    if (memcmp(ss_A, ss_B, CRYPTO_BYTES) == 0)
        printf("[OK] ss_A == ss_B (Kyber shared secret)\n");
    else
        printf("[FAIL] ss_A != ss_B\n");

    /* show prefixes for observability */
    print_hex("[Alice] ss_A (prefix)", ss_A, 32);
    print_hex("[Bob]   ss_B (prefix)", ss_B, 32);

    printf("\n--------------- END EKE-KYBER DEMO ---------------\n");
    printf("DONE\n");

    return 0;
}
