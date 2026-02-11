#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../kyber/ref/api.h"
#include "../kyber/ref/kem.h"
#include "../common/common.h"  // para print_hex, se tiveres

#define N_RUNS 100

int main(void) {
    printf("=== KYBER Alice–Bob KEM Demo ===\n\n");

    printf("Kyber parameters (from api.h):\n");
    printf("  CRYPTO_PUBLICKEYBYTES   = %d bytes\n", CRYPTO_PUBLICKEYBYTES);
    printf("  CRYPTO_SECRETKEYBYTES   = %d bytes\n", CRYPTO_SECRETKEYBYTES);
    printf("  CRYPTO_CIPHERTEXTBYTES  = %d bytes\n", CRYPTO_CIPHERTEXTBYTES);
    printf("  CRYPTO_BYTES (shared secret) = %d bytes\n\n", CRYPTO_BYTES);

    int ok = 0;

    for (int run = 1; run <= N_RUNS; run++) {
        /* -----------------------------------------
         * 1) Bob generates Kyber keypair
         * ----------------------------------------- */
        uint8_t pk[CRYPTO_PUBLICKEYBYTES];
        uint8_t sk[CRYPTO_SECRETKEYBYTES];

        if (crypto_kem_keypair(pk, sk) != 0) {
            printf("[FATAL] crypto_kem_keypair failed at run %d\n", run);
            return 1;
        }

        /* -----------------------------------------
         * 2) Alice encapsulates using Bob's pk
         * ----------------------------------------- */
        uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
        uint8_t ss_alice[CRYPTO_BYTES];

        if (crypto_kem_enc(ct, ss_alice, pk) != 0) {
            printf("[FATAL] crypto_kem_enc failed at run %d\n", run);
            return 1;
        }

        /* -----------------------------------------
         * 3) Bob decapsulates
         * ----------------------------------------- */
        uint8_t ss_bob[CRYPTO_BYTES];

        if (crypto_kem_dec(ss_bob, ct, sk) != 0) {
            printf("[FATAL] crypto_kem_dec failed at run %d\n", run);
            return 1;
        }

        /* -----------------------------------------
         * 4) Verify shared secrets match
         * ----------------------------------------- */
        if (memcmp(ss_alice, ss_bob, CRYPTO_BYTES) != 0) {
            printf("[FATAL] Shared secrets mismatch at run %d\n", run);
            return 1;
        }

        ok++;

        /* -----------------------------------------
         * 5) Print first run details
         * ----------------------------------------- */
        if (run == 1) {
            printf("[Run %d OK]\n", run);
            print_hex("  pk prefix", pk, 8);
            print_hex("  ct prefix", ct, 8);
            print_hex("  ss prefix", ss_alice, 8);

            /* Tampered ciphertext test (mantido, mas não executa nada) */
#if 1
            uint8_t ct_tampered[CRYPTO_CIPHERTEXTBYTES];
            uint8_t ss_tampered[CRYPTO_BYTES];
            memcpy(ct_tampered, ct, CRYPTO_CIPHERTEXTBYTES);

            ct_tampered[0] ^= 0xFF;


            if (crypto_kem_dec(ss_tampered, ct_tampered, sk) != 0) {
                printf("[WARN] crypto_kem_dec failed on tampered ct (ok depending on impl)\n");
            }

            if (memcmp(ss_alice, ss_tampered, CRYPTO_BYTES) == 0) {
                printf("[WARN] Tampered ciphertext produced SAME shared secret\n");
                return 1;
            } else {
                printf("  [Tamper test OK] Modified ct -> different shared secret\n");
            }
#endif
            printf("\n");
        }
    }

    printf("All runs successful: %d/%d\n", ok, N_RUNS);
    printf("--------------- END KYBER DEMO ---------------\n");

    return 0;
}
