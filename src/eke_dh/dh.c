#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include "../common/common.h"

int main(void) {

    printf("--------------- DH DEMO ---------------\n");

    /* -----------------------------------------
     * 1) Setup: DH parameters 
     * ----------------------------------------- */
    const char *group = "ffdhe2048";

    EVP_PKEY_CTX *param_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!param_ctx) {
        printf("EVP_PKEY_CTX_new_id failed\n");
        return 1;
    }

    if (EVP_PKEY_paramgen_init(param_ctx) <= 0) {
        printf("EVP_PKEY_paramgen_init failed\n");
        return 1;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)group, 0),
        OSSL_PARAM_END
    };

    if (EVP_PKEY_CTX_set_params(param_ctx, params) <= 0) {
        printf("EVP_PKEY_CTX_set_params failed\n");
        return 1;
    }

    EVP_PKEY *dh_params = NULL;
    if (EVP_PKEY_paramgen(param_ctx, &dh_params) <= 0) {
        printf("EVP_PKEY_paramgen failed\n");
        return 1;
    }

    EVP_PKEY_CTX_free(param_ctx);

    printf("[Setup] DH parameters ready (group = %s).\n", group);

    /* -----------------------------------------
     * 2) Alice generates DH keypair
     * ----------------------------------------- */
    EVP_PKEY *alice_kp = NULL;
    EVP_PKEY_CTX *alice_kctx = EVP_PKEY_CTX_new(dh_params, NULL);

    if (!alice_kctx) {
        printf("EVP_PKEY_CTX_new (Alice) failed\n");
        return 1;
    }

    if (EVP_PKEY_keygen_init(alice_kctx) <= 0) {
        printf("EVP_PKEY_keygen_init (Alice) failed\n");
        return 1;
    }

    if (EVP_PKEY_keygen(alice_kctx, &alice_kp) <= 0) {
        printf("EVP_PKEY_keygen (Alice) failed\n");
        return 1;
    }

    EVP_PKEY_CTX_free(alice_kctx);
    printf("[Alice] DH keypair generated.\n");

    /* -----------------------------------------
     * 3) Bob generates DH keypair
     * ----------------------------------------- */
    EVP_PKEY *bob_kp = NULL;
    EVP_PKEY_CTX *bob_kctx = EVP_PKEY_CTX_new(dh_params, NULL);

    if (!bob_kctx) {
        printf("EVP_PKEY_CTX_new (Bob) failed\n");
        return 1;
    }

    if (EVP_PKEY_keygen_init(bob_kctx) <= 0) {
        printf("EVP_PKEY_keygen_init (Bob) failed\n");
        return 1;
    }

    if (EVP_PKEY_keygen(bob_kctx, &bob_kp) <= 0) {
        printf("EVP_PKEY_keygen (Bob) failed\n");
        return 1;
    }

    EVP_PKEY_CTX_free(bob_kctx);
    printf("[Bob] DH keypair generated.\n");

    /* -----------------------------------------
     * 4) Alice derives shared secret
     * ----------------------------------------- */
    EVP_PKEY_CTX *alice_dctx = EVP_PKEY_CTX_new(alice_kp, NULL);

    if (!alice_dctx) {
        printf("EVP_PKEY_CTX_new (Alice derive) failed\n");
        return 1;
    }

    if (EVP_PKEY_derive_init(alice_dctx) <= 0) {
        printf("EVP_PKEY_derive_init (Alice) failed\n");
        return 1;
    }

    if (EVP_PKEY_derive_set_peer(alice_dctx, bob_kp) <= 0) {
        printf("EVP_PKEY_derive_set_peer (Alice) failed\n");
        return 1;
    }

    size_t alice_ss_len = 0;
    if (EVP_PKEY_derive(alice_dctx, NULL, &alice_ss_len) <= 0) {
        printf("EVP_PKEY_derive length (Alice) failed\n");
        return 1;
    }

    uint8_t *alice_ss = malloc(alice_ss_len);
    if (!alice_ss) {
        printf("malloc failed (Alice secret)\n");
        return 1;
    }

    if (EVP_PKEY_derive(alice_dctx, alice_ss, &alice_ss_len) <= 0) {
        printf("EVP_PKEY_derive (Alice) failed\n");
        return 1;
    }

    EVP_PKEY_CTX_free(alice_dctx);

    /* -----------------------------------------
     * 5) Bob derives shared secret
     * ----------------------------------------- */
    EVP_PKEY_CTX *bob_dctx = EVP_PKEY_CTX_new(bob_kp, NULL);

    if (!bob_dctx) {
        printf("EVP_PKEY_CTX_new (Bob derive) failed\n");
        return 1;
    }

    if (EVP_PKEY_derive_init(bob_dctx) <= 0) {
        printf("EVP_PKEY_derive_init (Bob) failed\n");
        return 1;
    }

    if (EVP_PKEY_derive_set_peer(bob_dctx, alice_kp) <= 0) {
        printf("EVP_PKEY_derive_set_peer (Bob) failed\n");
        return 1;
    }

    size_t bob_ss_len = 0;
    if (EVP_PKEY_derive(bob_dctx, NULL, &bob_ss_len) <= 0) {
        printf("EVP_PKEY_derive length (Bob) failed\n");
        return 1;
    }

    uint8_t *bob_ss = malloc(bob_ss_len);
    if (!bob_ss) {
        printf("malloc failed (Bob secret)\n");
        return 1;
    }

    if (EVP_PKEY_derive(bob_dctx, bob_ss, &bob_ss_len) <= 0) {
        printf("EVP_PKEY_derive (Bob) failed\n");
        return 1;
    }

    EVP_PKEY_CTX_free(bob_dctx);

    /* -----------------------------------------
     * 6) Demo check
     * ----------------------------------------- */
    printf("\n[Result] Derived shared secrets:\n");

    print_hex("[Alice] ss_A (prefix)", alice_ss, 32);
    print_hex("[Bob]   ss_B (prefix)", bob_ss, 32);

    if (alice_ss_len == bob_ss_len &&
        memcmp(alice_ss, bob_ss, alice_ss_len) == 0) {
        printf("[OK] Shared secrets match!\n");
    } else {
        printf("[FAIL] Shared secrets DO NOT match!\n");
    }

    free(alice_ss);
    free(bob_ss);
    EVP_PKEY_free(alice_kp);
    EVP_PKEY_free(bob_kp);
    EVP_PKEY_free(dh_params);

    printf("\n--------------- END DH DEMO ---------------\n");
    return 0;
}
