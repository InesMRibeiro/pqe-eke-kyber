#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>

#include "../common/common.h"

/* Export public key to DER (returns 1 ok / 0 fail) */
static int export_pubkey_der(EVP_PKEY *kp, uint8_t **out, int *out_len) {
    int len = i2d_PUBKEY(kp, NULL);
    if (len <= 0) {
        printf("i2d_PUBKEY (len) failed\n");
        return 0;
    }

    uint8_t *buf = malloc((size_t)len);
    if (!buf) {
        printf("malloc failed (export_pubkey_der)\n");
        return 0;
    }

    uint8_t *p = buf;
    if (i2d_PUBKEY(kp, &p) != len) {
        printf("i2d_PUBKEY failed\n");
        free(buf);
        return 0;
    }

    *out = buf;
    *out_len = len;
    return 1;
}

/* Import public key from DER (returns EVP_PKEY* or NULL) */
static EVP_PKEY* import_pubkey_der(const uint8_t *buf, int len) {
    const uint8_t *p = buf;
    EVP_PKEY *pk = d2i_PUBKEY(NULL, &p, len);
    if (!pk) {
        printf("d2i_PUBKEY failed\n");
        return NULL;
    }
    return pk;
}

int main(void) {

    printf("--------------- EKE-DH DEMO ---------------\n");

    /* -----------------------------------------
     * 1) Shared password -> PBKDF2 key (Bob/Alice)
     * ----------------------------------------- */
    const char *password = "eke_demo_password";
    uint8_t salt[16];
    uint8_t pw_bob[AES_KEY_LEN];
    uint8_t pw_alice[AES_KEY_LEN];

    if (RAND_bytes(salt, (int)sizeof(salt)) != 1) {
        printf("RAND_bytes(salt) failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    derive_key_pbkdf2(password, salt, sizeof(salt), pw_bob);

    printf("[Setup] Password: %s\n", password);
    print_hex("[Setup] Salt", salt, sizeof(salt));
    print_hex("[Bob]   Derived key (PBKDF2)", pw_bob, AES_KEY_LEN);

    /* -----------------------------------------
     * 2) DH parameters (ffdhe2048)
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
        printf("EVP_PKEY_CTX_set_params (group) failed\n");
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
     * 3) Alice generates DH keypair
     * ----------------------------------------- */
    EVP_PKEY *alice_kp = NULL;
    EVP_PKEY_CTX *actx = EVP_PKEY_CTX_new(dh_params, NULL);
    if (!actx) {
        printf("EVP_PKEY_CTX_new (Alice) failed\n");
        return 1;
    }

    if (EVP_PKEY_keygen_init(actx) <= 0) {
        printf("EVP_PKEY_keygen_init (Alice) failed\n");
        return 1;
    }

    if (EVP_PKEY_keygen(actx, &alice_kp) <= 0) {
        printf("EVP_PKEY_keygen (Alice) failed\n");
        return 1;
    }

    EVP_PKEY_CTX_free(actx);
    printf("[Alice] DH keypair generated.\n");

    /* Alice exports + encrypts her public key */
    uint8_t *alice_pub = NULL;
    int alice_pub_len = 0;

    if (!export_pubkey_der(alice_kp, &alice_pub, &alice_pub_len)) {
        printf("[Alice] export_pubkey_der failed\n");
        return 1;
    }

    /* -----------------------------------------
     * 4) Alice -> Bob: send salt || iv || ct || tag
     * ----------------------------------------- */
    printf("\n[Alice -> Bob] Sent: salt || iv || ct || tag\n");

    /* Alice derives her key after "receiving" salt (demo: she has it now) */
    derive_key_pbkdf2(password, salt, sizeof(salt), pw_alice);
    print_hex("[Alice] Derived key (PBKDF2)", pw_alice, AES_KEY_LEN);

    if (memcmp(pw_bob, pw_alice, AES_KEY_LEN) == 0)
        printf("[OK] pw_bob == pw_alice (same password+salt)\n");
    else
        printf("[FAIL] pw_bob != pw_alice\n");

    uint8_t alice_iv[12];
    uint8_t alice_tag[16];
    uint8_t alice_ct[4096];

    int alice_ct_len = aes_gcm_encrypt(
        alice_pub, alice_pub_len,
        pw_alice,
        alice_iv,
        alice_ct,
        alice_tag
    );

    if (alice_ct_len < 0) {
        printf("aes_gcm_encrypt (Alice->Bob) failed\n");
        return 1;
    }

    /* Bob decrypts + imports Alice public key */
    uint8_t alice_pub_dec[4096];

    int alice_pub_dec_len = aes_gcm_decrypt(
        alice_ct, alice_ct_len,
        pw_bob,
        alice_iv,
        alice_tag,
        alice_pub_dec
    );

    if (alice_pub_dec_len < 0) {
        printf("[Bob] Decryption failed (wrong password or tampering)\n");
        return 1;
    }

    EVP_PKEY *alice_pubkey = import_pubkey_der(alice_pub_dec, alice_pub_dec_len);
    if (!alice_pubkey) {
        printf("[Bob] import_pubkey_der failed\n");
        return 1;
    }

    printf("[Bob] Alice public key decrypted and imported.\n");

    /* -----------------------------------------
     * 5) Bob generates DH keypair
     * ----------------------------------------- */
    EVP_PKEY *bob_kp = NULL;
    EVP_PKEY_CTX *bctx = EVP_PKEY_CTX_new(dh_params, NULL);
    if (!bctx) {
        printf("EVP_PKEY_CTX_new (Bob) failed\n");
        return 1;
    }

    if (EVP_PKEY_keygen_init(bctx) <= 0) {
        printf("EVP_PKEY_keygen_init (Bob) failed\n");
        return 1;
    }

    if (EVP_PKEY_keygen(bctx, &bob_kp) <= 0) {
        printf("EVP_PKEY_keygen (Bob) failed\n");
        return 1;
    }

    EVP_PKEY_CTX_free(bctx);
    printf("[Bob] DH keypair generated.\n");

    /* Bob exports + encrypts his public key */
    uint8_t *bob_pub = NULL;
    int bob_pub_len = 0;

    if (!export_pubkey_der(bob_kp, &bob_pub, &bob_pub_len)) {
        printf("[Bob] export_pubkey_der failed\n");
        return 1;
    }

    uint8_t bob_iv[12];
    uint8_t bob_tag[16];
    uint8_t bob_ct[4096];

    int bob_ct_len = aes_gcm_encrypt(
        bob_pub, bob_pub_len,
        pw_bob,
        bob_iv,
        bob_ct,
        bob_tag
    );

    if (bob_ct_len < 0) {
        printf("aes_gcm_encrypt (Bob->Alice) failed\n");
        return 1;
    }

    printf("\n[Bob -> Alice] Sent: iv || ct || tag\n");

    /* Alice decrypts + imports Bob public key */
    uint8_t bob_pub_dec[4096];

    int bob_pub_dec_len = aes_gcm_decrypt(
        bob_ct, bob_ct_len,
        pw_alice,
        bob_iv,
        bob_tag,
        bob_pub_dec
    );

    if (bob_pub_dec_len < 0) {
        printf("[Alice] Decryption failed (wrong password or tampering)\n");
        return 1;
    }

    EVP_PKEY *bob_pubkey = import_pubkey_der(bob_pub_dec, bob_pub_dec_len);
    if (!bob_pubkey) {
        printf("[Alice] import_pubkey_der failed\n");
        return 1;
    }

    printf("[Alice] Bob public key decrypted and imported.\n");

    /* -----------------------------------------
     * 6) Derive shared secret (Alice + Bob)
     * ----------------------------------------- */
    EVP_PKEY_CTX *adctx = EVP_PKEY_CTX_new(alice_kp, NULL);
    if (!adctx) {
        printf("EVP_PKEY_CTX_new (Alice derive) failed\n");
        return 1;
    }

    if (EVP_PKEY_derive_init(adctx) <= 0) {
        printf("EVP_PKEY_derive_init (Alice) failed\n");
        return 1;
    }

    if (EVP_PKEY_derive_set_peer(adctx, bob_pubkey) <= 0) {
        printf("EVP_PKEY_derive_set_peer (Alice) failed\n");
        return 1;
    }

    size_t alice_ss_len = 0;
    if (EVP_PKEY_derive(adctx, NULL, &alice_ss_len) <= 0) {
        printf("EVP_PKEY_derive (Alice len) failed\n");
        return 1;
    }

    uint8_t *alice_ss = malloc(alice_ss_len);
    if (!alice_ss) {
        printf("malloc failed (alice_ss)\n");
        return 1;
    }

    if (EVP_PKEY_derive(adctx, alice_ss, &alice_ss_len) <= 0) {
        printf("EVP_PKEY_derive (Alice) failed\n");
        return 1;
    }

    EVP_PKEY_CTX_free(adctx);

    EVP_PKEY_CTX *bdctx = EVP_PKEY_CTX_new(bob_kp, NULL);
    if (!bdctx) {
        printf("EVP_PKEY_CTX_new (Bob derive) failed\n");
        return 1;
    }

    if (EVP_PKEY_derive_init(bdctx) <= 0) {
        printf("EVP_PKEY_derive_init (Bob) failed\n");
        return 1;
    }

    if (EVP_PKEY_derive_set_peer(bdctx, alice_pubkey) <= 0) {
        printf("EVP_PKEY_derive_set_peer (Bob) failed\n");
        return 1;
    }

    size_t bob_ss_len = 0;
    if (EVP_PKEY_derive(bdctx, NULL, &bob_ss_len) <= 0) {
        printf("EVP_PKEY_derive (Bob len) failed\n");
        return 1;
    }

    uint8_t *bob_ss = malloc(bob_ss_len);
    if (!bob_ss) {
        printf("malloc failed (bob_ss)\n");
        return 1;
    }

    if (EVP_PKEY_derive(bdctx, bob_ss, &bob_ss_len) <= 0) {
        printf("EVP_PKEY_derive (Bob) failed\n");
        return 1;
    }

    EVP_PKEY_CTX_free(bdctx);

    printf("\n[Result] Derived shared secrets:\n");
    print_hex("[Alice] ss_A (prefix)", alice_ss, (alice_ss_len < 32 ? alice_ss_len : 32));
    print_hex("[Bob]   ss_B (prefix)", bob_ss,   (bob_ss_len   < 32 ? bob_ss_len   : 32));

    if (alice_ss_len != bob_ss_len || memcmp(alice_ss, bob_ss, alice_ss_len) != 0) {
        printf("[FAIL] Shared secrets DO NOT match!\n");
        return 1;
    }
    printf("[OK] Shared secrets match!\n\n");

    /* -----------------------------------------
     * 7) Key confirmation (HMAC) - Alice -> Bob
     * ----------------------------------------- */
    uint8_t mac_alice[HMAC_LEN];
    uint8_t mac_bob_check[HMAC_LEN];

    const char *confirm_msg_alice = "Alice key confirmation";

    compute_hmac(alice_ss, alice_ss_len,
                 (const uint8_t *)confirm_msg_alice,
                 strlen(confirm_msg_alice),
                 mac_alice);

    printf("[Alice -> Bob] Sending key confirmation MAC.\n");
    print_hex("  MAC_Alice", mac_alice, HMAC_LEN);

    compute_hmac(bob_ss, bob_ss_len,
                 (const uint8_t *)confirm_msg_alice,
                 strlen(confirm_msg_alice),
                 mac_bob_check);

    if (memcmp(mac_alice, mac_bob_check, HMAC_LEN) != 0) {
        printf("[FAIL] Key confirmation failed at Bob.\n");
        return 1;
    }
    printf("[OK] Bob verified Alice's key confirmation.\n\n");

    /* -----------------------------------------
     * 8) Key confirmation (HMAC) - Bob -> Alice
     * ----------------------------------------- */
    uint8_t mac_bob[HMAC_LEN];
    uint8_t mac_alice_check[HMAC_LEN];

    const char *confirm_msg_bob = "Bob key confirmation";

    compute_hmac(bob_ss, bob_ss_len,
                 (const uint8_t *)confirm_msg_bob,
                 strlen(confirm_msg_bob),
                 mac_bob);

    printf("[Bob -> Alice] Sending key confirmation MAC.\n");
    print_hex("  MAC_Bob", mac_bob, HMAC_LEN);

    compute_hmac(alice_ss, alice_ss_len,
                 (const uint8_t *)confirm_msg_bob,
                 strlen(confirm_msg_bob),
                 mac_alice_check);

    if (memcmp(mac_bob, mac_alice_check, HMAC_LEN) != 0) {
        printf("[FAIL] Key confirmation failed at Alice.\n");
        return 1;
    }
    printf("[OK] Alice verified Bob's key confirmation.\n");

    printf("\n--------------- END EKE-DH DEMO ---------------\n");
    printf("DONE\n");
    return 0;
}
