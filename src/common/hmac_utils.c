#include "common.h"
#include <openssl/hmac.h>
#include <string.h>
#include <stdio.h>

#define HMAC_LEN 32  /* SHA-256 */

int compute_hmac(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out_mac) {

    unsigned int len = 0;

    if (!HMAC(EVP_sha256(),
              key, (int)key_len,
              data, data_len,
              out_mac, &len)) {
        fprintf(stderr, "[FATAL] HMAC computation failed\n");
        return -1;
    }

    return (int)len;
}
