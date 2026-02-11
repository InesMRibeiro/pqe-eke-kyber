CC = gcc
CFLAGS = -Wall -Wextra -O2 -I../common -I../kyber/ref
LDFLAGS = -L../kyber/ref/lib -Wl,-rpath,'$$ORIGIN/../kyber/ref/lib' -lcrypto -lpqcrystals_fips202_ref

COMMON_SRC = ../common/aes_gcm_utils.c ../common/aes_utils.c ../common/hash_utils.c ../common/hmac_utils.c ../common/pbkdf2_utils.c

all: dh_program dh_eke_1 eke_dh

dh_program: dh.c $(COMMON_SRC)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

dh_eke_1: dh_eke_1.c $(COMMON_SRC)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

eke_dh: eke_dh.c $(COMMON_SRC)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -f dh_program dh_eke_1 eke_dh
