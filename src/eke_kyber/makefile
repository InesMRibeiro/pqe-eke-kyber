CC = gcc
CFLAGS = -Wall -Wextra -O2 -I../common -I../kyber/ref
COMMON_SRC = ../common/aes_gcm_utils.c ../common/aes_utils.c ../common/hash_utils.c ../common/hmac_utils.c ../common/pbkdf2_utils.c

# Arquivos Kyber Ref
KYBER_SRC = ../kyber/ref/api.h ../kyber/ref/cbd.c ../kyber/ref/fips202.c ../kyber/ref/indcpa.c ../kyber/ref/kem.c ../kyber/ref/ntt.c ../kyber/ref/poly.c ../kyber/ref/polyvec.c ../kyber/ref/reduce.c ../kyber/ref/randombytes.c ../kyber/ref/symmetric-shake.c ../kyber/ref/verify.c

# Define os níveis de Kyber
KYBER_LEVELS = 512 768 1024

all: $(KYBER_LEVELS:%=eke_kyber_%)

eke_kyber_512: eke_kyber.c $(COMMON_SRC) $(KYBER_SRC)
	$(CC) $(CFLAGS) -DKYBER_K=2 $^ -lcrypto -o $@

eke_kyber_768: eke_kyber.c $(COMMON_SRC) $(KYBER_SRC)
	$(CC) $(CFLAGS) -DKYBER_K=3 $^ -lcrypto -o $@

eke_kyber_1024: eke_kyber.c $(COMMON_SRC) $(KYBER_SRC)
	$(CC) $(CFLAGS) -DKYBER_K=4 $^ -lcrypto -o $@

clean:
	rm -f eke_kyber_512 eke_kyber_768 eke_kyber_1024
