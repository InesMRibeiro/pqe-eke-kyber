«CC = gcc
CFLAGS = -Wall -Wextra -O2 -I../common -I../kyber/ref
COMMON_SRC = ../common/aes_gcm_utils.c ../common/aes_utils.c ../common/hash_utils.c ../common/hmac_utils.c ../common/pbkdf2_utils.c

# Arquivos Kyber Ref
KYBER_SRC = ../kyber/ref/cbd.c ../kyber/ref/fips202.c ../kyber/ref/indcpa.c ../kyber/ref/kem.c ../kyber/ref/ntt.c ../kyber/ref/poly.c ../kyber/ref/polyvec.c ../kyber/ref/reduce.c ../kyber/ref/randombytes.c ../kyber/ref/symmetric-shake.c ../kyber/ref/verify.c

# Níveis Kyber que queremos suportar
KYBER_LEVELS = 512 768 1024

# Executáveis
TARGETS = alice_bob_demo

all: $(TARGETS)

alice_bob_demo: alice_bob_demo.c $(COMMON_SRC) $(KYBER_SRC)
	$(CC) $(CFLAGS) -DKYBER_K=2 $^ -lcrypto -o $@

# Testar outros níveis:
# -DKYBER_K=3 para 768
# -DKYBER_K=4 para 1024

clean:
	rm -f $(TARGETS)
