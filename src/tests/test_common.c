#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "common/common.h"

int main() {
    printf("=== Teste dos Utilitários Common (AES & Hash) ===\n\n");

    // 1. Teste do Hash (Password derivation)
    const char *pwd = "password_do_meti_2024";
    uint8_t hashed_key[AES_KEY_LEN];
    
    hash_password(pwd, hashed_key);
    print_hex("Chave derivada da Password (SHA-256)", hashed_key, AES_KEY_LEN);

    // 2. Teste do AES (Cifragem/Decifragem)
    const char *original_text = "Este e um teste de segredo para o Kyber PK!";
    int plaintext_len = strlen(original_text) + 1; // +1 para o null terminator
    uint8_t iv[AES_IV_LEN] = {0}; // Em produção, usa um IV aleatório!
    
    uint8_t ciphertext[256];
    uint8_t decryptedtext[256];

    // Cifrar
    int cipher_len = aes_encrypt((uint8_t*)original_text, plaintext_len, hashed_key, iv, ciphertext);
    printf("Sucesso na Cifragem.\n");
    print_hex("Texto Cifrado (Binary)", ciphertext, cipher_len);

    // Decifrar
    int dec_len = aes_decrypt(ciphertext, cipher_len, hashed_key, iv, decryptedtext);
    printf("Sucesso na Decifragem.\n");
    printf("Conteudo Decifrado: %s\n", decryptedtext);

    // Verificação final
    if (strcmp(original_text, (char*)decryptedtext) == 0) {
        printf("\n[RESULTADO] TESTE PASSOU: O texto decifrado e igual ao original.\n");
    } else {
        printf("\n[RESULTADO] TESTE FALHOU: Os textos nao coincidem.\n");
    }

    return 0;
}