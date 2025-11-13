#ifndef AES_CRYPTO_H
#define AES_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

void aes_encrypt(const uint8_t *plaintext, size_t len, 
                 const uint8_t *key, uint8_t *ciphertext);
void aes_decrypt(const uint8_t *ciphertext, size_t len,
                 const uint8_t *key, uint8_t *plaintext);

#endif
