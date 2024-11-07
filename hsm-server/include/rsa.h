#ifndef __RSA_H__
#define __RSA_H__

#include "general.h"

CK_RV rsaGenerateKeys(size_t keySize, uint8_t *pubKey, size_t pubLen,
                      uint8_t *privKey, size_t privLen);
CK_RV rsaEncrypt(const uint8_t *plaintext, size_t plaintextLen,
                 const uint8_t *key, size_t keyLen, uint8_t *ciphertext,
                 size_t ciphertextLen, size_t keySize);
CK_RV rsaDecrypt(const uint8_t *ciphertext, size_t ciphertextLen,
                 const uint8_t *key, size_t keyLen, uint8_t *plaintext,
                 size_t *plaintextLen, size_t keySize);
size_t rsaGetEncryptedLen(size_t keySize);
size_t rsaGetPlainMaxLen(size_t keySize);
size_t rsaGetDecryptedLen(size_t keySize);
size_t rsaGetPublicKeyLen(size_t keySize);
size_t rsaGetPrivateKeyLen(size_t keySize);

#endif  // __RSA_H__