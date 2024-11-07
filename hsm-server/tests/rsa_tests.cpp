#include <iostream>
#include <gtest/gtest.h>
#include "rsa.h"
using namespace std;

TEST(RSATest, EncryptDecrypt_1024)
{
    const int KEY_SIZE = 1024;

    size_t pubLen = rsaGetPublicKeyLen(KEY_SIZE);
    size_t priLen = rsaGetPrivateKeyLen(KEY_SIZE);
    uint8_t *pubBuff = new uint8_t[pubLen];
    uint8_t *priBuff = new uint8_t[priLen];

    CK_RV rv1 = rsaGenerateKeys(KEY_SIZE, pubBuff, pubLen, priBuff, priLen);
    EXPECT_EQ(CKR_OK, rv1);

    const uint8_t plaintext[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    size_t plaintextLen = sizeof(plaintext);

    size_t ciphertextLen = rsaGetEncryptedLen(KEY_SIZE);
    uint8_t *ciphertext = new uint8_t[ciphertextLen];
    CK_RV rv2 = rsaEncrypt(plaintext, plaintextLen, pubBuff, pubLen, ciphertext,
                           ciphertextLen, KEY_SIZE);
    EXPECT_EQ(CKR_OK, rv2);

    size_t decryptedLen = rsaGetDecryptedLen(KEY_SIZE);
    uint8_t *decrypted = new uint8_t[decryptedLen];
    CK_RV rv3 = rsaDecrypt(ciphertext, ciphertextLen, priBuff, priLen,
                           decrypted, &decryptedLen, KEY_SIZE);
    EXPECT_EQ(CKR_OK, rv3);
    EXPECT_EQ(plaintextLen, decryptedLen);
    EXPECT_EQ(memcmp(plaintext, decrypted, plaintextLen), 0);

    delete[] pubBuff;
    delete[] priBuff;
    delete[] ciphertext;
    delete[] decrypted;
}

TEST(RSATest, EncryptDecrypt_2048)
{
    const int KEY_SIZE = 2048;

    size_t pubLen = rsaGetPublicKeyLen(KEY_SIZE);
    size_t priLen = rsaGetPrivateKeyLen(KEY_SIZE);
    uint8_t *pubBuff = new uint8_t[pubLen];
    uint8_t *priBuff = new uint8_t[priLen];

    CK_RV rv1 = rsaGenerateKeys(KEY_SIZE, pubBuff, pubLen, priBuff, priLen);
    EXPECT_EQ(CKR_OK, rv1);

    const uint8_t plaintext[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    size_t plaintextLen = sizeof(plaintext);

    size_t ciphertextLen = rsaGetEncryptedLen(KEY_SIZE);
    uint8_t *ciphertext = new uint8_t[ciphertextLen];
    CK_RV rv2 = rsaEncrypt(plaintext, plaintextLen, pubBuff, pubLen, ciphertext,
                           ciphertextLen, KEY_SIZE);
    EXPECT_EQ(CKR_OK, rv2);

    size_t decryptedLen = rsaGetDecryptedLen(KEY_SIZE);
    uint8_t *decrypted = new uint8_t[decryptedLen];
    CK_RV rv3 = rsaDecrypt(ciphertext, ciphertextLen, priBuff, priLen,
                           decrypted, &decryptedLen, KEY_SIZE);
    EXPECT_EQ(CKR_OK, rv3);
    EXPECT_EQ(plaintextLen, decryptedLen);
    EXPECT_EQ(memcmp(plaintext, decrypted, plaintextLen), 0);

    delete[] pubBuff;
    delete[] priBuff;
    delete[] ciphertext;
    delete[] decrypted;
}

TEST(RSATest, EncryptDecrypt_4096)
{
    const int KEY_SIZE = 4096;

    size_t pubLen = rsaGetPublicKeyLen(KEY_SIZE);
    size_t priLen = rsaGetPrivateKeyLen(KEY_SIZE);
    uint8_t *pubBuff = new uint8_t[pubLen];
    uint8_t *priBuff = new uint8_t[priLen];

    CK_RV rv1 = rsaGenerateKeys(KEY_SIZE, pubBuff, pubLen, priBuff, priLen);
    EXPECT_EQ(CKR_OK, rv1);

    const uint8_t plaintext[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    size_t plaintextLen = sizeof(plaintext);

    size_t ciphertextLen = rsaGetEncryptedLen(KEY_SIZE);
    uint8_t *ciphertext = new uint8_t[ciphertextLen];
    CK_RV rv2 = rsaEncrypt(plaintext, plaintextLen, pubBuff, pubLen, ciphertext,
                           ciphertextLen, KEY_SIZE);
    EXPECT_EQ(CKR_OK, rv2);

    size_t decryptedLen = rsaGetDecryptedLen(KEY_SIZE);
    uint8_t *decrypted = new uint8_t[decryptedLen];
    CK_RV rv3 = rsaDecrypt(ciphertext, ciphertextLen, priBuff, priLen,
                           decrypted, &decryptedLen, KEY_SIZE);
    EXPECT_EQ(CKR_OK, rv3);

    EXPECT_EQ(plaintextLen, decryptedLen);
    EXPECT_EQ(memcmp(plaintext, decrypted, plaintextLen), 0);

    delete[] pubBuff;
    delete[] priBuff;
    delete[] ciphertext;
    delete[] decrypted;
}