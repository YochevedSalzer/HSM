#include "../include/aes_stream.h"

void AESOfb::encryptStart(unsigned char block[], unsigned int inLen,
                          unsigned char *out, unsigned int outLen,
                          unsigned char *key, AESKeyLength keyLength)
{
    generateRandomIV(iv);
    memcpy(lastData, iv, BLOCK_BYTES_LEN);
    encrypt(block, inLen, key, out, outLen - BLOCK_BYTES_LEN, iv, lastData,
            keyLength);
    memcpy(out + outLen - BLOCK_BYTES_LEN, iv, BLOCK_BYTES_LEN);
    memcpy(lastBlock, out + outLen - BLOCK_BYTES_LEN * 2, BLOCK_BYTES_LEN);
    this->key = new unsigned char[keyLength];
    memcpy(this->key, key, keyLength);
    this->keyLength = keyLength;
}

void AESOfb::encryptContinue(unsigned char block[], unsigned int inLen,
                             unsigned char *out, unsigned int outLen)
{
    encrypt(block, inLen, key, out, outLen, lastBlock, lastData, keyLength);
    memcpy(lastBlock, out + outLen - BLOCK_BYTES_LEN, BLOCK_BYTES_LEN);
}

void AESOfb::decryptStart(unsigned char block[], unsigned int inLen,
                          unsigned char *out, unsigned int &outLen,
                          unsigned char *key, AESKeyLength keyLength)
{
    memcpy(lastData, iv, BLOCK_BYTES_LEN);
    memcpy(iv, block + inLen - BLOCK_BYTES_LEN, BLOCK_BYTES_LEN);
    decrypt(block, inLen - BLOCK_BYTES_LEN, key, out, outLen,
            block + inLen - BLOCK_BYTES_LEN, lastData, keyLength);
    memcpy(lastBlock, block + inLen - 2 * BLOCK_BYTES_LEN, BLOCK_BYTES_LEN);
}

void AESOfb::decryptContinue(unsigned char block[], unsigned int inLen,
                             unsigned char *out, unsigned int &outLen)
{
    decrypt(block, inLen, key, out, outLen, lastBlock, lastData, keyLength);
    memcpy(lastBlock, block + inLen - BLOCK_BYTES_LEN, BLOCK_BYTES_LEN);
}

void AESOfb::encrypt(unsigned char in[], unsigned int inLen, unsigned char *key,
                     unsigned char *out, unsigned int outLen,
                     const unsigned char *iv, unsigned char *lastData,
                     AESKeyLength keyLength)
{
    size_t paddedLength = getPaddedLength(inLen);
    unsigned char *paddedIn = new unsigned char[paddedLength];
    padMessage(in, inLen, paddedIn);
    unsigned char block[BLOCK_BYTES_LEN];
    unsigned char feedback[BLOCK_BYTES_LEN];
    unsigned char *roundKeys =
        new unsigned char[(aesKeyLengthData[keyLength].numRound + 1) *
                          NUM_BLOCKS * 4];
    keyExpansion(key, roundKeys, keyLength);
    memcpy(feedback, lastData, BLOCK_BYTES_LEN);
    for (unsigned int i = 0; i < outLen; i += BLOCK_BYTES_LEN) {
        encryptBlock(feedback, block, roundKeys, keyLength);
        xorBlocks(paddedIn + i, block, out + i, BLOCK_BYTES_LEN);
        for (unsigned int j = 0; j < BLOCK_BYTES_LEN; ++j)
            out[i + j] = paddedIn[i + j] ^ block[j];
        memcpy(feedback, block, BLOCK_BYTES_LEN);
        memcpy(lastData, feedback, BLOCK_BYTES_LEN);
    }
    delete[] paddedIn;
    delete[] roundKeys;
}

void AESOfb::decrypt(unsigned char in[], unsigned int inLen, unsigned char *key,
                     unsigned char *out, unsigned int &outLen,
                     const unsigned char *iv, unsigned char *lastData,
                     AESKeyLength keyLength)
{
    checkLength(inLen);
    unsigned char block[BLOCK_BYTES_LEN];
    outLen = inLen;
    unsigned char feedback[BLOCK_BYTES_LEN];
    unsigned char *roundKeys =
        new unsigned char[(aesKeyLengthData[keyLength].numRound + 1) *
                          NUM_BLOCKS * 4];
    keyExpansion(key, roundKeys, keyLength);
    memcpy(feedback, lastData, BLOCK_BYTES_LEN);
    for (unsigned int i = 0; i < outLen; i += BLOCK_BYTES_LEN) {
        encryptBlock(feedback, block, roundKeys, keyLength);
        xorBlocks(in + i, block, out + i, BLOCK_BYTES_LEN);
        memcpy(feedback, block, BLOCK_BYTES_LEN);
        memcpy(lastData, feedback, BLOCK_BYTES_LEN);
    }
    outLen = getUnpadMessageLength(out, inLen);
    delete[] roundKeys;
}