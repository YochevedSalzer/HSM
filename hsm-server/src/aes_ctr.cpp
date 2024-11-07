#include "../include/aes_stream.h"
#include <thread>
#include <vector>
#include <cstring>

/**
 Encrypts a single block of data using AES in CTR mode.
 This function handles the encryption of a single block in CTR (Counter) mode.
 It computes the counter value based on the given initialization vector (IV) and
 block index, encrypts the counter, and then XORs the encrypted counter with the
 input block to produce the output block.
 @param input     Pointer to the input block of plaintext data (BLOCK_BYTES_LEN bytes).
 @param output    Pointer to the output block where the encrypted ciphertext will be stored (BLOCK_BYTES_LEN bytes).
 @param roundKeys Pointer to the array of round keys used for AES encryption.
 @param keyLength The length of the AES key being used (e.g., AES_KEY_LENGTH_128, AES_KEY_LENGTH_192, AES_KEY_LENGTH_256).
 @param iv        Pointer to the initialization vector (IV) used for the counter.
 @param blockIndex The index of the current block to be encrypted, used to compute the counter value.
 */
void encryptBlockThreadedCTR(const unsigned char *input, unsigned char *output,
                             unsigned char *roundKeys, AESKeyLength keyLength,
                             const unsigned char *lastData,
                             unsigned int blockIndex)
{
    unsigned char block[BLOCK_BYTES_LEN];
    unsigned char counter[BLOCK_BYTES_LEN];

    memcpy(counter, lastData, BLOCK_BYTES_LEN);

    for (int j = BLOCK_BYTES_LEN - 1, k = blockIndex; j >= 0; --j) {
        counter[j] += (k % 256);
        if (counter[j] != 0)
            break;
        k /= 256;
    }

    encryptBlock(counter, block, roundKeys, keyLength);

    xorBlocks(block, input, output, BLOCK_BYTES_LEN);
}

/**
 Encrypts multiple blocks of data using AES in CTR mode with multithreading.
 This function divides the input plaintext into blocks and encrypts each block
 in parallel using multiple threads in CTR (Counter) mode. The function ensures
 that each block is encrypted using AES with a counter value derived from the
 initialization vector (IV) and block index, and all threads are joined before completing.
 @param plaintext Pointer to the input plaintext data to be encrypted.
 @param ciphertext Pointer to the buffer where the encrypted ciphertext will be stored.
 @param length The total length of the plaintext data (must be a multiple of BLOCK_BYTES_LEN).
 @param roundKeys Pointer to the array of round keys used for AES encryption.
 @param keyLength The length of the AES key being used (e.g., AES_KEY_LENGTH_128, AES_KEY_LENGTH_192, AES_KEY_LENGTH_256).
 @param iv        Pointer to the initialization vector (IV) used for the counter.
 */
void encryptCTRMultithreaded(const unsigned char *plaintext,
                             unsigned char *ciphertext, unsigned int length,
                             unsigned char *roundKeys, AESKeyLength keyLength,
                             const unsigned char *lastData)
{
    unsigned int numBlocks = length / BLOCK_BYTES_LEN;
    std::vector<std::thread> threads;

    for (unsigned int i = 0; i < numBlocks; ++i) {
        threads.push_back(std::thread(encryptBlockThreadedCTR,
                                      &plaintext[i * BLOCK_BYTES_LEN],
                                      &ciphertext[i * BLOCK_BYTES_LEN],
                                      roundKeys, keyLength, lastData, i));
    }

    for (auto &th : threads) {
        th.join();
    }
}

/**
 Decrypts a single block of data using AES in CTR mode.
 This function handles the decryption of a single block in CTR (Counter) mode.
 It computes the counter value based on the given initialization vector (IV) and
 block index, encrypts the counter, and then XORs the encrypted counter with the
 input block to produce the output block.
 @param input     Pointer to the input block of ciphertext data (BLOCK_BYTES_LEN bytes).
 @param output    Pointer to the output block where the decrypted plaintext will be stored (BLOCK_BYTES_LEN bytes).
 @param roundKeys Pointer to the array of round keys used for AES encryption.
 @param keyLength The length of the AES key being used (e.g., AES_KEY_LENGTH_128, AES_KEY_LENGTH_192, AES_KEY_LENGTH_256).
 @param iv        Pointer to the initialization vector (IV) used for the counter.
 @param blockIndex The index of the current block to be decrypted, used to compute the counter value.
 */
void decryptBlockThreadedCTR(const unsigned char *input, unsigned char *output,
                             unsigned char *roundKeys, AESKeyLength keyLength,
                             const unsigned char *lastData,
                             unsigned int blockIndex)
{
    unsigned char block[BLOCK_BYTES_LEN];
    unsigned char counter[BLOCK_BYTES_LEN];

    memcpy(counter, lastData, BLOCK_BYTES_LEN);

    for (int j = BLOCK_BYTES_LEN - 1, k = blockIndex; j >= 0; --j) {
        counter[j] += (k % 256);
        if (counter[j] != 0)
            break;
        k /= 256;
    }

    encryptBlock(counter, block, roundKeys, keyLength);

    xorBlocks(block, input, output, BLOCK_BYTES_LEN);
}

/**
 Decrypts multiple blocks of data using AES in CTR mode with multithreading.
 This function divides the input ciphertext into blocks and decrypts each block
 in parallel using multiple threads in CTR (Counter) mode. The function ensures
 that each block is decrypted using AES with a counter value derived from the
 initialization vector (IV) and block index, and all threads are joined before completing.
 @param ciphertext Pointer to the input ciphertext data to be decrypted.
 @param plaintext  Pointer to the buffer where the decrypted plaintext will be stored.
 @param length     The total length of the ciphertext data (must be a multiple of BLOCK_BYTES_LEN).
 @param roundKeys  Pointer to the array of round keys used for AES encryption.
 @param keyLength  The length of the AES key being used (e.g., AES_KEY_LENGTH_128, AES_KEY_LENGTH_192, AES_KEY_LENGTH_256).
 @param iv        Pointer to the initialization vector (IV) used for the counter.
 */
void decryptCTRMultithreaded(const unsigned char *ciphertext,
                             unsigned char *plaintext, unsigned int length,
                             unsigned char *roundKeys, AESKeyLength keyLength,
                             const unsigned char *lastData)
{
    unsigned int numBlocks = length / BLOCK_BYTES_LEN;
    std::vector<std::thread> threads;

    for (unsigned int i = 0; i < numBlocks; ++i)
        threads.push_back(std::thread(decryptBlockThreadedCTR,
                                      &ciphertext[i * BLOCK_BYTES_LEN],
                                      &plaintext[i * BLOCK_BYTES_LEN],
                                      roundKeys, keyLength, lastData, i));

    for (auto &th : threads)
        th.join();
}

void AESCtr::encryptStart(unsigned char block[], unsigned int inLen,
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

void AESCtr::encryptContinue(unsigned char block[], unsigned int inLen,
                             unsigned char *out, unsigned int outLen)
{
    encrypt(block, inLen, key, out, outLen, lastData, lastData, keyLength);
    memcpy(lastBlock, out + outLen - BLOCK_BYTES_LEN, BLOCK_BYTES_LEN);
}

void AESCtr::decryptStart(unsigned char block[], unsigned int inLen,
                          unsigned char *out, unsigned int &outLen,
                          unsigned char *key, AESKeyLength keyLength)
{
    memcpy(lastData, iv, BLOCK_BYTES_LEN);
    memcpy(iv, block + inLen - BLOCK_BYTES_LEN, BLOCK_BYTES_LEN);
    decrypt(block, inLen - BLOCK_BYTES_LEN, key, out, outLen,
            block + inLen - BLOCK_BYTES_LEN, lastData, keyLength);
    memcpy(lastBlock, block + inLen - 2 * BLOCK_BYTES_LEN, BLOCK_BYTES_LEN);
}

void AESCtr::decryptContinue(unsigned char block[], unsigned int inLen,
                             unsigned char *out, unsigned int &outLen)
{
    decrypt(block, inLen, key, out, outLen, lastData, lastData, keyLength);
    memcpy(lastBlock, block + inLen - BLOCK_BYTES_LEN, BLOCK_BYTES_LEN);
}

void AESCtr::encrypt(unsigned char in[], unsigned int inLen, unsigned char *key,
                     unsigned char *out, unsigned int outLen,
                     const unsigned char *iv, unsigned char *lastData,
                     AESKeyLength keyLength)
{
    size_t paddedLength = getPaddedLength(inLen);
    unsigned char *paddedIn = new unsigned char[paddedLength];
    padMessage(in, inLen, paddedIn);

    unsigned char *roundKeys =
        new unsigned char[(aesKeyLengthData[keyLength].numRound + 1) *
                          NUM_BLOCKS * AES_STATE_ROWS];
    keyExpansion(key, roundKeys, keyLength);

    encryptCTRMultithreaded(paddedIn, out, outLen, roundKeys, keyLength, iv);
    delete[] paddedIn;
    delete[] roundKeys;
}

void AESCtr::decrypt(unsigned char in[], unsigned int inLen, unsigned char *key,
                     unsigned char *out, unsigned int &outLen,
                     const unsigned char *iv, unsigned char *lastData,
                     AESKeyLength keyLength)
{
    checkLength(inLen);
    outLen = inLen;

    unsigned char *roundKeys =
        new unsigned char[(aesKeyLengthData[keyLength].numRound + 1) *
                          NUM_BLOCKS * AES_STATE_ROWS];
    keyExpansion(key, roundKeys, keyLength);

    decryptCTRMultithreaded(in, out, outLen, roundKeys, keyLength, iv);
    outLen = getUnpadMessageLength(out, inLen);
    delete[] roundKeys;
}