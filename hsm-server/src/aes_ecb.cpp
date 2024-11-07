#include "../include/aes_stream.h"
#include <thread>
#include <vector>
#include <cstring>
#include "../include/debug_utils.h"
#include "../include/aes_stream.h"
/**
 Encrypts a single block of data using AES in ECB mode.
 This function wraps the `encryptBlock` function to allow it to be used
 in a threaded context. It performs AES encryption on a single block of
 plaintext using the provided round keys and key length.
 @param in        Pointer to the input block of plaintext data (BLOCK_BYTES_LEN bytes).
 @param out       Pointer to the output block where the encrypted ciphertext will be stored (BLOCK_BYTES_LEN bytes).
 @param roundKeys Pointer to the array of round keys used for AES encryption.
 @param keyLength The length of the AES key being used (e.g., AES_KEY_LENGTH_128, AES_KEY_LENGTH_192, AES_KEY_LENGTH_256).
 */
void encryptBlockThreadedECB(const unsigned char in[], unsigned char out[],
                             unsigned char *roundKeys, AESKeyLength keyLength)
{
    encryptBlock(in, out, roundKeys, keyLength);
}

/**
 Encrypts multiple blocks of data using AES in ECB mode with multithreading.
 This function divides the input plaintext into blocks and encrypts each block
 in parallel using multiple threads. The function ensures that each block is
 encrypted using AES in ECB mode, and all threads are joined before completing.
 @param plaintext Pointer to the input plaintext data to be encrypted.
 @param ciphertext Pointer to the buffer where the encrypted ciphertext will be stored.
 @param length The total length of the plaintext data (must be a multiple of BLOCK_BYTES_LEN).
 @param roundKeys Pointer to the array of round keys used for AES encryption.
 @param keyLength The length of the AES key being used (e.g., AES_KEY_LENGTH_128, AES_KEY_LENGTH_192, AES_KEY_LENGTH_256).
 */
void encryptECBMultithreaded(const unsigned char *plaintext,
                             unsigned char *ciphertext, unsigned int length,
                             unsigned char *roundKeys, AESKeyLength keyLength)
{
    unsigned int numBlocks = length / BLOCK_BYTES_LEN;
    std::vector<std::thread> threads;

    for (unsigned int i = 0; i < numBlocks; ++i) {
        threads.push_back(std::thread(
            encryptBlockThreadedECB, &plaintext[i * BLOCK_BYTES_LEN],
            &ciphertext[i * BLOCK_BYTES_LEN], roundKeys, keyLength));
    }

    for (auto &th : threads) {
        th.join();
    }
}

/**
 Decrypts a single block of data using AES in ECB mode.
 This function wraps the `decryptBlock` function to allow it to be used
 in a threaded context. It performs AES decryption on a single block of
 ciphertext using the provided round keys and key length.
 @param input     Pointer to the input block of ciphertext data (BLOCK_BYTES_LEN bytes).
 @param output    Pointer to the output block where the decrypted plaintext will be stored (BLOCK_BYTES_LEN bytes).
 @param roundKeys Pointer to the array of round keys used for AES decryption.
 @param keyLength The length of the AES key being used (e.g., AES_KEY_LENGTH_128, AES_KEY_LENGTH_192, AES_KEY_LENGTH_256).
 */
void decryptBlockThreadedECB(const unsigned char *input, unsigned char *output,
                             unsigned char *roundKeys, AESKeyLength keyLength)
{
    decryptBlock(input, output, roundKeys, keyLength);
}

/**
 Decrypts multiple blocks of data using AES in ECB mode with multithreading.
 This function divides the input ciphertext into blocks and decrypts each block
 in parallel using multiple threads in ECB (Electronic Codebook) mode. The function
 ensures that each block is decrypted using AES with the provided round keys, and
 all threads are joined before completing.
 @param ciphertext Pointer to the input ciphertext data to be decrypted.
 @param plaintext  Pointer to the buffer where the decrypted plaintext will be stored.
 @param length     The total length of the ciphertext data (must be a multiple of BLOCK_BYTES_LEN).
 @param roundKeys  Pointer to the array of round keys used for AES decryption.
 @param keyLength  The length of the AES key being used (e.g., AES_KEY_LENGTH_128, AES_KEY_LENGTH_192, AES_KEY_LENGTH_256).
 */
void decryptECBMultithreaded(const unsigned char *ciphertext,
                             unsigned char *plaintext, unsigned int length,
                             unsigned char *roundKeys, AESKeyLength keyLength)
{
    unsigned int numBlocks = length / BLOCK_BYTES_LEN;
    std::vector<std::thread> threads;

    for (unsigned int i = 0; i < numBlocks; i++)
        threads.push_back(std::thread(
            decryptBlockThreadedECB, &ciphertext[i * BLOCK_BYTES_LEN],
            &plaintext[i * BLOCK_BYTES_LEN], roundKeys, keyLength));

    for (auto &th : threads)
        th.join();
}

void AESEcb::encryptStart(unsigned char block[], unsigned int inLen,
                          unsigned char *out, unsigned int outLen,
                          unsigned char *key, AESKeyLength keyLength)
{
    encrypt(block, inLen, key, out, outLen, nullptr, nullptr, keyLength);
    this->key = new unsigned char[keyLength];
    memcpy(this->key, key, keyLength);
    this->keyLength = keyLength;
}

void AESEcb::encryptContinue(unsigned char block[], unsigned int inLen,
                             unsigned char *out, unsigned int outLen)
{
    encrypt(block, inLen, key, out, outLen, nullptr, nullptr, keyLength);
}

void AESEcb::decryptStart(unsigned char block[], unsigned int inLen,
                          unsigned char *out, unsigned int &outLen,
                          unsigned char *key, AESKeyLength keyLength)
{
    decrypt(block, inLen, key, out, outLen, nullptr, nullptr, keyLength);
}

void AESEcb::decryptContinue(unsigned char block[], unsigned int inLen,
                             unsigned char *out, unsigned int &outLen)
{
    decrypt(block, inLen, key, out, outLen, nullptr, nullptr, keyLength);
}

void AESEcb::encrypt(unsigned char in[], unsigned int inLen, unsigned char *key,
                     unsigned char *out, unsigned int outLen,
                     const unsigned char *iv, unsigned char *lastData,
                     AESKeyLength keyLength)
{
    size_t paddedLength = getPaddedLength(inLen);
    unsigned char *paddedIn = new unsigned char[paddedLength];
    padMessage(in, inLen, paddedIn);
    unsigned char block[BLOCK_BYTES_LEN];
    unsigned char *roundKeys =
        new unsigned char[(aesKeyLengthData[keyLength].numRound + 1) *
                          NUM_BLOCKS * 4];
    keyExpansion(key, roundKeys, keyLength);
    for (unsigned int i = 0; i < outLen; i += BLOCK_BYTES_LEN) {
        memcpy(block, paddedIn + i, BLOCK_BYTES_LEN);
        encryptECBMultithreaded(block, out + i, BLOCK_BYTES_LEN, roundKeys,
                                keyLength);
    }
    delete[] paddedIn;
    delete[] roundKeys;
}

void AESEcb::decrypt(unsigned char in[], unsigned int inLen, unsigned char *key,
                     unsigned char *out, unsigned int &outLen,
                     const unsigned char *iv, unsigned char *lastData,
                     AESKeyLength keyLength)
{
    checkLength(inLen);
    outLen = inLen;
    unsigned char *roundKeys =
        new unsigned char[(aesKeyLengthData[keyLength].numRound + 1) *
                          NUM_BLOCKS * 4];
    keyExpansion(key, roundKeys, keyLength);
    for (unsigned int i = 0; i < outLen; i += BLOCK_BYTES_LEN)
        decryptECBMultithreaded(in, out, outLen, roundKeys, keyLength);
    outLen = getUnpadMessageLength(out, inLen);
    delete[] roundKeys;
}