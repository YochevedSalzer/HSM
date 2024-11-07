#include "../include/aes_stream.h"

/**
 * @brief Initializes the AES CFB encryption process.
 *
 * This function generates a random IV, encrypts the input block, 
 * and stores the last encrypted block for continuation of the encryption process.
 *
 * @param block The input data block to be encrypted.
 * @param inLen The length of the input block.
 * @param out The output buffer to store the encrypted data.
 * @param outLen The length of the output buffer.
 * @param key The AES key used for encryption.
 * @param keyLength The length of the AES key (128, 192, or 256 bits).
 */
void AESCfb::encryptStart(unsigned char block[], unsigned int inLen,
                          unsigned char *out, unsigned int outLen,
                          unsigned char *key, AESKeyLength keyLength)
{
    generateRandomIV(iv);
    encrypt(block, inLen, key, out, outLen - BLOCK_BYTES_LEN, iv, nullptr,
            keyLength);
    memcpy(out + outLen - BLOCK_BYTES_LEN, iv, BLOCK_BYTES_LEN);
    memcpy(lastBlock, out + outLen - BLOCK_BYTES_LEN * 2, BLOCK_BYTES_LEN);
    this->key = new unsigned char[keyLength];
    memcpy(this->key, key, keyLength);
    this->keyLength = keyLength;
}

/**
 * @brief Continues the AES CFB encryption process.
 *
 * This function encrypts additional data blocks, using the last encrypted block as IV for the next block.
 *
 * @param block The input data block to be encrypted.
 * @param inLen The length of the input block.
 * @param out The output buffer to store the encrypted data.
 * @param outLen The length of the output buffer.
 */
void AESCfb::encryptContinue(unsigned char block[], unsigned int inLen,
                             unsigned char *out, unsigned int outLen)
{
    encrypt(block, inLen, key, out, outLen, lastBlock, nullptr, keyLength);
    memcpy(lastBlock, out + outLen - BLOCK_BYTES_LEN, BLOCK_BYTES_LEN);
}

/**
 * @brief Initializes the AES CFB decryption process.
 *
 * This function retrieves the IV from the input block, performs AES decryption,
 * and stores the last block to be used in the continuation of the decryption process.
 *
 * @param block The input data block to be decrypted.
 * @param inLen The length of the input block.
 * @param out The output buffer to store the decrypted data.
 * @param outLen The length of the output buffer (output parameter).
 * @param key The AES key used for decryption.
 * @param keyLength The length of the AES key (128, 192, or 256 bits).
 */
void AESCfb::decryptStart(unsigned char block[], unsigned int inLen,
                          unsigned char *out, unsigned int &outLen,
                          unsigned char *key, AESKeyLength keyLength)
{
    memcpy(this->iv, block + inLen - BLOCK_BYTES_LEN, BLOCK_BYTES_LEN);
    decrypt(block, inLen - BLOCK_BYTES_LEN, key, out, outLen,
            block + inLen - BLOCK_BYTES_LEN, nullptr, keyLength);
    memcpy(lastBlock, block + inLen - 2 * BLOCK_BYTES_LEN, BLOCK_BYTES_LEN);
}

/**
 * @brief Continues the AES CFB decryption process.
 *
 * This function decrypts additional data blocks, using the last encrypted block as IV for the next block.
 *
 * @param block The input data block to be decrypted.
 * @param inLen The length of the input block.
 * @param out The output buffer to store the decrypted data.
 * @param outLen The length of the output buffer (output parameter).
 */
void AESCfb::decryptContinue(unsigned char block[], unsigned int inLen,
                             unsigned char *out, unsigned int &outLen)
{
    decrypt(block, inLen, key, out, outLen, lastBlock, nullptr, keyLength);
    memcpy(lastBlock, block + inLen - BLOCK_BYTES_LEN, BLOCK_BYTES_LEN);
}

/**
 * @brief Encrypts a padded message using AES in CFB mode.
 *
 * This function performs AES encryption on padded input data in CFB mode.
 * It generates the round keys and applies XOR between the input data and the encrypted feedback block.
 *
 * @param in The input data to be encrypted (padded).
 * @param inLen The length of the input data.
 * @param key The AES key used for encryption.
 * @param out The output buffer to store the encrypted data.
 * @param outLen The length of the output buffer.
 * @param iv The initialization vector used for the first encryption block.
 * @param lastData Optional parameter for chaining blocks (not used in this implementation).
 * @param keyLength The length of the AES key (128, 192, or 256 bits).
 */
void AESCfb::encrypt(unsigned char in[], unsigned int inLen, unsigned char *key,
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
    memcpy(feedback, iv, BLOCK_BYTES_LEN);
    for (unsigned int i = 0; i < outLen; i += BLOCK_BYTES_LEN) {
        encryptBlock(feedback, block, roundKeys, keyLength);
        xorBlocks(paddedIn + i, block, out + i, BLOCK_BYTES_LEN);
        memcpy(feedback, out + i, BLOCK_BYTES_LEN);
    }
    delete[] roundKeys;
    delete[] paddedIn;
}

/**
 * @brief Decrypts an AES-encrypted message using CFB mode.
 *
 * This function performs AES decryption on the input data in CFB mode.
 * It generates the round keys, decrypts the input, and applies XOR between the input data and the encrypted feedback block.
 *
 * @param in The input data to be decrypted.
 * @param inLen The length of the input data.
 * @param key The AES key used for decryption.
 * @param out The output buffer to store the decrypted data.
 * @param outLen The length of the output buffer (output parameter).
 * @param iv The initialization vector used for the first decryption block.
 * @param lastData Optional parameter for chaining blocks (not used in this implementation).
 * @param keyLength The length of the AES key (128, 192, or 256 bits).
 */
void AESCfb::decrypt(unsigned char in[], unsigned int inLen, unsigned char *key,
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
    memcpy(feedback, iv, BLOCK_BYTES_LEN);
    for (unsigned int i = 0; i < outLen; i += BLOCK_BYTES_LEN) {
        encryptBlock(feedback, block, roundKeys, keyLength);
        xorBlocks(in + i, block, out + i, BLOCK_BYTES_LEN);
        memcpy(feedback, in + i, BLOCK_BYTES_LEN);
    }
    outLen = getUnpadMessageLength(out, inLen);
    delete[] roundKeys;
}
