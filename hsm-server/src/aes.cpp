#include "../include/aes.h"
#include <cstddef>
#include <stdexcept>
#include <random>
#ifdef USE_SYCL
#include <cstring>
#include <stdexcept>
#include <random>
#include <CL/sycl.hpp>
#include <iostream>
#include <fstream>
using namespace cl::sycl;
#endif

/**
 @brief Generates a random Initialization Vector (IV) for cryptographic purposes.
 This function generates a BLOCK_BYTES_LEN-byte random IV, which is commonly used in cryptographic algorithms
 such as AES (Advanced Encryption Standard) in CBC (Cipher Block Chaining) mode.
 The IV ensures that the same plaintext block will result in a different ciphertext block
 when encrypted with the same key. 
 @param iv Pointer to an array of BLOCK_BYTES_LEN unsigned char (bytes) where the generated IV will be stored.
 @note The function uses the C++ standard library's random number generator to produce
       a uniformly distributed sequence of bytes.
 */
void generateRandomIV(unsigned char *iv)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (unsigned int i = 0; i < BLOCK_BYTES_LEN; i++)
        iv[i] = static_cast<unsigned char>(dis(gen));
}

unsigned int getPaddedLength(unsigned int originalLength)
{
    unsigned int paddedLength =
        ((originalLength + BLOCK_BYTES_LEN - 1) / BLOCK_BYTES_LEN) *
        BLOCK_BYTES_LEN;
    if (paddedLength == originalLength) {
        paddedLength += BLOCK_BYTES_LEN;
    }

    return paddedLength;
}

/** 
 @brief Pads the input message to ensure it is a multiple of the block size.
 @param message The message to be padded.
 @param originalLength The original length of the message.
 */
void padMessage(unsigned char *originalMessage, unsigned int originalLength,
                unsigned char *paddedMessage)
{
    size_t paddedLength = getPaddedLength(originalLength);
    unsigned char paddingValue =
        static_cast<unsigned char>(paddedLength - originalLength);
    memcpy(paddedMessage, originalMessage, originalLength);
    for (size_t i = originalLength; i < paddedLength; i++)
        paddedMessage[i] = paddingValue;
}

/**
 @brief Removes padding from the message.
 @param message The padded message.
 @param paddedLength The length of the padded message
 */
unsigned int getUnpadMessageLength(unsigned char *message,
                                   unsigned int paddedLength)
{
    unsigned char paddingValue = message[paddedLength - 1];
    return paddedLength - paddingValue;
}

/**
 @brief Generates a random AES key of the specified length.
 @param keyLength The length of the key (128, 192, or 256 bits).
 @return A pointer to the generated key.
 */
void generateKey(unsigned char *key, AESKeyLength keyLength)
{
    // Allocate memory for the key

    // Initialize a random device and a random number generator
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned char> dis(0, 255);

    // Fill the key with random bytes
    for (int i = 0; i < aesKeyLengthData[keyLength].keySize; i++)
        key[i] = dis(gen);
}

/**
 @brief Checks if the input length is a multiple of the block length.
 @param len The length of the input data.
 @throws std::length_error if the length is not a multiple of the block length.
 */
void checkLength(unsigned int len)
{
    if (len % BLOCK_BYTES_LEN != 0)
        throw std::length_error("Plaintext length must be divisible by " +
                                std::to_string(BLOCK_BYTES_LEN));
}

#ifdef USE_SYCL

/**
 @brief Encrypts a single block of data using SYCL.
 @param in The input block to be encrypted.
 @param out The output block to store the encrypted data.
 @param roundKeys The expanded key for encryption.
 */
void encryptBlock(const unsigned char in[], unsigned char out[],
                  unsigned char *roundKeys, AESKeyLength keyLength)
{
    queue queue;
    // State array initialization
    unsigned char state[AES_STATE_ROWS][NUM_BLOCKS];

    // Buffers for SYCL
    buffer<unsigned char, 1> in_buf(in, range<1>(AES_STATE_ROWS * NUM_BLOCKS));
    buffer<unsigned char, 1> state_buf(reinterpret_cast<unsigned char *>(state),
                                       range<1>(AES_STATE_ROWS * NUM_BLOCKS));
    buffer<unsigned char, 1> roundKeys_buf(
        roundKeys,
        range<1>(AES_STATE_ROWS * (aesKeyLengthData[keyLength].numRound + 1) *
                 NUM_BLOCKS));
    buffer<unsigned char, 1> out_buf(out,
                                     range<1>(AES_STATE_ROWS * NUM_BLOCKS));

    // Initialize state array with input block
    queue
        .submit([&](handler &handler) {
            auto in_acc = in_buf.get_access<access::mode::read>(handler);
            auto state_acc = state_buf.get_access<access::mode::write>(handler);
            handler.parallel_for(range<1>(AES_STATE_ROWS * NUM_BLOCKS),
                                 [=](id<1> idx) {
                                     // Row
                                     unsigned int i = idx % AES_STATE_ROWS;
                                     // Column
                                     unsigned int j = idx / AES_STATE_ROWS;
                                     state_acc[i * NUM_BLOCKS + j] =
                                         in_acc[i + AES_STATE_ROWS * j];
                                 });
        })
        .wait();

    // Initial round key addition
    addRoundKey(state, roundKeys);

    // Main rounds
    for (unsigned int round = 1; round < aesKeyLengthData[keyLength].numRound;
         round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys + round * AES_STATE_ROWS * NUM_BLOCKS);
    }

    // Final round
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys + aesKeyLengthData[keyLength].numRound *
                                       AES_STATE_ROWS * NUM_BLOCKS);

    // Copy state array to output block
    queue
        .submit([&](handler &handler) {
            auto state_acc = state_buf.get_access<access::mode::read>(handler);
            auto out_acc = out_buf.get_access<access::mode::write>(handler);
            handler.parallel_for(
                range<1>(AES_STATE_ROWS * NUM_BLOCKS), [=](id<1> idx) {
                    unsigned int i = idx % AES_STATE_ROWS;  // Row
                    unsigned int j = idx / AES_STATE_ROWS;  // Column
                    out_acc[i + AES_STATE_ROWS * j] =
                        state_acc[i * NUM_BLOCKS + j];
                });
        })
        .wait();
}

/**
 @brief Decrypts a single block of data using SYCL.
 Uses SYCL to perform AES decryption on the input block and stores the result in the output block.
 @param in Input block to be decrypted.
 @param[out] out Output block to store the decrypted data.
 @param roundKeys Expanded key for decryption.
 */
void decryptBlock(const unsigned char in[], unsigned char out[],
                  unsigned char *roundKeys, AESKeyLength keyLength)
{
    unsigned char state[AES_STATE_ROWS][NUM_BLOCKS];
    unsigned int i, j, round;

    // Initialize state array with input block
    for (i = 0; i < AES_STATE_ROWS; i++)
        for (j = 0; j < NUM_BLOCKS; j++)
            state[i][j] = in[i + AES_STATE_ROWS * j];

    // Initial round key addition
    addRoundKey(state, roundKeys + aesKeyLengthData[keyLength].numRound *
                                       AES_STATE_ROWS * NUM_BLOCKS);

    // Main rounds
    for (round = aesKeyLengthData[keyLength].numRound - 1; round >= 1;
         round--) {
        invSubBytes(state);
        invShiftRows(state);
        addRoundKey(state, roundKeys + round * AES_STATE_ROWS * NUM_BLOCKS);
        invMixColumns(state);
    }

    // Final round
    invSubBytes(state);
    invShiftRows(state);
    addRoundKey(state, roundKeys);

    // Copy state array to output block
    for (i = 0; i < AES_STATE_ROWS; i++)
        for (j = 0; j < NUM_BLOCKS; j++)
            out[i + AES_STATE_ROWS * j] = state[i][j];
}

/**
 @brief Multiplies a byte by x in GF(2^8).
 Multiplies the input byte by 2 in GF(2^8) and applies the irreducible polynomial if necessary.
 @param b Input byte.
 @return Result of the multiplication.
 */
unsigned char xtime(unsigned char b)
{
    return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}

/**
 @brief Multiplies two bytes in GF(2^8).
 Multiplies two bytes using the Galois field (GF) arithmetic.
 @param x First byte.
 @param y Second byte.
 @return Result of the multiplication.
 */
unsigned char multiply(unsigned char x, unsigned char y)
{
    unsigned char result = 0;
    unsigned char temp = y;
    for (int i = 0; i < 8; i++) {
        if (x & 1)
            result ^= temp;
        bool carry = temp & 0x80;
        temp <<= 1;
        if (carry)
            temp ^= 0x1b;
        x >>= 1;
    }

    return result;
}

/**
 @brief Applies the SubBytes transformation using SYCL.
 Substitutes bytes in the state array using the S-box.
 @param state 2D array representing the state of the AES block.
 */
void subBytes(unsigned char state[AES_STATE_ROWS][NUM_BLOCKS])
{
    queue queue;
    buffer<unsigned char, 2> stateBuffer(state[0],
                                         range<2>(AES_STATE_ROWS, NUM_BLOCKS));
    buffer<unsigned char, 2> sBoxBuffer(
        sBox[0], range<2>(BLOCK_BYTES_LEN, BLOCK_BYTES_LEN));
    queue
        .submit([&](handler &handler) {
            auto stateAcc =
                stateBuffer.get_access<access::mode::read_write>(handler);
            auto sBoxAcc = sBoxBuffer.get_access<access::mode::read>(handler);
            handler.parallel_for<class SubBytes>(
                range<2>(AES_STATE_ROWS, NUM_BLOCKS), [=](id<2> id) {
                    size_t i = id[0];
                    size_t j = id[1];
                    stateAcc[i][j] = sBoxAcc[state[i][j] / BLOCK_BYTES_LEN]
                                            [state[i][j] % BLOCK_BYTES_LEN];
                });
        })
        .wait();
}

/**
 @brief Applies the ShiftRows transformation using SYCL.
 Shifts the rows of the state array in the AES block.
 @param state 2D array representing the state of the AES block.
 */
void shiftRows(unsigned char state[AES_STATE_ROWS][NUM_BLOCKS])
{
    queue queue;
    queue
        .submit([&](handler &handler) {
            handler.parallel_for(range<1>(AES_STATE_ROWS), [=](id<1> i) {
                unsigned char tmp[NUM_BLOCKS];
                for (size_t k = 0; k < NUM_BLOCKS; k++)
                    tmp[k] = state[i][(k + i) % NUM_BLOCKS];
                for (size_t k = 0; k < NUM_BLOCKS; k++)
                    state[i][k] = tmp[k];
            });
        })
        .wait();
}

/**
 @brief Applies the MixColumns transformation using SYCL.
 Mixes the columns of the state array in the AES block.
 @param state 2D array representing the state of the AES block.
 */
void mixColumns(unsigned char state[AES_STATE_ROWS][NUM_BLOCKS])
{
    queue queue;

    queue
        .parallel_for(range<1>(AES_STATE_ROWS),
                      [=](id<1> idx) {
                          size_t i = idx[0];
                          unsigned char a[AES_STATE_ROWS];
                          unsigned char b[AES_STATE_ROWS];

                          for (size_t j = 0; j < AES_STATE_ROWS; j++) {
                              a[j] = state[j][i];
                              b[j] = xtime(state[j][i]);
                          }

                          state[0][i] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
                          state[1][i] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
                          state[2][i] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
                          state[3][i] = b[0] ^ a[0] ^ a[1] ^ a[2] ^ b[3];
                      })
        .wait();
}

/**
 @brief Applies the AddRoundKey transformation using SYCL.
 XORs the state array with the round key in the AES block.
 @param state 2D array representing the state of the AES block.
 @param roundKey Round key to be XORed with the state array.
 */
void addRoundKey(unsigned char state[AES_STATE_ROWS][NUM_BLOCKS],
                 unsigned char *roundKey)
{
    queue queue;
    buffer<unsigned char, 2> stateBuffer(state[0],
                                         range<2>(AES_STATE_ROWS, NUM_BLOCKS));
    buffer<unsigned char, 1> roundKeyBuffer(
        roundKey, range<1>(AES_STATE_ROWS * NUM_BLOCKS));

    queue
        .submit([&](handler &handler) {
            auto stateAcc =
                stateBuffer.get_access<access::mode::read_write>(handler);
            auto roundKeyAcc =
                roundKeyBuffer.get_access<access::mode::read>(handler);

            handler.parallel_for<class AddRoundKey>(
                range<2>(AES_STATE_ROWS, NUM_BLOCKS), [=](id<2> id) {
                    size_t i = id[0];
                    size_t j = id[1];
                    stateAcc[i][j] ^= roundKeyAcc[i + AES_STATE_ROWS * j];
                });
        })
        .wait();
}

/**
 @brief Applies the SubWord transformation using SYCL.
 Substitutes bytes in a word using the S-box.
 @param a Array representing the word to be transformed.
 */
void subWord(unsigned char a[AES_STATE_ROWS])
{
    queue queue;
    buffer<unsigned char, 1> aBuffer(a, range<1>(AES_STATE_ROWS));
    buffer<unsigned char, 2> sBoxBuffer(
        sBox[0], range<2>(BLOCK_BYTES_LEN, BLOCK_BYTES_LEN));

    queue
        .submit([&](handler &handler) {
            auto aAcc = aBuffer.get_access<access::mode::read_write>(handler);
            auto sBoxAcc = sBoxBuffer.get_access<access::mode::read>(handler);

            handler.parallel_for<class SubWord>(
                range<1>(AES_STATE_ROWS), [=](id<1> id) {
                    size_t i = id[0];
                    aAcc[i] = sBoxAcc[aAcc[i] / BLOCK_BYTES_LEN]
                                     [aAcc[i] % BLOCK_BYTES_LEN];
                });
        })
        .wait();
}

/**
 @brief Rotates a word (4 bytes) using SYCL.
 Performs a circular rotation of a word.
 @param word Pointer to the word to be rotated.
 */
void rotWord(unsigned char *word)
{
    queue queue;
    buffer<unsigned char, 1> wordBuffer(word, range<1>(AES_STATE_ROWS));

    queue
        .submit([&](handler &handler) {
            auto wordAcc =
                wordBuffer.get_access<access::mode::read_write>(handler);

            handler.single_task<class RotWord>([=]() {
                unsigned char temp = wordAcc[0];
                wordAcc[0] = wordAcc[1];
                wordAcc[1] = wordAcc[2];
                wordAcc[2] = wordAcc[3];
                wordAcc[3] = temp;
            });
        })
        .wait();
}

/**
 @brief Applies the Rcon transformation using SYCL.
 Generates the Rcon value for key expansion based on the round number.
 @param a Array to store the Rcon value.
 @param n Round number.
 */
void rconWord(unsigned char a[AES_STATE_ROWS], unsigned int n)
{
    queue queue;
    unsigned char strong = 1;
    for (size_t i = 0; i < n - 1; i++)
        strong = xtime(strong);

    queue
        .parallel_for(range<1>(AES_STATE_ROWS),
                      [=](id<1> idx) {
                          size_t i = idx[0];
                          if (i == 0) {
                              a[i] = strong;
                          }
                          else {
                              a[i] = 0;
                          }
                      })
        .wait();
}

/**
 @brief Expands the AES key for encryption/decryption using SYCL.
 Generates the round keys from the original key.
 @param key Original AES key.
 @param w Output array to store the expanded key.
 */
void keyExpansion(const unsigned char *key, unsigned char w[],
                  AESKeyLength keyLength)
{
    queue queue;
    unsigned int numWordLocal = aesKeyLengthData[keyLength].numWord;

    unsigned int NUM_BLOCKSLocal = NUM_BLOCKS;
    unsigned int numRoundLocal = aesKeyLengthData[keyLength].numRound;
    // Copy the initial key to the output array
    queue
        .submit([&](handler &handler) {
            handler.parallel_for(range<1>(AES_STATE_ROWS * numWordLocal),
                                 [=](id<1> idx) { w[idx] = key[idx]; });
        })
        .wait();

    unsigned int i = AES_STATE_ROWS * numWordLocal;

    while (i < AES_STATE_ROWS * NUM_BLOCKSLocal * (numRoundLocal + 1)) {
        unsigned char temp[AES_STATE_ROWS];
        buffer<unsigned char, 1> temp_buf(temp, range<1>(AES_STATE_ROWS));

        queue
            .submit([&](handler &handler) {
                auto temp_acc =
                    temp_buf.get_access<access::mode::write>(handler);
                handler.parallel_for(range<1>(AES_STATE_ROWS), [=](id<1> idx) {
                    temp_acc[idx] = w[i - AES_STATE_ROWS + idx];
                });
            })
            .wait();

        if (i / AES_STATE_ROWS % numWordLocal == 0) {
            // Use SYCL to execute rotWord and subWord
            rotWord(temp);
            subWord(temp);
            unsigned char rcon[AES_STATE_ROWS];
            rconWord(rcon, i / (numWordLocal * AES_STATE_ROWS));

            for (int k = 0; k < AES_STATE_ROWS; k++)
                temp[k] ^= rcon[k];
        }
        else if (numWordLocal > 6 && i / AES_STATE_ROWS % numWordLocal == 4)
            subWord(temp);

        queue
            .submit([&](handler &handler) {
                auto temp_acc =
                    temp_buf.get_access<access::mode::read>(handler);
                handler.parallel_for(range<1>(AES_STATE_ROWS), [=](id<1> idx) {
                    w[i + idx] = w[i + idx - AES_STATE_ROWS * numWordLocal] ^
                                 temp_acc[idx];
                });
            })
            .wait();

        i += 4;
    }
}

/**
 Applies the InvSubBytes transformation using the inverse S-box.
 This function replaces each byte in the state matrix with its
 corresponding byte from the inverse S-box.
 @param state 4xN matrix of state bytes to be transformed.
 */
void invSubBytes(unsigned char state[AES_STATE_ROWS][NUM_BLOCKS])
{
    queue queue;
    buffer<unsigned char, 2> stateBuffer(state[0],
                                         range<2>(AES_STATE_ROWS, NUM_BLOCKS));
    buffer<unsigned char, 2> invSBoxBuffer(
        invSBox[0], range<2>(BLOCK_BYTES_LEN, BLOCK_BYTES_LEN));

    queue
        .submit([&](handler &handler) {
            auto stateAcc =
                stateBuffer.get_access<access::mode::read_write>(handler);
            auto invSBoxAcc =
                invSBoxBuffer.get_access<access::mode::read>(handler);

            handler.parallel_for<class invSubBytes>(
                range<2>(AES_STATE_ROWS, NUM_BLOCKS), [=](id<2> id) {
                    size_t i = id[0];
                    size_t j = id[1];
                    stateAcc[i][j] = invSBoxAcc[state[i][j] / BLOCK_BYTES_LEN]
                                               [state[i][j] % BLOCK_BYTES_LEN];
                });
        })
        .wait();
}

/*Applies the InvMixColumns transformation*/
void invMixColumns(unsigned char state[AES_STATE_ROWS][NUM_BLOCKS])
{
    queue queue;
    queue
        .parallel_for(
            range<1>(NUM_BLOCKS),
            [=](id<1> idx) {
                size_t i = idx[0];
                unsigned char a[AES_STATE_ROWS];
                unsigned char b[AES_STATE_ROWS];

                for (size_t j = 0; j < AES_STATE_ROWS; j++) {
                    a[j] = state[j][i];
                    b[j] = xtime(a[j]);
                }

                state[0][i] = multiply(0x0e, a[0]) ^ multiply(0x0b, a[1]) ^
                              multiply(0x0d, a[2]) ^ multiply(0x09, a[3]);
                state[1][i] = multiply(0x09, a[0]) ^ multiply(0x0e, a[1]) ^
                              multiply(0x0b, a[2]) ^ multiply(0x0d, a[3]);
                state[2][i] = multiply(0x0d, a[0]) ^ multiply(0x09, a[1]) ^
                              multiply(0x0e, a[2]) ^ multiply(0x0b, a[3]);
                state[3][i] = multiply(0x0b, a[0]) ^ multiply(0x0d, a[1]) ^
                              multiply(0x09, a[2]) ^ multiply(0x0e, a[3]);
            })
        .wait();
}

/**
 Applies the InvShiftRows transformation.
 This function performs a cyclic shift of the rows in the state matrix
 in the reverse direction for decryption.
 @param state 4xN matrix of state bytes to be transformed.
 */
void invShiftRows(unsigned char state[AES_STATE_ROWS][NUM_BLOCKS])
{
    queue queue;
    queue
        .submit([&](handler &handler) {
            handler.parallel_for(range<1>(AES_STATE_ROWS), [=](id<1> i) {
                unsigned char tmp[NUM_BLOCKS];
                for (size_t k = 0; k < NUM_BLOCKS; k++)
                    tmp[k] = state[i][(k - i + NUM_BLOCKS) % NUM_BLOCKS];
                for (size_t k = 0; k < NUM_BLOCKS; k++)
                    state[i][k] = tmp[k];
            });
        })
        .wait();
}

/** XORs two blocks of bytes a and b of length len, storing the result in c. */
void xorBlocks(const unsigned char *a, const unsigned char *b, unsigned char *c,
               unsigned int len)
{
    queue queue;

    buffer<unsigned char, 1> bufA(a, range<1>(len));
    buffer<unsigned char, 1> bufB(b, range<1>(len));
    buffer<unsigned char, 1> bufC(c, range<1>(len));

    queue
        .submit([&](handler &handler) {
            auto accA = bufA.get_access<access::mode::read>(handler);
            auto accB = bufB.get_access<access::mode::read>(handler);
            auto accC = bufC.get_access<access::mode::write>(handler);

            handler.parallel_for(range<1>(len), [=](id<1> idx) {
                accC[idx] = accA[idx] ^ accB[idx];
            });
        })
        .wait();
}

#else

/*
 Encrypts a single block of data.
 `in` - input block to be encrypted
 `out` - output block to store the encrypted data
 `roundKeys` - expanded key for encryption
*/
void encryptBlock(const unsigned char in[], unsigned char out[],
                  unsigned char *roundKeys, AESKeyLength keyLength)
{
    unsigned char state[AES_STATE_ROWS][NUM_BLOCKS];
    unsigned int i, j, round;

    // Initialize state array with input block
    for (i = 0; i < AES_STATE_ROWS; i++)
        for (j = 0; j < NUM_BLOCKS; j++)
            state[i][j] = in[i + AES_STATE_ROWS * j];

    // Initial round key addition
    addRoundKey(state, roundKeys);

    // Main rounds
    for (round = 1; round < aesKeyLengthData[keyLength].numRound; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys + round * AES_STATE_ROWS * NUM_BLOCKS);
    }

    // Final round
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys + aesKeyLengthData[keyLength].numRound *
                                       AES_STATE_ROWS * NUM_BLOCKS);

    // Copy state array to output block
    for (i = 0; i < AES_STATE_ROWS; i++)
        for (j = 0; j < NUM_BLOCKS; j++)
            out[i + AES_STATE_ROWS * j] = state[i][j];
}

/*
 Decrypts a single block of data.
 `in` - input block to be decrypted
 `out` - output block to store the decrypted data
 `roundKeys` - expanded key for decryption
*/
void decryptBlock(const unsigned char in[], unsigned char out[],
                  unsigned char *roundKeys, AESKeyLength keyLength)
{
    unsigned char state[AES_STATE_ROWS][NUM_BLOCKS];
    unsigned int i, j, round;

    // Initialize state array with input block
    for (i = 0; i < AES_STATE_ROWS; i++)
        for (j = 0; j < NUM_BLOCKS; j++)
            state[i][j] = in[i + AES_STATE_ROWS * j];

    // Initial round key addition
    addRoundKey(state, roundKeys + aesKeyLengthData[keyLength].numRound *
                                       AES_STATE_ROWS * NUM_BLOCKS);

    // Main rounds
    for (round = aesKeyLengthData[keyLength].numRound - 1; round >= 1;
         round--) {
        invSubBytes(state);
        invShiftRows(state);
        addRoundKey(state, roundKeys + round * AES_STATE_ROWS * NUM_BLOCKS);
        invMixColumns(state);
    }

    // Final round
    invSubBytes(state);
    invShiftRows(state);
    addRoundKey(state, roundKeys);

    // Copy state array to output block
    for (i = 0; i < AES_STATE_ROWS; i++)
        for (j = 0; j < NUM_BLOCKS; j++)
            out[i + AES_STATE_ROWS * j] = state[i][j];
}

/*Multiplies a byte by x in GF(2^8)*/
unsigned char xtime(unsigned char b)
{
    return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}

/*Multiplies two bytes in GF(2^8)*/
unsigned char multiply(unsigned char x, unsigned char y)
{
    unsigned char result = 0;
    unsigned char temp = y;
    for (int i = 0; i < 8; i++) {
        if (x & 1)
            result ^= temp;
        bool carry = temp & 0x80;
        temp <<= 1;
        if (carry)
            temp ^= 0x1b;
        x >>= 1;
    }

    return result;
}

/*Apply SubBytes transformation using the S-box*/
void subBytes(unsigned char state[AES_STATE_ROWS][NUM_BLOCKS])
{
    for (size_t i = 0; i < AES_STATE_ROWS; i++)
        for (size_t j = 0; j < NUM_BLOCKS; j++)
            state[i][j] = sBox[state[i][j] / BLOCK_BYTES_LEN]
                              [state[i][j] % BLOCK_BYTES_LEN];
}

/*ShiftRows transformation*/
void shiftRows(unsigned char state[AES_STATE_ROWS][NUM_BLOCKS])
{
    for (size_t i = 0; i < AES_STATE_ROWS; i++) {
        unsigned char tmp[NUM_BLOCKS];
        for (size_t k = 0; k < NUM_BLOCKS; k++)
            tmp[k] = state[i][(k + i) % NUM_BLOCKS];
        memcpy(state[i], tmp, NUM_BLOCKS * sizeof(unsigned char));
    }
}

/*MixColumns transformation*/
void mixColumns(unsigned char state[AES_STATE_ROWS][NUM_BLOCKS])
{
    for (size_t i = 0; i < AES_STATE_ROWS; i++) {
        unsigned char a[AES_STATE_ROWS];
        unsigned char b[AES_STATE_ROWS];
        for (size_t j = 0; j < AES_STATE_ROWS; j++) {
            a[j] = state[j][i];
            b[j] = xtime(state[j][i]);
        }
        state[0][i] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
        state[1][i] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
        state[2][i] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
        state[3][i] = b[0] ^ a[0] ^ a[1] ^ a[2] ^ b[3];
    }
}

/*AddRoundKey transformation*/
void addRoundKey(unsigned char state[AES_STATE_ROWS][NUM_BLOCKS],
                 unsigned char *key)
{
    unsigned int i, j;
    for (i = 0; i < AES_STATE_ROWS; i++)
        for (j = 0; j < NUM_BLOCKS; j++)
            state[i][j] = state[i][j] ^ key[i + AES_STATE_ROWS * j];
}

/*Applies the SubWord transformation using the S-box*/
void subWord(unsigned char a[AES_STATE_ROWS])
{
    for (size_t i = 0; i < AES_STATE_ROWS; i++)
        a[i] = sBox[a[i] / BLOCK_BYTES_LEN][a[i] % BLOCK_BYTES_LEN];
}

/*Rotates a word (4 bytes)*/
void rotWord(unsigned char a[AES_STATE_ROWS])
{
    unsigned char first = a[0];
    for (size_t i = 0; i < 3; i++)
        a[i] = a[i + 1];
    a[3] = first;
}

/*Applies the Rcon transformation*/
void rconWord(unsigned char a[AES_STATE_ROWS], unsigned int n)
{
    unsigned char strong = 1;
    for (size_t i = 0; i < n - 1; i++)
        strong = xtime(strong);

    a[0] = strong;
    a[1] = a[2] = a[3] = 0;
}

/*Expands the key for AES encryption/decryption*/
void keyExpansion(const unsigned char *key, unsigned char w[],
                  AESKeyLength keyLength)
{
    unsigned char temp[AES_STATE_ROWS], rcon[AES_STATE_ROWS];
    unsigned int i = 0;

    //copy key to w array
    while (i < AES_STATE_ROWS * aesKeyLengthData[keyLength].numWord) {
        w[i] = key[i];
        i++;
    }

    i = AES_STATE_ROWS * aesKeyLengthData[keyLength].numWord;

    //main expansion loop
    while (i < AES_STATE_ROWS * NUM_BLOCKS *
                   (aesKeyLengthData[keyLength].numRound + 1)) {
        for (size_t k = AES_STATE_ROWS, j = 0; k > 0; --k, ++j)
            temp[j] = w[i - k];

        if (i / AES_STATE_ROWS % aesKeyLengthData[keyLength].numWord == 0) {
            rotWord(temp);
            subWord(temp);
            rconWord(rcon, i / (aesKeyLengthData[keyLength].numWord *
                                AES_STATE_ROWS));
            for (int i = 0; i < AES_STATE_ROWS; i++)
                temp[i] = temp[i] ^ rcon[i];
        }
        else if (aesKeyLengthData[keyLength].numWord > 6 &&
                 i / AES_STATE_ROWS % aesKeyLengthData[keyLength].numWord == 4)
            subWord(temp);

        for (int k = 0; k < AES_STATE_ROWS; k++)
            w[i + k] = w[i + k -
                         AES_STATE_ROWS * aesKeyLengthData[keyLength].numWord] ^
                       temp[k];

        i += 4;
    }
}

/*Applies the InvSubBytes transformation using the inverse S-box*/
void invSubBytes(unsigned char state[AES_STATE_ROWS][NUM_BLOCKS])
{
    unsigned int i, j;
    unsigned char t;
    for (i = 0; i < AES_STATE_ROWS; i++)
        for (j = 0; j < NUM_BLOCKS; j++) {
            t = state[i][j];
            state[i][j] = invSBox[t / BLOCK_BYTES_LEN][t % BLOCK_BYTES_LEN];
        }
}

/*Applies the InvMixColumns transformation*/
void invMixColumns(unsigned char state[AES_STATE_ROWS][NUM_BLOCKS])
{
    for (size_t i = 0; i < NUM_BLOCKS; i++) {
        unsigned char a[AES_STATE_ROWS];
        unsigned char b[AES_STATE_ROWS];
        for (size_t j = 0; j < AES_STATE_ROWS; j++) {
            a[j] = state[j][i];
            b[j] = xtime(a[j]);
        }
        state[0][i] = multiply(0x0e, a[0]) ^ multiply(0x0b, a[1]) ^
                      multiply(0x0d, a[2]) ^ multiply(0x09, a[3]);
        state[1][i] = multiply(0x09, a[0]) ^ multiply(0x0e, a[1]) ^
                      multiply(0x0b, a[2]) ^ multiply(0x0d, a[3]);
        state[2][i] = multiply(0x0d, a[0]) ^ multiply(0x09, a[1]) ^
                      multiply(0x0e, a[2]) ^ multiply(0x0b, a[3]);
        state[3][i] = multiply(0x0b, a[0]) ^ multiply(0x0d, a[1]) ^
                      multiply(0x09, a[2]) ^ multiply(0x0e, a[3]);
    }
}

/*Applies the InvShiftRows transformation*/
void invShiftRows(unsigned char state[AES_STATE_ROWS][NUM_BLOCKS])
{
    for (size_t i = 0; i < AES_STATE_ROWS; i++) {
        unsigned char tmp[NUM_BLOCKS];
        for (size_t k = 0; k < NUM_BLOCKS; k++)
            tmp[k] = state[i][(k - i + NUM_BLOCKS) % NUM_BLOCKS];
        memcpy(state[i], tmp, NUM_BLOCKS * sizeof(unsigned char));
    }
}

/** XORs two blocks of bytes a and b of length len, storing the result in c. */
void xorBlocks(const unsigned char *a, const unsigned char *b, unsigned char *c,
               unsigned int len)
{
    for (unsigned int i = 0; i < len; i++) {
        c[i] = a[i] ^ b[i];
    }
}

size_t calculatEncryptedLenAES(size_t inLen, bool isFirst,
                               AESChainingMode chainingMode)
{
    if (inLen % BLOCK_BYTES_LEN == 0)  //padding
        inLen += BLOCK_BYTES_LEN;
    if (isFirst && chainingMode != ECB)  //iv
        inLen += BLOCK_BYTES_LEN;
    return (inLen + 15) & ~15;
}

size_t calculatDecryptedLenAES(size_t inLen, bool isFirst,
                               AESChainingMode chainingMode)
{
    if (isFirst && chainingMode != ECB)  //iv
        inLen -= BLOCK_BYTES_LEN;
    return inLen;
}

#endif
