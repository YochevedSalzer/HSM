#include <cstring>
#include <stdexcept>
#include <string>
#include <random>
#include "../include/rsa.h"
#include "../logger/logger.h"
#include "../include/prime_tests.h"
#include "../include/big_int64.h"

using namespace std;

constexpr int PADDING_MIN_LEN = 11;
constexpr int PRIME_TEST_ROUNDS = 40;
constexpr int DEFAULT_E = 65537;
constexpr int FALLBACK_E = 17;

bool allowedKeySizes(size_t keySize)
{
    return keySize == 1024 || keySize == 2048 || keySize == 4096;
}

void rsaGeneratePrime(size_t bits, BigInt64 &prime)
{
    BigInt64 random = BigInt64(BigInt64::CreateModes::RANDOM, bits);
    prime = nextPrimeDivideToChunks(random, PRIME_TEST_ROUNDS);
}

void rsaKeysGeneration(const BigInt64 &p, const BigInt64 &q, size_t keySize,
                       BigInt64 &e, BigInt64 &d)
{
    BigInt64 phi;
    BigInt64 gcdVal;
    // phi(n) = (p-1) * (q-1)
    BigInt64 pMinus1 = p - 1;
    BigInt64 qMinus1 = q - 1;
    phi = pMinus1 * qMinus1;
    // Choose e such that 1 < e < phi and gcd(e, phi) = 1 (coprime)
    // A common choice for e is 65537
    e = DEFAULT_E;
    gcdVal = gcd(e, phi);
    while (gcdVal != 1) {
        e += 2;
        if (e > phi)
            e = FALLBACK_E;
    }

    // d is the modular inverse of e modulo ϕ(n) or e^-1 mod phi
    //  0<d<phi and  (d * e) % phi = 1 ,<- (d*e -1) is divisible by phi
    d = modularInverse(e, phi);
}

size_t rsaGetModulusLen(size_t keySize)
{
    return keySize / BITS_IN_BYTE;
}

/**
 * @brief Generates an RSA key pair for cryptographic use.
 * @param keySize The size of the RSA key in bits (must be 1024, 2048, or 4096).
 * @param pubExponent Pointer to an array where the public exponent will be stored.
 * @param pubLen The length of the public exponent buffer.
 * @param privExponent Pointer to an array where the private exponent will be stored.
 * @param privLen The length of the private exponent buffer.
 * @param modulus Pointer to an array where the modulus (n = p * q) will be stored.
 * @param modulusLen The length of the modulus buffer.
 * @return CKR_OK on success, CKR_KEY_SIZE_RANGE if the key size is invalid, or CKR_BUFFER_TOO_SMALL if buffer sizes are insufficient.
 */
CK_RV rsaGenerateKeys(size_t keySize, uint8_t *pubKey, size_t pubLen,
                      uint8_t *privKey, size_t privLen)
{
    log(logger::LogLevel::INFO,
        "RSA generate keys: generation RSA key pair of " + to_string(keySize) +
            " bits : started...");
    if (!allowedKeySizes(keySize)) {
        log(logger::LogLevel::ERROR, "RSA generate keys: invalid key size");
        return CKR_KEY_SIZE_RANGE;
    }

    if (!(pubLen == rsaGetPublicKeyLen(keySize)) ||
        !(privLen == rsaGetPrivateKeyLen(keySize))) {
        log(logger::LogLevel::ERROR,
            "RSA generate keys: buffer sizes are insufficient");
        return CKR_BUFFER_TOO_SMALL;
    }

    // Generate prime numbers for public and
    // private keys
    BigInt64 p, q, n, e, d;
    try {
        // Generate large prime numbers
        rsaGeneratePrime(keySize / 2, p);
        rsaGeneratePrime(keySize / 2, q);
        n = p * q;
        rsaKeysGeneration(p, q, keySize, e, d);
    }
    catch (const std::exception &e) {
        log(logger::LogLevel::ERROR,
            "RSA generate keys: failed " + string(e.what()));
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }

    memset(pubKey, 0, pubLen);
    memset(privKey, 0, privLen);
    n.exportTo(pubKey, rsaGetModulusLen(keySize),
               BigInt64::CreateModes::BIG_ENDIANESS);
    n.exportTo(privKey, rsaGetModulusLen(keySize),
               BigInt64::CreateModes::BIG_ENDIANESS);
    e.exportTo(pubKey + rsaGetModulusLen(keySize),
               pubLen - rsaGetModulusLen(keySize),
               BigInt64::CreateModes::BIG_ENDIANESS);
    d.exportTo(privKey + rsaGetModulusLen(keySize),
               privLen - rsaGetModulusLen(keySize),
               BigInt64::CreateModes::BIG_ENDIANESS);
    return CKR_OK;
}

void rsaPkcs1v15Pad(const uint8_t *plaintext, size_t plaintextLen,
                    uint8_t *padded, size_t keySize)
{
    size_t paddingLen = keySize - plaintextLen - 3;  // Padding length
    if (paddingLen < 8)                              // Minimum padding length
        throw std::runtime_error("Plaintext is too long for padding");

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, 255);
    // Start with 0x00 0x02
    padded[0] = 0x00;
    padded[1] = 0x02;

    // Add non-zero random padding
    for (size_t i = 2; i < paddingLen + 2; i++) {
        padded[i] = static_cast<uint8_t>(dis(gen));
    }

    // Add 0x00 separator
    padded[paddingLen + 2] = 0x00;
    std::memcpy(padded + paddingLen + 3, plaintext, plaintextLen);
}

void rsaPkcs1v15Unpad(const uint8_t *padded, size_t paddedLen,
                      uint8_t *plaintext, size_t *plaintextLen)
{
    if (paddedLen < PADDING_MIN_LEN || padded[0] != 0x00 || padded[1] != 0x02)
        throw std::runtime_error("Invalid padding");

    // Find 0x00 separator
    size_t i = 2;
    while (i < paddedLen && padded[i] != 0x00)
        ++i;
    if (i == paddedLen)
        throw std::runtime_error("Invalid padding: No separator found");

    *plaintextLen = paddedLen - i - 1;
    std::memcpy(plaintext, padded + i + 1, *plaintextLen);
}

/**
 * @brief Encrypts data using RSA public or private key.
 * @param plaintext Pointer to the plaintext data.
 * @param plaintextLen The length of the plaintext in bytes.
 * @param modulus Pointer to the modulus (n).
 * @param modulusLen The length of the modulus in bytes.
 * @param exponent Pointer to the exponent (either public or private).
 * @param exponentLen The length of the exponent in bytes.
 * @param ciphertext Pointer to the buffer where the encrypted data (ciphertext) will be stored.
 * @param ciphertextLen The length of the ciphertext buffer.
 * @param keySize The size of the RSA key in bits.
 * @return CKR_OK on success, CKR_KEY_SIZE_RANGE if the key size is invalid, or CKR_BUFFER_TOO_SMALL if buffers are insufficient.
 */
CK_RV rsaEncrypt(const uint8_t *plaintext, size_t plaintextLen,
                 const uint8_t *key, size_t keyLen, uint8_t *ciphertext,
                 size_t ciphertextLen, size_t keySize)
{
    if (!allowedKeySizes(keySize)) {
        log(logger::LogLevel::ERROR, "RSA encryption: invalid key size");
        return CKR_KEY_SIZE_RANGE;
    }

    if ((!(keyLen == rsaGetPublicKeyLen(keySize)) &&
         !(keyLen == rsaGetPrivateKeyLen(keySize)))) {
        log(logger::LogLevel::ERROR,
            "RSA encryption: buffer sizes are insufficient");
        return CKR_BUFFER_TOO_SMALL;
    }

    size_t keySizeBytes = keySize / BITS_IN_BYTE;
    if (plaintextLen > rsaGetPlainMaxLen(keySize)) {
        log(logger::LogLevel::ERROR, "RSA encryption: plaintext is too long");
        return CKR_DATA_TOO_LARGE;
    }

    if (ciphertextLen != keySizeBytes) {
        log(logger::LogLevel::ERROR,
            "RSA encryption: ciphertext buffer is too small");
        return CKR_BUFFER_TOO_SMALL;
    }

    size_t paddedLen = keySizeBytes;
    // Padding plaintext to keySizeBytes
    uint8_t *padded = new uint8_t[keySizeBytes];
    rsaPkcs1v15Pad(plaintext, plaintextLen, padded, keySizeBytes);
    // Convert padded plaintext to BigInt64
    BigInt64 plainNumber(padded, paddedLen,
                         BigInt64::CreateModes::BIG_ENDIANESS);
    BigInt64 modulus(key, rsaGetModulusLen(keySize),
                     BigInt64::CreateModes::BIG_ENDIANESS);
    BigInt64 exponent(key + rsaGetModulusLen(keySize),
                      keyLen - rsaGetModulusLen(keySize),
                      BigInt64::CreateModes::BIG_ENDIANESS);
    // Encrypt message: plain = plain^key % n
    BigInt64 cipherNumber;
    try {
        cipherNumber = modularExponentiation(plainNumber, exponent, modulus);
    }
    catch (std::exception &e) {
        log(logger::LogLevel::ERROR,
            "RSA encryption: error performing modular exponentiation " +
                string(e.what()));
        return CKR_DECRYPTED_DATA_INVALID;
    }

    memset(ciphertext, 0, keySizeBytes);
    cipherNumber.exportTo(ciphertext, ciphertextLen,
                          BigInt64::CreateModes::BIG_ENDIANESS);
    delete[] padded;
    return CKR_OK;
}

/**
 * @brief Decrypts data using RSA public or private key.
 * @param ciphertext Pointer to the encrypted data (ciphertext).
 * @param ciphertextLen The length of the ciphertext in bytes.
 * @param modulus Pointer to the modulus (n).
 * @param modulusLen The length of the modulus in bytes.
 * @param exponent Pointer to the exponent (either public or private).
 * @param exponentLen The length of the exponent in bytes.
 * @param plaintext Pointer to the buffer where the decrypted data (plaintext) will be stored.
 * @param plaintextLen Pointer to a variable that will store the length of the decrypted data.
 * @param keySize The size of the RSA key in bits.
 * @return CKR_OK on success, CKR_KEY_SIZE_RANGE if the key size is invalid, or CKR_BUFFER_TOO_SMALL if buffers are insufficient.
 */
CK_RV rsaDecrypt(const uint8_t *ciphertext, size_t ciphertextLen,
                 const uint8_t *key, size_t keyLen, uint8_t *plaintext,
                 size_t *plaintextLen, size_t keySize)
{
    if (!allowedKeySizes(keySize)) {
        log(logger::LogLevel::ERROR, "RSA decryption: invalid key size");
        return CKR_KEY_SIZE_RANGE;
    }

    if ((!(keyLen == rsaGetPublicKeyLen(keySize)) &&
         !(keyLen == rsaGetPrivateKeyLen(keySize)))) {
        log(logger::LogLevel::ERROR,
            "RSA encryption: buffer sizes are insufficient");
        return CKR_BUFFER_TOO_SMALL;
    }

    size_t keySizeBytes = keySize / BITS_IN_BYTE;
    if (ciphertextLen != keySizeBytes) {
        log(logger::LogLevel::ERROR,
            "RSA decryption: ciphertext buffer is too small");
        return CKR_BUFFER_TOO_SMALL;
    }

    // Convert ciphertext to BigInt64
    BigInt64 cipherNumber(ciphertext, ciphertextLen,
                          BigInt64::CreateModes::BIG_ENDIANESS);
    BigInt64 modulus(key, rsaGetModulusLen(keySize),
                     BigInt64::CreateModes::BIG_ENDIANESS);
    BigInt64 exponent(key + rsaGetModulusLen(keySize),
                      keyLen - rsaGetModulusLen(keySize),
                      BigInt64::CreateModes::BIG_ENDIANESS);
    // Decrypt message: plain = cipher^key % n
    BigInt64 plainNumber;
    try {
        plainNumber = modularExponentiation(cipherNumber, exponent, modulus);
    }
    catch (std::exception &e) {
        log(logger::LogLevel::ERROR,
            "RSA decryption: error performing modular exponentiation " +
                string(e.what()));
        return CKR_ENCRYPTED_DATA_INVALID;
    }

    uint8_t *padded = new uint8_t[keySizeBytes];
    size_t paddedLen = keySizeBytes;
    plainNumber.exportTo(padded, paddedLen,
                         BigInt64::CreateModes::BIG_ENDIANESS);
    // Remove padding
    try {
        rsaPkcs1v15Unpad(padded, paddedLen, plaintext, plaintextLen);
    }
    catch (std::exception &e) {
        log(logger::LogLevel::ERROR,
            "RSA decryption: error unpadding plaintext " + string(e.what()));
        delete[] padded;
        return CKR_DECRYPTED_DATA_INVALID;
    }

    delete[] padded;
    return CKR_OK;
}

size_t rsaGetEncryptedLen(size_t keySize)
{
    return keySize / BITS_IN_BYTE;
}

/**
 * @brief Gets the maximum length of plaintext that can be encrypted with a given RSA key size.
 * @param keySize The size of the RSA key in bits.
 * @return The maximum length of plaintext in bytes.
 */
size_t rsaGetPlainMaxLen(size_t keySize)
{
    return keySize / BITS_IN_BYTE - PADDING_MIN_LEN;
}

/**
 * @brief Gets the length of decrypted data for a given RSA key size.
 * @param keySize The size of the RSA key in bits.
 * @return The length of the decrypted data in bytes.
 */
size_t rsaGetDecryptedLen(size_t keySize)
{
    // Minimum padding length for PKCS#1 v1.5 is 11 bytes
    // Remove the padding: The maximum length of the plaintext is keySize -
    // minPaddingLength
    return keySize / BITS_IN_BYTE - PADDING_MIN_LEN;
}

/**
 * @brief Gets the total length of the public key (including the modulus and public exponent) for RSA.
 * @param keySize The size of the RSA key in bits.
 * @return The length of the public key in bytes, which includes the modulus and the public exponent.
 */
size_t rsaGetPublicKeyLen(size_t keySize)
{
    return rsaGetModulusLen(keySize) + BYTES_IN_LIMB;
}

/**
 * @brief Gets the total length of the private key (including the modulus and private exponent) for RSA.
 * @param keySize The size of the RSA key in bits.
 * @return The length of the private key in bytes, which includes the modulus and the private exponent.
 */
size_t rsaGetPrivateKeyLen(size_t keySize)
{
    return rsaGetModulusLen(keySize) + keySize / BITS_IN_BYTE;
}