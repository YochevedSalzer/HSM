#ifndef __GENERAL_H__
#define __GENERAL_H__
#include "../logger/logger.h"

typedef unsigned long CK_RV;

/* Successful operation */
constexpr CK_RV CKR_OK = 0x00000000;  // 0
/* General failure when a function could not complete its intended task */
constexpr CK_RV CKR_FUNCTION_FAILED = 0x00000006;  // 6
/* Invalid arguments provided to the function (e.g., null pointers or invalid values) */
constexpr CK_RV CKR_ARGUMENTS_BAD = 0x00000007;  // 7
/* Key size is out of the allowed range (e.g., key length is too short or too long) */
constexpr CK_RV CKR_KEY_SIZE_RANGE = 0x00000162;  // 354
/* Buffer provided by the user is too small to hold the required data (e.g., during encryption or decryption) */
constexpr CK_RV CKR_BUFFER_TOO_SMALL = 0x00000150;  // 336
/* The function attempted to generate a key, but key generation is not permitted or failed */
constexpr CK_RV CKR_KEY_FUNCTION_NOT_PERMITTED = 0x00000068;  // 104
/* Decryption was attempted, but the decrypted data is invalid (e.g., data was corrupted) */
constexpr CK_RV CKR_DECRYPTED_DATA_INVALID = 0x00000064;  // 100
/* Encrypted data has invalid padding (e.g., during decryption or when verifying padding) */
constexpr CK_RV CKR_ENCRYPTED_DATA_INVALID = 0x00000063;  // 99
/* Data provided for encryption is too large for the RSA key */
constexpr CK_RV CKR_DATA_TOO_LARGE = 0x00000080;  // 128
/* User is not authorized to access or use the requested key */
constexpr CK_RV CKR_USER_NOT_AUTHORIZED = 0x00000100;  // 256
/* Signature or hash did not match */
constexpr CK_RV CKR_SIGNATURE_INVALID = 0x000000C0;  // 192
/*user sent an empty buffer to be encrypted or decrypted*/
constexpr CK_RV CKR_EMPTY_BUFFER = 0x00000200;  // 512
/* User is not logged in or user does not exist */
constexpr CK_RV CKR_USER_NOT_LOGGED_IN = 0x00000101;  // 257

enum KeyPermission { VERIFY, SIGN, ENCRYPT, DECRYPT, EXPORTABLE };
enum AsymmetricFunction { RSA, ECC };
enum SHAAlgorithm { SHA_256, SHA_3_512 };
enum AESChainingMode {
    ECB, /*Electronic Codebook*/
    CBC, /*Cipher Block Chaining*/
    CFB, /*Cipher Feedback*/
    OFB, /*Output Feedback*/
    CTR  /*Counter*/
};
enum AESKeyLength { AES_128 = 16, AES_192 = 24, AES_256 = 32 };

struct CryptoConfig {
    SHAAlgorithm hashFunction;              // Hash function algorithm
    AESKeyLength aesKeyLength;              // AES key length
    AESChainingMode aesChainingMode;        // AES chaining mode
    AsymmetricFunction asymmetricFunction;  // Asymmetric encryption function

    CryptoConfig(SHAAlgorithm hashFunc, AESKeyLength aesLen,
                 AESChainingMode aesMode, AsymmetricFunction asymFunc)
        : hashFunction(hashFunc),
          aesKeyLength(aesLen),
          aesChainingMode(aesMode),
          asymmetricFunction(asymFunc)
    {
    }
    CryptoConfig() {}
};
void log(logger::LogLevel level, const std::string &message);

bool isValidAESKeyLength(AESKeyLength aesKeyLength);
void signalHandler(int signum);
#endif  // __GENERAL_H__
