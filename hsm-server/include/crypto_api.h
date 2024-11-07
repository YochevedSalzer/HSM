#ifndef __CRYPTO_API_H__
#define __CRYPTO_API_H__

#include <cstddef>
#include <future>
#include <stdexcept>
#include <string>
#include <thread>

#include "aes_stream_factory.h"
#include "ecc.h"
#include "general.h"
#include "sha256.h"

int getCountFromEncryptions(int userID);
int getCountFromDecryptions(int userID);
int getCountFromSigning(int userID);
int getCountFromVerifying(int userID);
CK_RV bootSystem(
    const std::map<int, std::vector<KeyPermission>> &usersIdspermissions);
// generate key pair to each coponnet cinfigure the
//encrypt and decrypt behaviour for later

CK_RV addProccess(int userId, std::vector<KeyPermission> &permissions);

CK_RV configure(int userId, CryptoConfig config);

// keys generation:
std::string generateAESKey(int userId, AESKeyLength aesKeyLength,
                           std::vector<KeyPermission> permissions,
                           int destUserId);

std::pair<std::string, std::string> generateRSAKeyPair(
    int userId, std::vector<KeyPermission> permissions);

std::pair<std::string, std::string> generateECCKeyPair(
    int userId, std::vector<KeyPermission> permissions);

// sign-verify

size_t getSignatureLength();

CK_RV signUpdate(int senderId, void *data, size_t dataLen,
                 SHAAlgorithm hashfunc, int counter);
CK_RV signFinalize(int senderId, void *signature, size_t signatureLen,
                   SHAAlgorithm hashfunc, std::string keyId);

CK_RV verifyUpdate(int recieverId, void *in, size_t inLen,
                   SHAAlgorithm hashFunc, size_t counter);
CK_RV verifyFinalize(int recieverId, void *signature, size_t signatureLen,
                     SHAAlgorithm hashFunc, std::string keyId);

// get public key id's

std::string getPublicECCKeyByUserId(int userId);

std::string getPublicRSAKeyByUserId(int userId);

// ecc
size_t getECCencryptedLength();

size_t getECCdecryptedLength();

CK_RV ECCencrypt(int senderId, std::string keyId, void *in, size_t inLen,
                 void *out, size_t &outLen);

CK_RV ECCdecrypt(int receiverId, std::string keyId, void *in, size_t inLen,
                 void *out, size_t &outLen);
// rsa
size_t getRSAencryptedLength();

size_t getRSAdecryptedLength();

CK_RV RSAencrypt(int userId, std::string keyId, void *in, size_t inLen,
                 void *out, size_t outLen);

CK_RV RSAdecrypt(int userId, std::string keyId, void *in, size_t inLen,
                 void *out, size_t *outLen);
// aes
size_t getAESencryptedLength(size_t dataLen, bool isFirst,
                             AESChainingMode chainingMode);

size_t getAESdecryptedLength(size_t dataLen, bool isFirst,
                             AESChainingMode chainingMode);

CK_RV AESencrypt(int senderId, int receiverId, void *in, size_t inLen,
                 void *out, size_t outLen, AESKeyLength keyLength,
                 AESChainingMode chainingMode, size_t counter,
                 std::string keyId);

CK_RV
AESdecrypt(int senderId, int receiverId, void *in, size_t inLen, void *out,
           size_t &outLen, AESKeyLength keyLength, AESChainingMode chainingMode,
           size_t counter, std::string keyId);

// encrypt-decrypt
size_t getEncryptedLen(int senderId, size_t inLen, bool isFirst);

size_t getDecryptedLen(int senderId, size_t inLen, bool isFirst);

CK_RV encrypt(int senderId, int receiverId, void *in, size_t inLen, void *out,
              size_t outLen, void *signature, size_t signatureLen,
              size_t counter);

CK_RV decrypt(int senderId, int receiverId, void *in, size_t inLen,
              void *signature, size_t signatureLen, void *out, size_t &outLen,
              size_t counter);

template <class T>
void deleteFromMap(std::map<int, T> &streamingMap, int userId,
                   const std::string &mapName)
{
    // Find the userId in the map
    auto it = streamingMap.find(userId);

    // Check if userId is found before attempting to erase
    if (it != streamingMap.end()) {
        streamingMap.erase(it);  // Erase the user by iterator
        log(logger::LogLevel::INFO,
            "Deleted user: " + std::to_string(userId) + " from map " + mapName);
    }
    else {
        log(logger::LogLevel::INFO,
            "User: " + std::to_string(userId) + " not found in map " + mapName);
    }
}
#endif  // __CRYPTO_API_H__
