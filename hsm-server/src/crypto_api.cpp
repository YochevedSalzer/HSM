#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <cstddef>
#include "../include/crypto_api.h"
#include "../include/hash_factory.h"
#include "../include/rsa.h"
#include "temp_hsm.h"
#include "../logger/logger.h"
#include "../include/debug_utils.h"

std::map<int, std::pair<StreamAES *, size_t>> mapToInMiddleEncryptions;
std::map<int, std::pair<StreamAES *, size_t>> mapToInMiddleDecryptions;
std::map<int, std::pair<std::unique_ptr<IHash>, size_t>> mapToInMiddleSigning;
std::map<int, std::pair<std::unique_ptr<IHash>, size_t>> mapToInMiddleVerifying;

constexpr size_t BITS_IN_BYTE = 8;
constexpr size_t ECC_CIPHER_LENGTH = 512;
constexpr size_t ECC_MAX_DECRYPTED_LENGTH = 256;

int getCountFromEncryptions(int userID)
{
    auto it = mapToInMiddleEncryptions.find(userID);
    if (it != mapToInMiddleEncryptions.end())
        return it->second.second;

    return 0;
}

int getCountFromDecryptions(int userID)
{
    auto it = mapToInMiddleDecryptions.find(userID);
    if (it != mapToInMiddleDecryptions.end())
        return it->second.second;
    return 0;
}

int getCountFromSigning(int userID)
{
    auto it = mapToInMiddleSigning.find(userID);
    if (it != mapToInMiddleSigning.end())
        return it->second.second;
    return 0;
}

int getCountFromVerifying(int userID)
{
    auto it = mapToInMiddleVerifying.find(userID);
    if (it != mapToInMiddleVerifying.end())
        return it->second.second;
    return 0;
}

std::string keyPermissionToString(KeyPermission permission)
{
    switch (permission) {
        case VERIFY:
            return "VERIFY";
        case SIGN:
            return "SIGN";
        case ENCRYPT:
            return "ENCRYPT";
        case DECRYPT:
            return "DECRYPT";
        case EXPORTABLE:
            return "EXPORTABLE";
        default:
            return "UNKNOWN";
    }
}

std::string permissionsToString(const std::vector<KeyPermission> &permissions)
{
    std::ostringstream oss;
    for (size_t i = 0; i < permissions.size(); ++i) {
        oss << keyPermissionToString(permissions[i]);
        if (i != permissions.size() - 1) {
            oss << ", ";
        }
    }
    return oss.str();
}

/**
 * @brief Boot the system by generating asymmetric keys for users.
 *
 * This function logs the start of the boot process, iterates over a map of user IDs and 
 * their associated key permissions, and generates ECC and RSA key pairs for each user.
 *
 * @param usersIdspermissions A map where each key is a user ID (int), and the value is a 
 *                            vector of KeyPermission objects representing the user's permissions.
 * 
 * @return CKR_OK on successful completion of the key generation process.
 */
CK_RV bootSystem(
    const std::map<int, std::vector<KeyPermission>> &usersIdspermissions)
{
    log(logger::LogLevel::INFO, "Boot: Booting system started...");

    for (const auto &[userId, permissions] : usersIdspermissions) {
        if (permissions.empty()) {
            log(logger::LogLevel::ERROR,
                "Boot: User ID: " + std::to_string(userId) +
                    " did not send any permissions.");
            return CKR_ARGUMENTS_BAD;
        }

        // Generate ECC and RSA key pairs
        std::pair<std::string, std::string> eccIds =
            TempHsm::getInstance().generateECCKeyPair(userId, permissions);
        std::pair<std::string, std::string> rsaIds =
            TempHsm::getInstance().generateRSAKeyPair(userId, permissions);

        // Log the generated key IDs
        log(logger::LogLevel::INFO,
            "Boot: Generated asymmetric keys for User ID: " +
                std::to_string(userId) + ". ECC Key IDs (Public, Private): (" +
                eccIds.first + ", " + eccIds.second +
                "), RSA Key IDs (Public, Private): (" + rsaIds.first + ", " +
                rsaIds.second +
                "), Permissions: " + permissionsToString(permissions));
    }

    return CKR_OK;
}

/**
 * @brief Adds a user to the HSM by generating asymmetric keys for a user.
 *
 * This function adds a user to the HSM, it generates ECC and RSA 
 * key pairs for the specified user based on their permissions.
 *
 * @param userId The ID of the user that is being added.
 * @param permissions A vector of KeyPermission objects representing the 
 *                    permissions associated with the user.
 * 
 * @return CKR_OK on successful completion of the process.
 */
CK_RV addProccess(int userId, std::vector<KeyPermission> &permissions)
{
    log(logger::LogLevel::INFO,
        "AddProccess: adding proccess...\n Generating "
        "assymetric keys for user: ");
    if (permissions.empty()) {
        log(logger::LogLevel::ERROR, "User ID: " + std::to_string(userId) +
                                         " did not send no permissions.");
        return CKR_ARGUMENTS_BAD;
    }
    log(logger::LogLevel::INFO,
        "User ID: " + std::to_string(userId) +
            ", Permissions: " + permissionsToString(permissions));
    TempHsm::getInstance().generateECCKeyPair(userId, permissions);
    TempHsm::getInstance().generateRSAKeyPair(userId, permissions);

    return CKR_OK;
}

//Configures the encryption settings for a specific user.
CK_RV configure(int userId, CryptoConfig config)
{
    log(logger::LogLevel::INFO,
        "Configure: configuring user: " + std::to_string(userId));
    TempHsm::getInstance().configure(userId, config);
    return CKR_OK;
}

//Logs and handles error conditions for operations with only input buffers.
CK_RV logAndHandleErrors(std::string action, int userId, void *in, size_t inLen,
                         bool isStarting)
{
    if (isStarting)
        log(logger::LogLevel::INFO,
            "Starting " + action + " for user ID: " + std::to_string(userId));

    // Check if 'in' is nullptr or has zero length
    if (in == nullptr || inLen == 0) {
        log(logger::LogLevel::ERROR,
            action + " failed for user ID: " + std::to_string(userId) +
                ". An empty buffer was provided for " + action + ".");
        return CKR_EMPTY_BUFFER;
    }

    return CKR_OK;  // Return success if no errors occurred
}

//Logs and handles error conditions for encryption/decryption operations with input and output buffers.
CK_RV logAndHandleErrors(std::string action, int userId, std::string keyId,
                         void *in, size_t inLen, void *out, size_t outLen,
                         size_t requiredLength, bool isStarting)
{
    // if (isStarting)
    //     log(logger::LogLevel::INFO,
    //         "Starting " + action + " for user ID: " + std::to_string(userId) +
    //             " with keyId: " + keyId);

    // // Check if 'in' is nullptr or has zero length
    // if (in == nullptr || inLen == 0) {
    //     log(logger::LogLevel::ERROR,
    //         action + " failed for user ID: " + std::to_string(userId) +
    //             ". An empty buffer was provided for " + action + ".");
    //     return CKR_EMPTY_BUFFER;
    // }
    CK_RV returnCode =
        logAndHandleErrors(action, userId, in, inLen, isStarting);
    if (returnCode != CKR_OK)
        return returnCode;

    // Check if 'out' is nullptr
    if (out == nullptr) {
        log(logger::LogLevel::ERROR,
            action + " failed for user ID: " + std::to_string(userId) +
                ". Output buffer is nullptr for " + action + ".");
        return CKR_EMPTY_BUFFER;
    }

    // Check if the allocated output buffer is too small
    if (outLen < requiredLength) {
        log(logger::LogLevel::ERROR,
            action + " failed for user ID: " + std::to_string(userId) +
                ". Insufficient memory allocated for the result. Required "
                "size: " +
                std::to_string(requiredLength) + " bytes.");
        return CKR_BUFFER_TOO_SMALL;
    }

    return CKR_OK;  // Return success if no errors occurred
}

CK_RV logAndHandleErrors(std::string action, int userId, std::string keyId,
                         void *in, size_t inLen, void *out, size_t outLen,
                         size_t requiredLength, bool isStarting,
                         AESKeyLength keyLen)
{
    CK_RV returnCode = logAndHandleErrors(action, userId, keyId, in, inLen, out,
                                          outLen, requiredLength, isStarting);
    if (returnCode != CKR_OK)
        return returnCode;

    if (!isValidAESKeyLength(keyLen)) {
        log(logger::LogLevel::ERROR,
            "Invalid AES key length provided: " + std::to_string(keyLen) +
                ". Supported lengths are 128, 192, or 256 bits.");
        return CKR_KEY_SIZE_RANGE;
    }

    return CKR_OK;
}

#pragma region RSA and ECC
// Deserialize buffer back to Point
Point bufferToPoint(const void *buffer, size_t bufferSize)
{
    size_t offset = 0;
    const uint8_t *byteBuffer = static_cast<const uint8_t *>(buffer);

    // Deserialize x
    mpz_class x;
    size_t countX = byteBuffer[offset];
    offset += sizeof(uint8_t);
    mpz_import(x.get_mpz_t(), countX, 1, 1, 0, 0, byteBuffer + offset);
    offset += countX;

    // Deserialize y
    mpz_class y;
    size_t countY = byteBuffer[offset];
    offset += sizeof(uint8_t);
    mpz_import(y.get_mpz_t(), countY, 1, 1, 0, 0, byteBuffer + offset);

    return Point(x, y);
}
// Serialize the EncryptedMessage to a void* buffer
void serializeToBuffer(const EncryptedMessage &message, uint8_t *out)
{
    size_t count1, count2;
    std::vector<uint8_t> buffer1, buffer2;
    size_t offset = 0;

    buffer1.resize((mpz_sizeinbase(message.c1X.get_mpz_t(), 2) + 7) /
                   8);  // size in bytes
    mpz_export(buffer1.data(), &count1, 1, 1, 0, 0, message.c1X.get_mpz_t());
    buffer1.resize(count1);  // resize buffer to actual size after export

    buffer2.resize((mpz_sizeinbase(message.c2X.get_mpz_t(), 2) + 7) /
                   8);  // size in bytes
    mpz_export(buffer2.data(), &count2, 1, 1, 0, 0, message.c2X.get_mpz_t());
    buffer2.resize(count2);  // resize buffer to actual size after export

    // Store c1X (length followed by data)
    std::memcpy(out + offset, &count1, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    std::memcpy(out + offset, buffer1.data(), count1);
    offset += count1;

    // Store c1Y
    std::memcpy(out + offset, &message.c1Y, sizeof(message.c1Y));
    offset += sizeof(message.c1Y);

    // Store c2X (length followed by data)
    std::memcpy(out + offset, &count2, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    std::memcpy(out + offset, buffer2.data(), count2);
    offset += count2;

    // Store c2Y
    std::memcpy(out + offset, &message.c2Y, sizeof(message.c2Y));
}

// Deserialize the buffer back to EncryptedMessage
EncryptedMessage deserializeFromBuffer(const void *buffer, size_t bufferSize)
{
    size_t offset = 0;
    const uint8_t *byteBuffer = static_cast<const uint8_t *>(buffer);

    // Deserialize c1X
    mpz_class c1X;
    size_t count1 = byteBuffer[offset];
    offset += sizeof(uint8_t);
    mpz_import(c1X.get_mpz_t(), count1, 1, 1, 0, 0, byteBuffer + offset);
    offset += count1;

    // Deserialize c1Y
    bool c1Y;
    std::memcpy(&c1Y, byteBuffer + offset, sizeof(c1Y));
    offset += sizeof(c1Y);

    // Deserialize c2X
    mpz_class c2X;
    size_t count2 = byteBuffer[offset];
    offset += sizeof(uint8_t);
    mpz_import(c2X.get_mpz_t(), count2, 1, 1, 0, 0, byteBuffer + offset);
    offset += count2;

    // Deserialize c2Y
    bool c2Y;
    std::memcpy(&c2Y, byteBuffer + offset, sizeof(c2Y));

    return EncryptedMessage(c1X, c1Y, c2X, c2Y);
}

//Retrieves the encrypted length based on the asymmetric encryption function.
size_t getEncryptedLengthByAssymFunc(AsymmetricFunction func)
{
    if (func == RSA)
        return getRSAencryptedLength();
    else
        return getECCencryptedLength();
}

/**
 * @brief Retrieves the length of RSA-encrypted data.
 *
 * This function calculates the length of the data encrypted using the RSA algorithm,
 * based on a predefined RSA key size.
 * 
 * @return The encrypted data length for RSA.
 */
size_t getRSAencryptedLength()
{
    return rsaGetEncryptedLen(RSA_KEY_SIZE);
}

/**
 * @brief Retrieves the length of RSA-decrypted data.
 *
 * This function calculates the length of data decrypted using the RSA algorithm,
 * based on a predefined RSA key size.
 * 
 * @return The decrypted data length for RSA.
 */
size_t getRSAdecryptedLength()
{
    return rsaGetDecryptedLen(RSA_KEY_SIZE);
}

/**
 * @brief Retrieves the length of ECC-encrypted data.
 *
 * This function calculates the length of the data encrypted using the Elliptic Curve Cryptography (ECC) algorithm.
 * It factors in the ECC cipher length and related padding.
 * 
 * @return The encrypted data length for ECC.
 */
size_t getECCencryptedLength()
{
    return 2 * (sizeof(uint8_t) + sizeof(bool)) +
           ECC_CIPHER_LENGTH / BITS_IN_BYTE;
}

/**
 * @brief Retrieves the maximum length of ECC-decrypted data.
 *
 * This function returns the maximum length of data that can be decrypted using the ECC algorithm.
 * 
 * @return The maximum decrypted data length for ECC.
 */
size_t getECCdecryptedLength()
{
    return ECC_MAX_DECRYPTED_LENGTH / BITS_IN_BYTE;
}

/**
 * @brief Retrieves the public ECC key id for a specific user.
 *
 * This function retrieves the public Elliptic Curve Cryptography (ECC) key ID associated with a user ID.
 * 
 * @param userId The ID of the user whose public ECC key is requested.
 * 
 * @return The public ECC key ID for the given user.
 */
std::string getPublicECCKeyByUserId(int userId)
{
    //todo: error no such user id
    return TempHsm::getInstance().getPublicKeyIdByUserId(
        userId, AsymmetricFunction::ECC);
}

/**
 * @brief Retrieves the public RSA key id for a specific user.
 *
 * This function retrieves the public RSA key ID associated with a user ID.
 * 
 * @param userId The ID of the user whose public RSA key is requested.
 * 
 * @return The public RSA key ID for the given user.
 */
std::string getPublicRSAKeyByUserId(int userId)
{
    //todo: error no such user id
    return TempHsm::getInstance().getPublicKeyIdByUserId(
        userId, AsymmetricFunction::RSA);
}

// Retrieves the private ECC key id for a specific user.
std::string getPrivateECCKeyByUserId(int userId)
{
    //todo: error no such user id
    return TempHsm::getInstance().getPrivateKeyIdByUserId(
        userId, AsymmetricFunction::ECC);
}

// Retrieves the private RSA key id for a specific user.
std::string getPrivateRSAKeyByUserId(int userId)
{
    //todo: error no such user id
    return TempHsm::getInstance().getPrivateKeyIdByUserId(
        userId, AsymmetricFunction ::RSA);
}

/**
 * @brief Encrypts data using Elliptic Curve Cryptography (ECC).
 *
 * This function performs ECC encryption on the input data using the specified sender ID and key ID.
 * It retrieves the corresponding ECC public key from the HSM and encrypts the input data using the public key.
 * The encrypted data is then serialized and stored in the output buffer.
 *
 * @param senderId The ID of the sender.
 * @param keyId The ID of the ECC public key to be used for encryption.
 * @param in The input data to be encrypted.
 * @param inLen The length of the input data.
 * @param out The buffer where the encrypted output will be stored.
 * @param outLen The length of the encrypted output.
 * @return CKR_OK on success or an appropriate error code on failure.
 */
CK_RV ECCencrypt(int senderId, std::string keyId, void *in, size_t inLen,
                 void *out, size_t &outLen)
{
    LOG_BUFFER_HEXA(in, inLen, "plain text to encrypt", senderId);
    CK_RV error =
        logAndHandleErrors("ECC Encryption", senderId, keyId, in, inLen, out,
                           outLen, getECCencryptedLength(), true);
    if (error != CKR_OK)
        return error;

    std::vector<uint8_t> inVec(static_cast<uint8_t *>(in),
                               static_cast<uint8_t *>(in) + inLen);
    Point eccPublicKey;

    try {
        size_t eccPublicKeySize =
            TempHsm::getInstance().getKeyLengthByKeyId(keyId);
        std::vector<uint8_t> eccPublicKeyVec(eccPublicKeySize);
        TempHsm::getInstance().getKeyByKeyId(
            senderId, keyId, KeyPermission::ENCRYPT, eccPublicKeyVec.data(),
            eccPublicKeySize);
        eccPublicKey = bufferToPoint(eccPublicKeyVec.data(), eccPublicKeySize);
    }
    catch (std::exception &e) {
        log(logger::LogLevel::ERROR,
            "Failed to retrieve ECC public key for user id: " +
                std::to_string(senderId) + ", keyId: " + keyId +
                ". Error: " + e.what());
        return CKR_USER_NOT_AUTHORIZED;
    }

    //perform ecc encryption
    EncryptedMessage cipher = encryptECC(inVec, eccPublicKey);

    //cast cipher from EncryptedMessage to out buffer
    serializeToBuffer(cipher, static_cast<uint8_t *>(out));

    log(logger::LogLevel::INFO,
        "Successfully completed ECC encryption for user id: " +
            std::to_string(senderId));
    LOG_BUFFER_HEXA(out, outLen, "encrypted", senderId);
    return CKR_OK;
}

// Decrypts data using Elliptic Curve Cryptography (ECC).
CK_RV ECCdecrypt(int receiverId, std::string keyId, void *in, size_t inLen,
                 void *out, size_t &outLen, size_t requiredOutLen)
{
    LOG_BUFFER_HEXA(in, inLen, "encrypted to decrypt", receiverId);

    CK_RV error = logAndHandleErrors("ECC Decryption", receiverId, keyId, in,
                                     inLen, out, outLen, requiredOutLen, true);
    if (error != CKR_OK)
        return error;

    mpz_class eccPrivateKey;

    try {
        size_t eccPrivateKeySize =
            TempHsm::getInstance().getKeyLengthByKeyId(keyId);
        std::vector<uint8_t> eccPrivateKeyVec(eccPrivateKeySize);
        TempHsm::getInstance().getKeyByKeyId(
            receiverId, keyId, KeyPermission::DECRYPT, eccPrivateKeyVec.data(),
            eccPrivateKeySize);
        eccPrivateKey = mpz_class();
        mpz_import(eccPrivateKey.get_mpz_t(), eccPrivateKeySize, 1,
                   sizeof(uint8_t), 0, 0, eccPrivateKeyVec.data());
    }
    catch (std::exception &e) {
        log(logger::LogLevel::ERROR,
            "Failed to retrieve ECC private key for user id: " +
                std::to_string(receiverId) + ", keyId: " + keyId +
                ". Error: " + e.what());
        return CKR_USER_NOT_AUTHORIZED;
    }

    //cast the cipher from in buffer to EncryptedMessage
    EncryptedMessage cipher = deserializeFromBuffer(in, inLen);

    //perform decryption
    std::vector<uint8_t> decryptedMessage = decryptECC(cipher, eccPrivateKey);
    outLen = decryptedMessage.size();
    std::memcpy(out, decryptedMessage.data(), outLen);

    log(logger::LogLevel::INFO,
        "Successfully completed ECC decryption for user id: " +
            std::to_string(receiverId));
    LOG_BUFFER_HEXA(out, outLen, "decrypted", receiverId);
    return CKR_OK;
}

/**
 * @brief Decrypts data using Elliptic Curve Cryptography (ECC).
 *
 * This function decrypts the input data using the ECC decryption algorithm and the provided key.
 * It retrieves the private ecc key from the HSM for the specified user and key ID, then decrypts the input data.
 *
 * @param receiverId The ID of the reciever.
 * @param keyId The ID of the key to be used for decryption.
 * @param in A pointer to the input data to be decrypted.
 * @param inLen The length of the input data.
 * @param out A pointer to the buffer where the decrypted output will be stored.
 * @param[out] outLen The length of the decrypted output.
 *
 * @return CKR_OK if the decryption is successful, or an appropriate error code if the decryption fails.
 *
 * @note This function logs the start and end of the decryption process for debugging purposes.
 * @note If the decryption fails due to an unauthorized key, it returns CKR_USER_NOT_AUTHORIZED.
 */
CK_RV ECCdecrypt(int receiverId, std::string keyId, void *in, size_t inLen,
                 void *out, size_t &outLen)
{
    return ECCdecrypt(receiverId, keyId, in, inLen, out, outLen,
                      getECCdecryptedLength());
}

/**
 * @brief Encrypts data using RSA.
 *
 * This function performs RSA encryption on the input data using the specified sender ID and key ID.
 * It retrieves the corresponding RSA key from the HSM and encrypts the input data.
 * The encrypted data is then stored in the output buffer.
 *
 * @param userId The ID of the user.
 * @param keyId The ID of the RSA encryption key to be used.
 * @param in The input data to be encrypted.
 * @param inLen The length of the input data.
 * @param out The buffer where the encrypted output will be stored.
 * @param outLen The length of the buffer for the encrypted output.
 *
 * @return CKR_OK on successful encryption, or CKR_USER_NOT_AUTHORIZED if the key retrieval fails.
 */
CK_RV RSAencrypt(int userId, std::string keyId, void *in, size_t inLen,
                 void *out, size_t outLen)
{
    CK_RV error =
        logAndHandleErrors("RSA Encryption", userId, keyId, in, inLen, out,
                           outLen, getRSAencryptedLength(), true);
    if (error != CKR_OK)
        return error;
    size_t rsaKeySize = TempHsm::getInstance().getKeyLengthByKeyId(keyId);
    std::vector<uint8_t> rsaKey(rsaKeySize);
    try {
        TempHsm::getInstance().getKeyByKeyId(
            userId, keyId, KeyPermission::ENCRYPT, rsaKey.data(), rsaKeySize);
    }
    catch (std::exception &e) {
        log(logger::LogLevel::ERROR,
            "Failed to retrieve RSA key for user id: " +
                std::to_string(userId) + ", keyId: " + keyId +
                ". Error: " + e.what());
        //either keyid not found or user not authorised to use key
        //so really should have 2 types of codes that could be
        //returned but for now...
        return CKR_USER_NOT_AUTHORIZED;
    }

    CK_RV returnCode = rsaEncrypt(
        reinterpret_cast<uint8_t *>(in), inLen, rsaKey.data(), rsaKeySize,
        reinterpret_cast<uint8_t *>(out), outLen, RSA_KEY_SIZE);

    if (returnCode == CKR_OK)
        log(logger::LogLevel::INFO,
            "Successfully completed RSA encryption for user id: " +
                std::to_string(userId));

    return returnCode;
}

//Decrypts data using RSA.
CK_RV RSAdecrypt(int userId, std::string keyId, void *in, size_t inLen,
                 void *out, size_t *outLen, size_t requiredLength)
{
    CK_RV error = logAndHandleErrors("RSA Decryption", userId, keyId, in, inLen,
                                     out, *outLen, requiredLength, true);
    if (error != CKR_OK)
        return error;
    size_t rsaKeySize = TempHsm::getInstance().getKeyLengthByKeyId(keyId);
    std::vector<uint8_t> rsaKey(rsaKeySize);

    try {
        rsaKey.resize(rsaKeySize);
        TempHsm::getInstance().getKeyByKeyId(
            userId, keyId, KeyPermission::DECRYPT, rsaKey.data(), rsaKeySize);
    }
    catch (std::exception &e) {
        log(logger::LogLevel::ERROR,
            "Failed to retrieve RSA key for user id: " +
                std::to_string(userId) + ", keyId: " + keyId +
                ". Error: " + e.what());
        //either keyid not found or user not authorised to use key
        //so really should have 2 types of codes that could be
        //returned but for now...
        return CKR_USER_NOT_AUTHORIZED;
    }

    CK_RV returnCode = rsaDecrypt(
        reinterpret_cast<uint8_t *>(in), inLen, rsaKey.data(), rsaKeySize,
        reinterpret_cast<uint8_t *>(out), outLen, RSA_KEY_SIZE);

    if (returnCode == CKR_OK)
        log(logger::LogLevel::INFO,
            "Successfully completed RSA decryption for user id: " +
                std::to_string(userId));

    return returnCode;
}

/**
 * @brief Decrypts data using RSA.
 *
 * This function decrypts the input data using the RSA decryption algorithm and the provided key.
 * It retrieves the corresponding RSA key from the HSM for the specified user and key ID, then decrypts the input data.
 * The decrypted data is then stored in the output buffer.
 *
 * @param userId The ID of the user.
 * @param keyId The ID of the RSA decryption key to be used.
 * @param in The input data to be decrypted.
 * @param inLen The length of the input data.
 * @param out The buffer where the decrypted output will be stored.
 * @param outLen The length of the buffer for the decrypted output.
 *
 * @return CKR_OK on successful decryption, or CKR_USER_NOT_AUTHORIZED if the
 * key retrieval fails, or the return code fron rsa decryption.
 */
CK_RV RSAdecrypt(int userId, std::string keyId, void *in, size_t inLen,
                 void *out, size_t *outLen)
{
    return RSAdecrypt(userId, keyId, in, inLen, out, outLen,
                      getRSAdecryptedLength());
}

// Generates a pair of asymmetric ECC keys and returns their keyIds
std::pair<std::string, std::string> generateECCKeyPair(
    int userId, std::vector<KeyPermission> permissions)
{
    //todo logging and validations
    return TempHsm::getInstance().generateECCKeyPair(userId, permissions);
}

// Generates a pair of asymmetric RSA keys and returns their keyIds
std::pair<std::string, std::string> generateRSAKeyPair(
    int userId, std::vector<KeyPermission> permissions)
{
    //todo logging and validations
    return TempHsm::getInstance().generateRSAKeyPair(userId, permissions);
}

#pragma endregion RSA and ECC

#pragma region AES

// Checks if the user is encrypting the first chunk.
bool isFirstChunkForEncryption(int userId)
{
    return mapToInMiddleEncryptions.count(userId) == 0;
}

// Checks if the user is decrypting the first chunk.
bool isFirstChunkForDecryption(int userId)
{
    return mapToInMiddleDecryptions.count(userId) == 0;
}

// Retrieves an AES key from the HSM by key ID.
CK_RV retrieveAESKeyByKeyId(int userId, std::string aesKeyId,
                            unsigned char *symmetricKey, int symmetricKeyLength,
                            KeyPermission usage)
{
    try {
        TempHsm::getInstance().getKeyByKeyId(userId, aesKeyId, usage,
                                             symmetricKey, symmetricKeyLength);
    }
    catch (std::exception &e) {
        log(logger::LogLevel::ERROR,
            "Failed to retrieve AES key for user id: " +
                std::to_string(userId) + ", keyId: " + aesKeyId +
                ". Error: " + e.what());
        return CKR_USER_NOT_AUTHORIZED;
    }
    return CKR_OK;
}

//function to encrypt symmetric key with RSA or ECC
CK_RV encryptAESkey(int senderId, int recieverId, uint8_t *symmetricKey,
                    size_t symmetricKeyLen, void *encryptedKey,
                    size_t encryptedKeyLen, AsymmetricFunction func)
{
    std::string recieversPublicKeyId =
        TempHsm::getInstance().getPublicKeyIdByUserId(recieverId, func);
    CK_RV returnCode;

    // encrypt symmetric key with ECC or RSA with recievers public key
    if (func == RSA)
        returnCode = RSAencrypt(senderId, recieversPublicKeyId, symmetricKey,
                                symmetricKeyLen, encryptedKey, encryptedKeyLen);
    else {
        returnCode = ECCencrypt(senderId, recieversPublicKeyId, symmetricKey,
                                symmetricKeyLen, encryptedKey, encryptedKeyLen);
    }
    // printBufferHex(encryptedKey, encryptedKeyLen, "encrypted key");

    return returnCode;
}

//function to decrypt symmetric key with RSA or ECC
CK_RV decryptAESkey(int senderId, int recieverId, void *in, size_t inLen,
                    uint8_t *symmetricKey, size_t &symmetricKeyLen,
                    AsymmetricFunction func, AESKeyLength keyLen)
{
    std::string recieverrsPrivateKeyId =
        TempHsm::getInstance().getPrivateKeyIdByUserId(recieverId, func);
    CK_RV returnCode;

    // decrypt symmetric key with ECC or RSA with recievers private key
    if (func == RSA)
        returnCode = RSAdecrypt(recieverId, recieverrsPrivateKeyId, in, inLen,
                                symmetricKey, &symmetricKeyLen, keyLen);
    else
        returnCode = ECCdecrypt(recieverId, recieverrsPrivateKeyId, in, inLen,
                                symmetricKey, symmetricKeyLen, keyLen);

    //printBufferHexa(symmetricKey, symmetricKeyLen, "decrypted key");

    return returnCode;
}

//Performs AES encryption on the first data block.
CK_RV performAESEncryption(int senderId, void *in, size_t inLen, void *out,
                           size_t outLen, AESChainingMode chainingMode,
                           unsigned char *symmetricKey, AESKeyLength keyLength,
                           size_t counter)
{
    LOG_BUFFER_HEXA(in, inLen, "this is the plain data", senderId);
    StreamAES *streamAES = FactoryManager::getInstance().create(chainingMode);
    mapToInMiddleEncryptions[senderId] = std::make_pair(streamAES, counter);

    mapToInMiddleEncryptions[senderId].first->encryptStart(
        reinterpret_cast<unsigned char *>(in), inLen,
        static_cast<unsigned char *>(out), outLen, symmetricKey, keyLength);
    LOG_BUFFER_HEXA(out, outLen, "this is the encrypted data", senderId);

    return CKR_OK;
}

// Encrypts data using AES encryption with optional key generation or retrieval.
CK_RV AESencrypt(int senderId, int receiverId, void *in, size_t inLen,
                 void *out, size_t outLen, AESKeyLength keyLength,
                 AESChainingMode chainingMode, size_t counter,
                 std::string keyId, bool generateKeyFlag,
                 AsymmetricFunction func)
{
    CK_RV returnCode = logAndHandleErrors(
        "AES Encryption", senderId, keyId, in, inLen, out, outLen,
        getAESencryptedLength(inLen, isFirstChunkForEncryption(senderId),
                              chainingMode),
        isFirstChunkForEncryption(senderId), keyLength);

    if (returnCode != CKR_OK) {
        deleteFromMap(mapToInMiddleEncryptions, senderId,
                      "mapToInMiddleEncryptions");
        return returnCode;
    }

    size_t encryptedKeyLength = 0;

    //if first chunk
    if (isFirstChunkForEncryption(senderId)) {
        size_t symmetricKeyLen = keyLength;
        std::vector<unsigned char> symmetricKey(keyLength);

        // Handle key generation or retrieval:
        // if using key generation - generate a new key and concatenate it to the encrypted data
        if (generateKeyFlag) {
            generateKey(symmetricKey.data(), keyLength);
            encryptedKeyLength = getEncryptedLengthByAssymFunc(func);
            //encrypt the symmetric key and store it in the out buffer
            returnCode = encryptAESkey(
                senderId, receiverId, symmetricKey.data(), symmetricKeyLen, out,
                getEncryptedLengthByAssymFunc(func), func);

            if (returnCode != CKR_OK) {
                deleteFromMap(mapToInMiddleEncryptions, senderId,
                              "mapToInMiddleEncryptions");
                return returnCode;
            }
        }
        //otherwise retrieve the key from file by keyId:
        else {
            retrieveAESKeyByKeyId(senderId, keyId, symmetricKey.data(),
                                  symmetricKeyLen, ENCRYPT);
        }
        //printBufferHexa(symmetricKey, symmetricKeyLen, "key retrieved for encrypting");
        if (generateKeyFlag == true)
            log(logger::LogLevel::INFO,
                "Performing AES encryption for user id: " +
                    std::to_string(senderId) +
                    " for chunk of data number 1 with keyId: " +
                    keyId);  //aes key
        else
            log(logger::LogLevel::INFO,
                "Performing AES encryption for user id: " +
                    std::to_string(senderId) +
                    " for chunk of data number 1");  //receiver rsa public key
        // Perform AES encryption
        returnCode = performAESEncryption(
            senderId, in, inLen,
            static_cast<uint8_t *>(out) + encryptedKeyLength,
            outLen - encryptedKeyLength, chainingMode, symmetricKey.data(),
            keyLength, counter);
        if (returnCode != CKR_OK) {
            deleteFromMap(mapToInMiddleEncryptions, senderId,
                          "mapToInMiddleEncryptions");
            return returnCode;
        }
    }
    else {
        // Handle chunk continuation
        log(logger::LogLevel::INFO,
            "Performing AES encryption for user id: " +
                std::to_string(senderId) + " for chunk of data number " +
                std::to_string(counter -
                               mapToInMiddleEncryptions[senderId].second + 1) +
                ".");
        //perform encryption
        LOG_BUFFER_HEXA(in, inLen, "this is the plain data", senderId);
        mapToInMiddleEncryptions[senderId].first->encryptContinue(
            reinterpret_cast<unsigned char *>(in), inLen,
            static_cast<unsigned char *>(out), outLen);
        LOG_BUFFER_HEXA(out, outLen, "this is the encrypted data", senderId);
    }

    //reduce a chunk from the chunks counter
    mapToInMiddleEncryptions[senderId].second--;

    // If all chunks have been encrypted, erase the entry from the map
    if (mapToInMiddleEncryptions[senderId].second == 0) {
        deleteFromMap(mapToInMiddleEncryptions, senderId,
                      "mapToInMiddleEncryptions");
        log(logger::LogLevel::INFO,
            "Successfully completed AES encryption for user id: " +
                std::to_string(senderId) + " for all " +
                std::to_string(counter) + " chunks.");
    }

    return CKR_OK;
}

// Performs AES decryption on the first data block.
CK_RV performAESDecryption(int receiverId, void *in, size_t inLen, void *out,
                           size_t &outLen, AESChainingMode chainingMode,
                           unsigned char *symmetricKey, AESKeyLength keyLength,
                           size_t counter, bool generateKeyFlag)
{
    LOG_BUFFER_HEXA(in, inLen, "this is the encrypted data", receiverId);
    StreamAES *streamAES = FactoryManager::getInstance().create(chainingMode);
    mapToInMiddleDecryptions[receiverId] = std::make_pair(streamAES, counter);
    unsigned int outLen2 = outLen;
    try {
        mapToInMiddleDecryptions[receiverId].first->decryptStart(
            reinterpret_cast<unsigned char *>(in), inLen,
            static_cast<unsigned char *>(out), outLen2, symmetricKey,
            keyLength);
    }
    catch (std::exception &e) {
        log(logger::LogLevel::ERROR,
            "Failed to decrypt AES data for user id: " +
                std::to_string(receiverId) + ". Error: " + e.what());
        return CKR_ARGUMENTS_BAD;
    }
    LOG_BUFFER_HEXA(out, outLen2, "this is the decrypted data", receiverId);

    outLen = outLen2;
    return CKR_OK;
}

// Decrypts data using AES decryption with optional key generation or retrieval.
CK_RV AESdecrypt(int senderId, int receiverId, void *in, size_t inLen,
                 void *out, size_t &outLen, AsymmetricFunction func,
                 AESKeyLength keyLength, AESChainingMode chainingMode,
                 size_t counter, bool generateKeyFlag, std::string keyId = "")
{
    size_t encryptedKeyLen =
        ((isFirstChunkForDecryption(receiverId)) && generateKeyFlag)
            ? ((func == RSA) ? rsaGetEncryptedLen(RSA_KEY_SIZE)
                             : getECCencryptedLength())
            : 0;
    size_t requiredLength =
        getAESdecryptedLength(inLen, isFirstChunkForDecryption(receiverId),
                              chainingMode) -
        encryptedKeyLen;

    CK_RV error =
        logAndHandleErrors("AES Decryption", receiverId, keyId, in,
                           inLen - encryptedKeyLen, out, outLen, requiredLength,
                           isFirstChunkForDecryption(receiverId), keyLength);
    if (error != CKR_OK) {
        deleteFromMap(mapToInMiddleDecryptions, receiverId,
                      "mapToInMiddleDecryptions");
        return error;
    }

    //if first chunk
    if (isFirstChunkForDecryption(receiverId)) {
        std::vector<unsigned char> symmetricKey;
        size_t offset = 0;
        size_t symmetricKeyLength;
        // Handle key generation or retrieval:
        //if using key generation - decrypt the concatenated key
        if (generateKeyFlag) {
            size_t encryptedKeyLength = getEncryptedLengthByAssymFunc(func);
            size_t symmetricKeyLength = keyLength;
            symmetricKey.resize(keyLength);
            //decrypt the symmetric key
            CK_RV returnCode = decryptAESkey(
                senderId, receiverId, in, encryptedKeyLength,
                symmetricKey.data(), symmetricKeyLength, func, keyLength);
            offset = encryptedKeyLength;

            if (returnCode != CKR_OK) {
                deleteFromMap(mapToInMiddleDecryptions, receiverId,
                              "mapToInMiddleDecryptions");
                return returnCode;
            }
        }
        //otherwise retrieve the key from file by keyId:
        else {
            symmetricKeyLength =
                TempHsm::getInstance().getKeyLengthByKeyId(keyId);
            symmetricKey.resize(symmetricKeyLength);
            retrieveAESKeyByKeyId(receiverId, keyId, symmetricKey.data(),
                                  symmetricKeyLength, DECRYPT);
        }
        if (keyId != "")
            log(logger::LogLevel::INFO,
                "Performing AES decryption for user id: " +
                    std::to_string(receiverId) +
                    " for chunk of data number 1 with keyId: " + keyId + ".");
        else
            log(logger::LogLevel::INFO,
                "Performing AES decryption for user id: " +
                    std::to_string(receiverId) +
                    " for chunk of data number 1.");
        // Perform AES decryption
        CK_RV error = performAESDecryption(
            receiverId, static_cast<unsigned char *>(in) + offset,
            inLen - offset, out, outLen, chainingMode, symmetricKey.data(),
            keyLength, counter, generateKeyFlag);
        if (error != CKR_OK) {
            deleteFromMap(mapToInMiddleDecryptions, receiverId,
                          "mapToInMiddleDecryptions");
            return error;
        }
    }
    // Handle chunk continuation
    else {
        log(logger::LogLevel::INFO,
            "Performing AES decryption for user id: " +
                std::to_string(receiverId) + " for chunk of data number " +
                std::to_string(
                    counter - mapToInMiddleDecryptions[receiverId].second + 1) +
                ".");
        unsigned int outLen2 = outLen;
        try {
            LOG_BUFFER_HEXA(in, inLen, "this is the encrypted data",
                            receiverId);
            mapToInMiddleDecryptions[receiverId].first->decryptContinue(
                reinterpret_cast<unsigned char *>(in), inLen,
                static_cast<unsigned char *>(out), outLen2);
            LOG_BUFFER_HEXA(out, outLen2, "this is the decrypted data",
                            receiverId);
        }
        catch (std::exception &e) {
            log(logger::LogLevel::ERROR,
                "Failed to decrypt AES data for user id: " +
                    std::to_string(receiverId) + ". Error: " + e.what());
            deleteFromMap(mapToInMiddleDecryptions, receiverId,
                          "mapToInMiddleDecryptions");
            return CKR_ARGUMENTS_BAD;
        }
        outLen = outLen2;
    }
    // reduce a chunk from the chunks counter
    mapToInMiddleDecryptions[receiverId].second--;

    // If all chunks have been decrypted, erase the entry from the map
    if (mapToInMiddleDecryptions[receiverId].second == 0) {
        deleteFromMap(mapToInMiddleDecryptions, receiverId,
                      "mapToInMiddleDecryptions");
        log(logger::LogLevel::INFO,
            "Successfully completed AES decryption for user id: " +
                std::to_string(receiverId) + " for all " +
                std::to_string(counter) + " chunks.");
    }

    return CKR_OK;
}

// Generates a symmetric AES key, writes it to file and returns its keyId
std::string generateAESKey(int userId, AESKeyLength aesKeyLength,
                           std::vector<KeyPermission> permissions,
                           int destUserId)
{
    if (!isValidAESKeyLength(aesKeyLength)) {
        log(logger::LogLevel::ERROR,
            "Invalid AES key length provided: " + std::to_string(aesKeyLength) +
                ". Supported lengths are 128, 192, or 256 bits.");
        //return CKR_KEY_SIZE_RANGE;
        return "";
    }
    log(logger::LogLevel::INFO,
        "Generating AES key for user " + std::to_string(userId));
    return TempHsm::getInstance().generateAESKey(userId, aesKeyLength,
                                                 permissions, destUserId);
}

// Function to calculate length of encrypted data by AES when using a keyId.
size_t getAESencryptedLength(size_t dataLen, bool isFirst,
                             AESChainingMode chainingMode)
{
    return calculatEncryptedLenAES(dataLen, isFirst, chainingMode);
}

// Function to calculate length of decrypted data by AES  when using a keyId.
size_t getAESdecryptedLength(size_t dataLen, bool isFirst,
                             AESChainingMode chainingMode)
{
    if (dataLen == 0)
        return 0;
    return calculatDecryptedLenAES(dataLen, isFirst, chainingMode);
}

/**
 * @brief Encrypts data using AES.
 * 
 * This function performs AES encryption.
 * It performs encryption using the provided sender and receiver IDs, input data, and key ID. 
 * Unlike the inner `AESencrypt` function, this version does not generate a new AES key 
 * but instead retrieves an existing key.
 * 
 * @param senderId The ID of the sender.
 * @param receiverId The ID of the receiver.
 * @param in The input data to be encrypted.
 * @param inLen The length of the input data.
 * @param[out] out The buffer where the encrypted output will be stored.
 * @param[out] outLen The length of the encrypted output.
 * @param func The asymmetric encryption function used (e.g., RSA, ECC).
 * @param keyLength The AES key length (128, 192, or 256 bits).
 * @param chainingMode The AES chaining mode (e.g., CBC, CTR).
 * @param counter The counter for the chunked encryption process.
 * @param keyId The ID of the key to be retrieved.
 * @return CKR_OK on success or an appropriate error code on failure.
 */
CK_RV AESencrypt(int senderId, int receiverId, void *in, size_t inLen,
                 void *out, size_t outLen, AESKeyLength keyLength,
                 AESChainingMode chainingMode, size_t counter,
                 std::string keyId)
{
    return AESencrypt(senderId, receiverId, in, inLen, out, outLen, keyLength,
                      chainingMode, counter, keyId, false, RSA);
}

/**
 * @brief Decrypts data using AES.
 * 
 * This function performs AES decryption. 
 * It performs decryption using the provided sender and receiver IDs, input data, and key ID. 
 * Unlike the inner `AESdecrypt` function, this version does not get an aes key concatenated 
 * to data but instead retrieves an existing key.
 * 
 * @param senderId The ID of the sender.
 * @param receiverId The ID of the receiver.
 * @param in The input data to be decrypted.
 * @param inLen The length of the input data.
 * @param[out] out The buffer where the decrypted output will be stored.
 * @param[out] outLen The length of the decrypted output.
 * @param keyLength The AES key length (128, 192, or 256 bits).
 * @param chainingMode The AES chaining mode (e.g., CBC, CTR).
 * @param counter The chunks counter for the chunked decryption process.
 * @param keyId The ID of the key to be retrieved.
 * @return CKR_OK on successful encryption, an appropriate error code on failure..
 */
CK_RV AESdecrypt(int senderId, int receiverId, void *in, size_t inLen,
                 void *out, size_t &outLen, AESKeyLength keyLength,
                 AESChainingMode chainingMode, size_t counter,
                 std::string keyId)
{
    return AESdecrypt(senderId, receiverId, in, inLen, out, outLen, RSA,
                      keyLength, chainingMode, counter, false, keyId);
}

#pragma endregion A

#pragma region SIGN VERIFY

// Retrieves the size of the hashed message based on the hash algorithm.
size_t getHashedMessageSize(SHAAlgorithm hashFunc)
{
    switch (hashFunc) {
        case SHAAlgorithm::SHA_256:
            return 256 / BITS_IN_BYTE;
        case SHAAlgorithm::SHA_3_512:
            return 512 / BITS_IN_BYTE;
        default:
            throw std::invalid_argument("Invalid hash function");
    }
}

// Checks if the hashing process is done for a specific user.
bool isDoneSigning(int userId)
{
    return mapToInMiddleSigning.count(userId) != 0 &&
           mapToInMiddleSigning[userId].second == 0;
}

bool isDoneVerifying(int userId)
{
    return mapToInMiddleVerifying.count(userId) != 0 &&
           mapToInMiddleVerifying[userId].second == 0;
}

// Checks if the user is hashing the first chunk.
bool isFirstChunkSigning(int userId)
{
    return mapToInMiddleSigning.count(userId) == 0;
}

bool isFirstChunkVerifying(int userId)
{
    return mapToInMiddleVerifying.count(userId) == 0;
}

/**
 * @brief Retrieves the length of the signature based on the RSA encryption length.
 *
 * This function calculates and returns the length of a signature, which is determined by
 * the length of the RSA-encrypted data. It internally calls the function that provides
 * the RSA encrypted length.
 *
 * @return The length of the signature in bytes.
 */
size_t getSignatureLength()
{
    return getRSAencryptedLength();
}

// Updates the hash with the provided data for signing.
CK_RV signUpdate(int senderId, void *data, size_t dataLen,
                 SHAAlgorithm hashfunc, int counter)
{
    LOG_BUFFER_HEXA(data, dataLen, "chunk to sign:", senderId);
    CK_RV returnCode = CKR_OK;

    returnCode = logAndHandleErrors("Signing Digital Signature", senderId, data,
                                    dataLen, isFirstChunkSigning(senderId));
    if (returnCode != CKR_OK)
        return returnCode;

    log(logger::LogLevel::INFO, ("Signing for user id: " +
                                 std::to_string(senderId) + " chunk of data."));

    if (isFirstChunkSigning(senderId)) {  // first time
        HashFactory *factoryManager = &HashFactory::getInstance();
        mapToInMiddleSigning[senderId] =
            std::make_pair(std::unique_ptr<IHash>(), counter);
        returnCode = factoryManager->create(
            hashfunc, mapToInMiddleSigning[senderId].first);
        if (returnCode != CKR_OK) {
            deleteFromMap(mapToInMiddleSigning, senderId,
                          "mapToInMiddleSigning");
            return returnCode;
        }
    }

    std::vector<uint8_t>(static_cast<uint8_t *>(data),
                         static_cast<uint8_t *>(data) + dataLen);

    returnCode = mapToInMiddleSigning[senderId].first->update(
        std::vector<uint8_t>(static_cast<uint8_t *>(data),
                             static_cast<uint8_t *>(data) + dataLen));
    mapToInMiddleSigning[senderId].second--;

    if (returnCode != CKR_OK)
        deleteFromMap(mapToInMiddleSigning, senderId, "mapToInMiddleSigning");

    return returnCode;
}

// Finalizes the signing process and retrieves the resulting digital signature.
CK_RV signFinalize(int senderId, void *signature, size_t signatureLen,
                   SHAAlgorithm hashfunc, std::string keyId)
{
    log(logger::LogLevel::INFO,
        "Signing for user id: " + std::to_string(senderId) + " finalizing.");
    size_t hashLen = getHashedMessageSize(hashfunc);
    std::vector<uint8_t> hash(hashLen);
    if (mapToInMiddleSigning.count(senderId) == 0)
        return CKR_SIGNATURE_INVALID;
    CK_RV returnCode = mapToInMiddleSigning[senderId].first->finalize(hash);
    deleteFromMap(mapToInMiddleSigning, senderId, "mapToInMiddleSigning");
    LOG_BUFFER_HEXA(hash.data(), hashLen, "hashed in sign finalize", senderId);
    if (returnCode != CKR_OK)
        return returnCode;

    returnCode = RSAencrypt(senderId, keyId, hash.data(), hashLen, signature,
                            signatureLen);
    LOG_BUFFER_HEXA(signature, signatureLen, "signature in sign finalize",
                    senderId);
    return returnCode;
}

// Verifies and updates the hash with the provided data.
CK_RV verifyUpdate(int recieverId, void *data, size_t dataLen,
                   SHAAlgorithm hashFunc, size_t counter)
{
    LOG_BUFFER_HEXA(data, dataLen, "chunk to verify:", recieverId);
    CK_RV returnCode = CKR_OK;

    returnCode =
        logAndHandleErrors("Verifying Digital Signature", recieverId, data,
                           dataLen, isFirstChunkVerifying(recieverId));
    if (returnCode != CKR_OK)
        return returnCode;

    log(logger::LogLevel::INFO,
        ("Verifying for user id: " + std::to_string(recieverId) +
         " chunk of data."));

    if (isFirstChunkVerifying(recieverId)) {  // first time
        HashFactory *factoryManager = &HashFactory::getInstance();
        mapToInMiddleVerifying[recieverId] =
            std::make_pair(std::unique_ptr<IHash>(), counter);
        returnCode = factoryManager->create(
            hashFunc, mapToInMiddleVerifying[recieverId].first);
        if (returnCode != CKR_OK) {
            deleteFromMap(mapToInMiddleVerifying, recieverId,
                          "mapToInMiddleVerifying");
            return returnCode;
        }
    }

    std::vector<uint8_t>(static_cast<uint8_t *>(data),
                         static_cast<uint8_t *>(data) + dataLen);

    returnCode = mapToInMiddleVerifying[recieverId].first->update(
        std::vector<uint8_t>(static_cast<uint8_t *>(data),
                             static_cast<uint8_t *>(data) + dataLen));
    mapToInMiddleVerifying[recieverId].second--;

    if (returnCode != CKR_OK)
        deleteFromMap(mapToInMiddleVerifying, recieverId,
                      "mapToInMiddleVerifying");

    return returnCode;
}

// Verifies the digital signature of the hashed input data and finalizes the signature verification process.
CK_RV verifyFinalize(int recieverId, void *signature, size_t signatureLen,
                     SHAAlgorithm hashFunc, std::string keyId)
{
    log(logger::LogLevel::INFO,
        "Verifying for user id: " + std::to_string(recieverId) +
            " finalizing.");
    size_t hashLen = getHashedMessageSize(hashFunc);
    std::vector<uint8_t> hash(hashLen);
    if (mapToInMiddleVerifying.count(recieverId) == 0)
        return CKR_SIGNATURE_INVALID;
    CK_RV returnCode = mapToInMiddleVerifying[recieverId].first->finalize(hash);
    deleteFromMap(mapToInMiddleVerifying, recieverId, "mapToInMiddleVerifying");
    if (returnCode != CKR_OK)
        return returnCode;

    LOG_BUFFER_HEXA(hash.data(), hashLen, "hashed in verify finalize",
                    recieverId);
    LOG_BUFFER_HEXA(signature, signatureLen, "signature in verify finalize",
                    recieverId);

    size_t decryptSignatureLen = rsaGetDecryptedLen(RSA_KEY_SIZE);
    std::vector<uint8_t> decryptSignature(decryptSignatureLen);
    returnCode = RSAdecrypt(recieverId, keyId, signature, signatureLen,
                            decryptSignature.data(), &decryptSignatureLen,
                            getRSAdecryptedLength());
    //printBufferHexa(decryptSignature.data(), decryptSignatureLen, "decrypted signature by verify finalize");
    if (returnCode != CKR_OK)
        return returnCode;
    LOG_BUFFER_HEXA(decryptSignature.data(), decryptSignatureLen,
                    "decrypted signature in verify finalize", recieverId);

    //printBufferHexa(hash.data(), hashLen, "hash by verify finalize (before if)");
    if (decryptSignatureLen != hashLen ||
        memcmp(decryptSignature.data(), hash.data(), decryptSignatureLen) !=
            0) {
        returnCode = CKR_SIGNATURE_INVALID;
        log(logger::LogLevel::ERROR,
            "Verifying signature failed for user id: " +
                std::to_string(recieverId) + ".");
    }

    return returnCode;
}

#pragma endregion SIGN VERIFY

#pragma region ENCRYPT DECRYPT

/**
 * @brief Retrieves the encrypted length for the specified user and input data.
 *
 * This function calculates the total length of the encrypted data based on the sender's
 * encryption configuration, including both symmetric and asymmetric encryption lengths.
 * If this is the first chunk of data (`isFirst` is true), the length also includes the 
 * encrypted symmetric key.
 *
 * The function retrieves the encryption function type from the user's configuration.
 * If the user ID does not exist or any error occurs while retrieving the configuration,
 * it logs an error and returns the error code `CKR_FUNCTION_FAILED` instead of the length.
 *
 * @param senderId The ID of the user whose encryption configuration is being retrieved.
 * @param inLen The length of the input data to be encrypted.
 * @param isFirst Indicates if this is the first chunk of data, which includes the symmetric key.
 * 
 * @return The total length of the encrypted data in bytes, or `CKR_FUNCTION_FAILED` if 
 * the user does not exist or an error occurs.
 */
size_t getEncryptedLen(int senderId, size_t inLen, bool isFirst)
{
    DEBUG_LOG("here getEncryptedLen");
    try {
        // Retrieve the encryption function type for the given sender ID
        CryptoConfig config = TempHsm::getInstance().getUserConfig(senderId);
        // encrypted padded data (+ if first chunk: encrypted symmetric key)
        return getAESencryptedLength(inLen, isFirst, config.aesChainingMode) +
               (isFirst
                    ? getEncryptedLengthByAssymFunc(config.asymmetricFunction)
                    : 0);
    }
    catch (const std::runtime_error &e) {
        log(logger::LogLevel::ERROR,
            "Error while retrieving encryption configuration for user ID " +
                std::to_string(senderId) + ": " + e.what());

        return CKR_USER_NOT_LOGGED_IN;
    }
}

/**
 * @brief Retrieves the decrypted length for the specified user and input data.
 *
 * This function calculates the total length of the decrypted data based on the sender's
 * encryption configuration. It determines the decrypted length of the data that was
 * encrypted with AES, subtracting the asymmetric encrypted key length if it's the first
 * chunk (`isFirst` is true).
 *
 * The function retrieves the encryption function type from the user's configuration.
 * If the user ID does not exist or any error occurs while retrieving the configuration,
 * it logs an error and returns the error code `CKR_FUNCTION_FAILED` instead of the length.
 *
 * @param senderId The ID of the user whose encryption configuration is being retrieved.
 * @param inLen The length of the encrypted input data.
 * @param isFirst Indicates if this is the first chunk of data, which includes the symmetric key.
 * 
 * @return The total length of the decrypted data in bytes, or `CKR_FUNCTION_FAILED` if 
 * the user does not exist or an error occurs.
 */
size_t getDecryptedLen(int senderId, size_t inLen, bool isFirst)
{
    DEBUG_LOG("here getDecryptedLen");
    try {
        // Retrieve the encryption function type for the given sender ID
        CryptoConfig config = TempHsm::getInstance().getUserConfig(senderId);
        size_t encryptedLength =
            (inLen -
             (isFirst ? getEncryptedLengthByAssymFunc(config.asymmetricFunction)
                      : 0));

        return calculatDecryptedLenAES(encryptedLength, isFirst,
                                       config.aesChainingMode);
    }
    catch (const std::runtime_error &e) {
        log(logger::LogLevel::ERROR,
            "Error while retrieving encryption configuration for user ID " +
                std::to_string(senderId) + ": " + e.what());

        return CKR_USER_NOT_LOGGED_IN;
    }
}

/**
 * @brief Encrypts the input data using AES and signs it with RSA.
 *
 * This function performs the encryption and signing operations for the input data.
 * It uses the sender's user ID to retrieve its encryption and signing configurations.
 * The encrypted data is then signed using the sender's private key.
 * and by the last chunk the signature is sent in the signature buffer.
 * The encryption and signing are based on the settings defined in the sender's user configuration.
 *
 * @param senderId The ID of the sender, used to retrieve the encryption and signing configurations.
 * @param receiverId The ID of the receiver, used to retrieve the public key for encryption.
 * @param in The input data to be encrypted and signed.
 * @param inLen The length of the input data.
 * @param out The buffer to store the encrypteddata.
 * @param outLen The length of the encrypted data.
 * @param signature The buffer to store the digital signature.
 * @param signatureLen The length of the digital signature.
 * @param counter The counter value used for streaming.
 *
 * @return CKR_OK on success, or an appropriate error code on failure.
 */
CK_RV encrypt(int senderId, int receiverId, void *in, size_t inLen, void *out,
              size_t outLen, void *signature, size_t signatureLen,
              size_t counter)
{
    LOG_BUFFER_HEXA(in, inLen, "this is the plain data", senderId);

    CryptoConfig config;

    try {
        config = TempHsm::getInstance().getUserConfig(senderId);
    }
    catch (const std::runtime_error &e) {
        log(logger::LogLevel::ERROR,
            "Error while retrieving encryption configuration for user ID " +
                std::to_string(senderId) + ": " + e.what());

        return CKR_USER_NOT_LOGGED_IN;
    }

    CK_RV returnCode;

    std::string recieversPublicKeyId =
        TempHsm::getInstance().getPublicKeyIdByUserId(
            receiverId, config.asymmetricFunction);

    //perform encryption
    returnCode =
        AESencrypt(senderId, receiverId, in, inLen, out, outLen,
                   config.aesKeyLength, config.aesChainingMode, counter,
                   recieversPublicKeyId, true, config.asymmetricFunction);
    if (returnCode != CKR_OK)
        return returnCode;

    //sign the data
    returnCode = signUpdate(senderId, in, inLen, config.hashFunction, counter);
    if (returnCode != CKR_OK)
        return returnCode;
    if (isDoneSigning(senderId)) {
        std::string senderPrivateKeyId =
            TempHsm::getInstance().getPrivateKeyIdByUserId(senderId, RSA);
        returnCode = signFinalize(senderId, signature, signatureLen,
                                  config.hashFunction, senderPrivateKeyId);
        if (returnCode != CKR_OK)
            return returnCode;
    }
    LOG_BUFFER_HEXA(out, outLen, "this is the encrypted data", senderId);

    return CKR_OK;
}

/**
 * @brief  Decrypts the input data using AES and verifies it with RSA.
 *
 * This function gets the digital signature and encrypted data,
 * decrypts the data using AES, and verifies the digital signature using RSA. 
 * The decryption and signature verification are based on the settings defined in the sender's user configuration.
 *
 * @param senderId The ID of the sender, used for retrieving the signature verification settings.
 * @param receiverId The ID of the receiver, used for retrieving the private key for decryption.
 * @param in The input buffer containing the concatenated signature and encrypted data.
 * @param inLen The length of the input buffer.
 * @param out The buffer to store the decrypted data.
 * @param[out] outLen The length of the decrypted data.
 * @param counter The counter value used for streaming.
 *
 * @return CKR_OK on success, or an appropriate error code on failure.
 */
CK_RV decrypt(int senderId, int receiverId, void *in, size_t inLen,
              void *signature, size_t signatureLen, void *out, size_t &outLen,
              size_t counter)
{
    LOG_BUFFER_HEXA(in, inLen, "this is the encrypted data", receiverId);

    CryptoConfig config;

    try {
        config = TempHsm::getInstance().getUserConfig(senderId);
    }
    catch (const std::runtime_error &e) {
        log(logger::LogLevel::ERROR,
            "Error while retrieving encryption configuration for user ID " +
                std::to_string(senderId) + ": " + e.what());

        return CKR_USER_NOT_LOGGED_IN;
    }

    CK_RV returnCode;

    //perform decryption
    returnCode = AESdecrypt(senderId, receiverId, in, inLen, out, outLen,
                            config.asymmetricFunction, config.aesKeyLength,
                            config.aesChainingMode, counter, true);
    if (returnCode != CKR_OK)
        return returnCode;
    //perform signature verification
    returnCode =
        verifyUpdate(receiverId, out, outLen, config.hashFunction, counter);
    if (returnCode != CKR_OK)
        return returnCode;
    if (isDoneVerifying(receiverId)) {
        std::string senderPublicKeyId =
            TempHsm::getInstance().getPublicKeyIdByUserId(senderId, RSA);
        returnCode = verifyFinalize(receiverId, signature, signatureLen,
                                    config.hashFunction, senderPublicKeyId);
    }

    if (returnCode != CKR_OK)
        return returnCode;
    LOG_BUFFER_HEXA(out, outLen, "this is the decrypted data", receiverId);

    return CKR_OK;
}

#pragma endregion ENCRYPT DECRYPT

//////////////////////////////////////
//json copying to maps
// /**
//  * @brief Loads key data from a JSON file and populates key maps.
//  *
//  * This function reads a JSON file containing key information and populates
//  * the corresponding key maps with user IDs and key IDs. It handles
//  different
//  * key types, including ECC and RSA private and public keys. The JSON file
//  * should have a structure where each key entry includes the key type, user
//  ID,
//  * and key ID.
//  *
//  * @note The JSON file is expected to be located at "../keys/keys.json".
//  *       The key types supported are "ECC-Private", "ECC-Public",
//  "RSA-Private",
//  *       and "RSA-Public".
//  *
//  * @return void This function does not return any value.
//  *
//  * @throws std::ifstream::failure If the file could not be opened for
//  reading.
//  */
// void loadDataFromJson() {
//   std::string filePath = "../keys/keys.json";
//   std::ifstream file(filePath);
//   if (!file.is_open()) {
//     std::cerr << "Could not open the file!" << std::endl;
//     return;
//   }
//   nlohmann::json jsonData;
//   file >> jsonData;
//   for (const auto &key : jsonData["keys"]) {
//     // Check if the key_type is "ECC-Private"
//     int user;
//     std::string keyId;
//     if (key["key_type"] == "ECC-Private") {
//       // Extract user and key_id
//       user = key["user"];
//       keyId = key["key_id"];
//       // Insert into the map
//       TempHsm::EccPrivateKeysIds[user] = keyId;
//     } else if (key["key_type"] == "ECC-Public") {
//       user = key["user"];
//       keyId = key["key_id"];
//       TempHsm::EccPublicKeysIds[user] = keyId;
//     } else if (key["key_type"] == "RSA-Private") {
//       user = key["user"];
//       keyId = key["key_id"];
//       TempHsm::RsaPrivateKeysIds[user] = keyId;
//     } else if (key["key_type"] == "RSA-Public") {
//       user = key["user"];
//       keyId = key["key_id"];
//       TempHsm::RsaPublicKeysIds[user] = keyId;
//     }
//   }
//   // Close the file after reading
//   file.close();
// }
