#include <mutex>

#include "hsm_support.h"
#include "crypto_api.h"
#include "debug_utils.h"

namespace hsm {
std::mutex cryptoMutex;
/**
 * @brief Decrypts the given data.
 *
 * This function attempts to decrypt the provided data. If decryption fails,
 * the data remains unchanged.
 *
 * @param[in,out] data Pointer to the data to be decrypted. 
 *                     On success, the decrypted data is written back to this pointer.
 * @param[in] senderId The ID of the sender, used for decryption.
 * @param[in] myId The ID of the recipient (current entity), used to initialize the CryptoClient.
 * 
 * @return true if decryption was successful, false otherwise. 
 *         If false, the original data remains unchanged.
 */
bool decryptData(void *data, uint32_t senderId, uint32_t myId)
{
    std::lock_guard<std::mutex> lock(cryptoMutex);
    DEBUG_LOG("start");
    CryptoClient client(myId);
    size_t encryptedLength = client.getEncryptedLengthByEncrypted(data);

    size_t decryptedLength = client.getDecryptedLen(senderId, encryptedLength);

    uint8_t decryptedData[decryptedLength];

    CK_RV decryptResult = client.decrypt(senderId, data, encryptedLength,
                                         decryptedData, decryptedLength);
    if (decryptResult != CKR_OK) {
        log(logger::LogLevel::ERROR, "HSM: The message dycryption failed");
        return false;
    }
    LOG_BUFFER_HEXA(decryptedData, decryptedLength,
                    "got from " + std::to_string(senderId), myId);
    memcpy(data, decryptedData, decryptedLength);
    log(logger::LogLevel::INFO, "HSM: The message dycrypted successfully");
    DEBUG_LOG("end");
    return true;
}

/**
 * @brief Encrypts the given data.
 *
 * This function encrypts the provided data using the receiver's ID and writes 
 * the encrypted data to the provided buffer. 
 *
 * @param[in] data Pointer to the data to be encrypted.
 * @param[in] dataLen The length of the data to be encrypted.
 * @param[out] encryptedData Pointer to the buffer where the encrypted data will be stored.
 * @param[in] encryptedLength The size of the buffer to store the encrypted data.
 * @param[in] myId The ID of the sender (current entity), used to initialize the CryptoClient.
 * @param[in] receiverId The ID of the recipient, used for encryption.
 * 
 * @return true if encryption was successful, false otherwise.
 */
bool encryptData(const void *data, int dataLen, uint8_t *encryptedData,
                 size_t encryptedLength, uint32_t myId, uint32_t receiverId)
{
    std::lock_guard<std::mutex> lock(cryptoMutex);
    DEBUG_LOG("start");
    LOG_BUFFER_HEXA(data, dataLen, " send to " + std::to_string(receiverId),
                    myId);
    CryptoClient client(myId);
    CK_RV encryptResult = client.encrypt(receiverId, data, dataLen,
                                         encryptedData, encryptedLength);
    if (encryptResult != CKR_OK) {
        log(logger::LogLevel::ERROR, "HSM: The message encryption failed");
        return false;
    }
    log(logger::LogLevel::INFO, "HSM: The message encrypted successfully");
    DEBUG_LOG("end");
    return true;
}

/**
 * @brief Gets the encrypted length of the data.
 *
 * This function calculates and returns the length of the data after encryption, 
 *
 * @param[in] myId The ID of the entity requesting the encrypted length.
 * @param[in] dataLength The length of the data to be encrypted.
 * 
 * @return The length of the encrypted data.
 */
size_t getEncryptedLen(uint32_t myId, size_t dataLength)
{
    std::lock_guard<std::mutex> lock(cryptoMutex);
    DEBUG_LOG("start");
    CryptoClient client(myId);
    size_t len = client.getEncryptedLen(myId, dataLength);
    DEBUG_LOG("end");
    return len;
}

bool configureUsers(const std::map<uint32_t, CryptoConfig> &userIdsConfigs)
{
    bool allSuccess = true;
    for (const auto &[userId, config] : userIdsConfigs) {
        CryptoClient client(userId);
        CK_RV returnCode = client.configure(config);
        if (returnCode != CKR_OK) {
            log(logger::LogLevel::ERROR, "HSM: Configuration for userId " +
                                             std::to_string(userId) +
                                             " failed.");
            allSuccess = false;
        }
        else {
            log(logger::LogLevel::INFO, "HSM: Configured for userId " +
                                            std::to_string(userId) +
                                            " successfully.");
        }
    }
    return allSuccess;
}
bool configureUser(uint32_t userId, const CryptoConfig &config)
{
    CryptoClient client(userId);
    CK_RV returnCode = client.configure(config);
    if (returnCode != CKR_OK) {
        log(logger::LogLevel::ERROR, "HSM: Configuration for userId " +
                                         std::to_string(userId) + " failed.");
        return false;
    }
    else {
        log(logger::LogLevel::INFO, "HSM: Configured for userId " +
                                        std::to_string(userId) +
                                        " successfully.");
        return true;
    }
}

bool generateKeys(
    const std::map<uint32_t, std::vector<KeyPermission>> &userIdsPermissions)
{
    CryptoClient client(0);
    CK_RV returnCode = client.bootSystem(userIdsPermissions);
    if (returnCode != CKR_OK) {
        log(logger::LogLevel::ERROR, "HSM: Keys generation failed.");
        return false;
    }
    else {
        log(logger::LogLevel::INFO, "HSM: Generated keys successfully.");
        return true;
    }
}
bool generateKeys(uint32_t userId,
                  const std::vector<KeyPermission> &permissions)
{
    CryptoClient client(userId);
    CK_RV returnCode = client.addProccess(userId, permissions);
    if (returnCode != CKR_OK) {
        log(logger::LogLevel::ERROR,
            "HSM: Keys generation failed for userId " + std::to_string(userId));
        return false;
    }
    else {
        log(logger::LogLevel::INFO,
            "HSM: Generated keys successfully for userId " +
                std::to_string(userId));
        return true;
    }
}

}  // namespace hsm
