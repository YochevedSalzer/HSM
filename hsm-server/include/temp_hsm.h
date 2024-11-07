#ifndef __TEMP_HSM_H__
#define __TEMP_HSM_H__

#include "aes.h"
#include "debug_utils.h"
#include "ecc.h"
#include "general.h"
#include "rsa.h"
#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <fstream>
#include <chrono>
#include <iomanip>
#include "json.hpp"
constexpr size_t RSA_KEY_SIZE = 1024;

enum class KeyType { AES, RSA_PUB, RSA_PRIV, ECC_PUB, ECC_PRIV };

class TempHsm {
   public:
    // Deleted to avoid copying and assignment
    TempHsm(const TempHsm &) = delete;
    TempHsm &operator=(const TempHsm &) = delete;

    static TempHsm &getInstance();

    void configure(int userId, CryptoConfig config);
    CryptoConfig getUserConfig(int userId);

    std::string generateAESKey(int ownerId, AESKeyLength aesKeyLength,
                               const std::vector<KeyPermission> &permissions,
                               int destUserId);
    std::pair<std::string, std::string> generateRSAKeyPair(
        int userId, const std::vector<KeyPermission> &permissions);
    std::pair<std::string, std::string> generateECCKeyPair(
        int userId, const std::vector<KeyPermission> &permissions);

    std::string getPublicKeyIdByUserId(int userId, AsymmetricFunction function);
    std::string getPrivateKeyIdByUserId(int userId,
                                        AsymmetricFunction function);
    std::string getSymmetricKeyIdByUserIdAndKeySize(int userId,
                                                    AESKeyLength aesKeyLength);
    void getKeyByKeyId(int userId, const std::string &keyId,
                       KeyPermission usage, uint8_t *keyBuffer, size_t keySize);
    size_t getKeyLengthByKeyId(const std::string &keyId);

   private:
    TempHsm();

    // For each user, store configurations, keys, and permissions
    std::unordered_map<int, CryptoConfig> usersConfig;

    struct KeyInfo {
        std::string fileName;
        KeyType keyType;
        int ownerId;
        size_t keySize;
        std::set<KeyPermission> ownerPermissions;
        std::unordered_map<int, std::set<KeyPermission>> otherUsersPermissions;
    };
    std::unordered_map<std::string, KeyInfo> keyIdUsersPermissions;
    KeyType getKeyTypeById(const std::string &keyId);
    std::string getFileNameFromKeyId(const std::string &keyId);
    void loadPermissionsFromJson();
    void addKey(const std::string &keyId, const uint8_t *keyBuffer,
                size_t keySize, const std::string &keyType, int ownerId,
                const std::vector<KeyPermission> &ownerPermissions,
                const std::vector<KeyPermission> &allUsersPermissions,
                int destUserId = -1);
    void checkPermission(const std::string &keyId, int userId,
                         KeyPermission usage);
};
#endif  // __TEMP_HSM_H__
