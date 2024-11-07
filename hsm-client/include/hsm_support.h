#ifndef __HSM_SUPPORT__
#define __HSM_SUPPORT__
#include <stddef.h>
#include <map>
#include <vector>
#include <cstdint>
#include "general.h"
namespace hsm {
bool decryptData(void *data, uint32_t senderId, uint32_t myId);
bool encryptData(const void *data, int dataLen, uint8_t *encryptedData,
                 size_t encryptedLength, uint32_t myId, uint32_t receiverId);
size_t getEncryptedLen(uint32_t myId, size_t dataLength);
bool generateKeys(
    const std::map<uint32_t, std::vector<KeyPermission>> &userIdsPermissions);
bool configureUsers(const std::map<uint32_t, CryptoConfig> &userIdsConfigs);
bool configureUser(uint32_t userId, const CryptoConfig &config);
bool generateKeys(uint32_t userId,
                  const std::vector<KeyPermission> &permissions);
}  // namespace hsm
#endif  // __HSM_SUPPORT__