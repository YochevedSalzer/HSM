#include <filesystem>
#include "temp_hsm.h"
// #define DEBUG
#ifdef DEBUG
const std::string KEYS_DIR = "keys/";
#else
const std::string KEYS_DIR = "../keys/";
#endif
const std::string KEYS_CONFIG_FILE = KEYS_DIR + "keys_config.json";
#pragma region UTILS
void removePermissionsJson(const std::string &keyId)
{
    // Load existing JSON data
    std::ifstream file(KEYS_CONFIG_FILE);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open JSON file for update.");
    }
    nlohmann::json jsonData;
    file >> jsonData;
    file.close();

    // Remove the key entry in JSON
    auto &keys = jsonData["keys"];
    keys.erase(std::remove_if(keys.begin(), keys.end(),
                              [&](const nlohmann::json &key) {
                                  return key["key_id"] == keyId;
                              }),
               keys.end());

    // Write the updated JSON data back to file
    std::ofstream outFile(KEYS_CONFIG_FILE);
    outFile << jsonData.dump(4);
}
// Helper function to extract permissions from a JSON object
std::set<KeyPermission> extractPermissionsFromJson(
    const nlohmann::json &permissionsJson)
{
    std::set<KeyPermission> permissions;

    if (permissionsJson.at("encrypt").get<bool>()) {
        permissions.insert(KeyPermission::ENCRYPT);
    }
    if (permissionsJson.at("decrypt").get<bool>()) {
        permissions.insert(KeyPermission::DECRYPT);
    }
    if (permissionsJson.at("sign").get<bool>()) {
        permissions.insert(KeyPermission::SIGN);
    }
    if (permissionsJson.at("verify").get<bool>()) {
        permissions.insert(KeyPermission::VERIFY);
    }
    if (permissionsJson.at("exportable").get<bool>()) {
        permissions.insert(KeyPermission::EXPORTABLE);
    }

    return permissions;
}
// Helper function to create JSON from a vector of permissions
nlohmann::json createPermissionsJson(
    const std::vector<KeyPermission> &permissions)
{
    nlohmann::json permissionsJson = {{"encrypt", false},
                                      {"decrypt", false},
                                      {"sign", false},
                                      {"verify", false},
                                      {"exportable", false}};

    for (const auto &perm : permissions) {
        switch (perm) {
            case KeyPermission::ENCRYPT:
                permissionsJson["encrypt"] = true;
                break;
            case KeyPermission::DECRYPT:
                permissionsJson["decrypt"] = true;
                break;
            case KeyPermission::SIGN:
                permissionsJson["sign"] = true;
                break;
            case KeyPermission::VERIFY:
                permissionsJson["verify"] = true;
                break;
            case KeyPermission::EXPORTABLE:
                permissionsJson["exportable"] = true;
                break;
        }
    }

    return permissionsJson;
}
KeyType stringKeyTypeToEnum(const std::string &type)
{
    if (type == "AES")
        return KeyType::AES;
    if (type == "RSA_PUB")
        return KeyType::RSA_PUB;
    if (type == "RSA_PRIV")
        return KeyType::RSA_PRIV;
    if (type == "ECC_PUB")
        return KeyType::ECC_PUB;
    if (type == "ECC_PRIV")
        return KeyType::ECC_PRIV;
    throw std::invalid_argument("Unknown key type: " + type);
}
std::string enumKeyPermissionToString(const KeyPermission &keyPermission)
{
    std::string keyPermissionStr;
    switch (keyPermission) {
        case KeyPermission::ENCRYPT:
            keyPermissionStr = "encrypt";
            break;
        case KeyPermission::DECRYPT:
            keyPermissionStr = "decrypt";
            break;
        case KeyPermission::SIGN:
            keyPermissionStr = "sign";
            break;
        case KeyPermission::VERIFY:
            keyPermissionStr = "verify";
            break;
        case KeyPermission::EXPORTABLE:
            keyPermissionStr = "exportable";
            break;
        default:
            throw std::runtime_error("Unknown key permission: " +
                                     keyPermission);
    }
    return keyPermissionStr;
}
// Function to write the key buffer to a file in hex format
void writeKeyToFile(const uint8_t *keyBuffer, size_t keySize,
                    const std::string &fileName)
{
    std::ofstream keyFile(KEYS_DIR + fileName);
    if (!keyFile) {
        throw std::runtime_error("Unable to open key file for writing: " +
                                 fileName);
    }

    // Write each byte in hex format, 16 bytes per line
    for (size_t i = 0; i < keySize; ++i) {
        keyFile << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(keyBuffer[i]);

        // Add a space between bytes and a newline every 16 bytes
        if ((i + 1) % 16 == 0) {
            keyFile << "\n";
        }
        else {
            keyFile << " ";
        }
    }
    keyFile.close();
}
std::string generateTimestampedKeyID()
{
    static int counter = 0;  // Static to persist across calls
    auto now = std::chrono::system_clock::now();
    auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                     now.time_since_epoch())
                     .count();

    std::string keyId =
        "key_" + std::to_string(nowMs) + "_" + std::to_string(counter);
    counter = (counter + 1) % 1000;  // Reset counter after 1000 IDs per ms
    return keyId;
}

// Serialize Point to a void* buffer
void pointToBuffer(const Point &point, uint8_t *out)
{
    size_t countX, countY;
    std::vector<uint8_t> bufferX, bufferY;
    size_t offset = 0;

    // Serialize x (size + data)
    bufferX.resize((mpz_sizeinbase(point.x.get_mpz_t(), 2) + 7) / 8);
    mpz_export(bufferX.data(), &countX, 1, 1, 0, 0, point.x.get_mpz_t());
    bufferX.resize(countX);  // resize buffer to actual size after export

    // Store x's size and data
    std::memcpy(out + offset, &countX, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    std::memcpy(out + offset, bufferX.data(), countX);
    offset += countX;

    // Serialize y (size + data)
    bufferY.resize((mpz_sizeinbase(point.y.get_mpz_t(), 2) + 7) / 8);
    mpz_export(bufferY.data(), &countY, 1, 1, 0, 0, point.y.get_mpz_t());
    bufferY.resize(countY);  // resize buffer to actual size after export

    // Store y's size and data
    std::memcpy(out + offset, &countY, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    std::memcpy(out + offset, bufferY.data(), countY);
}
// Function to read the key from a file into a buffer
void readKeyFromFile(uint8_t *keyBuffer, size_t keySize,
                     const std::string &fileName)
{
    std::ifstream keyFile(KEYS_DIR + fileName);
    if (!keyFile) {
        throw std::runtime_error("Unable to open key file for reading: " +
                                 fileName);
    }

    std::string hexByte;
    size_t i = 0;

    // Read each hex byte and store it in the buffer until keySize is reached
    while (keyFile >> hexByte && i < keySize) {
        keyBuffer[i] = static_cast<uint8_t>(std::stoi(hexByte, nullptr, 16));
        ++i;
    }

    if (i != keySize) {
        throw std::runtime_error("Key size mismatch when reading from file: " +
                                 fileName);
    }
}
#pragma endregion
#pragma region TEMP_HSM
TempHsm &TempHsm::getInstance()
{
    static TempHsm instance;
    return instance;
}

void TempHsm::configure(int userId, CryptoConfig config)
{
    usersConfig[userId] = CryptoConfig(config);
}

std::string TempHsm::generateAESKey(
    int ownerId, AESKeyLength aesKeyLength,
    const std::vector<KeyPermission> &permissions, int destUserId)
{
    std::string keyId =
        getSymmetricKeyIdByUserIdAndKeySize(ownerId, aesKeyLength);
    if (keyId != "") {
            log(logger::LogLevel::INFO,"User " + std::to_string(ownerId) + " already has AES key of size"+std::to_string(aesKeyLength)+". Skipping key creation.");
        return keyId;
    }
    keyId = generateTimestampedKeyID();
    std::string filePath = keyId + ".key";
    int keySize = aesKeyLengthData[aesKeyLength].keySize;
    std::vector<unsigned char> key(keySize);
    generateKey(key.data(), aesKeyLength);
    addKey(keyId, key.data(), keySize, "AES", ownerId, permissions,
           {KeyPermission::DECRYPT}, destUserId);

    return keyId;
}

std::pair<std::string, std::string> TempHsm::generateRSAKeyPair(
    int userId, const std::vector<KeyPermission> &permissions)
{
    std::string pubKeyId =
        getPublicKeyIdByUserId(userId, AsymmetricFunction::RSA);
    std::string privKeyId =
        getPrivateKeyIdByUserId(userId, AsymmetricFunction::RSA);
    if (pubKeyId != "" || privKeyId != "") {
    log(logger::LogLevel::INFO,"User " + std::to_string(userId) + " already has RSA key. Skipping key creation.");
        return std::make_pair(pubKeyId, privKeyId);
    }

    pubKeyId = generateTimestampedKeyID();
    privKeyId = generateTimestampedKeyID();

    // ASK:: does he give other premossions? and premissions to private and
    // public?
    //  Store key pair with permissions

    size_t pubLen = rsaGetPublicKeyLen(RSA_KEY_SIZE);
    size_t priLen = rsaGetPrivateKeyLen(RSA_KEY_SIZE);
    std::vector<uint8_t> pubBuff(pubLen);
    std::vector<uint8_t> priBuff(priLen);
    CK_RV rv1 = rsaGenerateKeys(RSA_KEY_SIZE, pubBuff.data(), pubLen,
                                priBuff.data(), priLen);
    addKey(pubKeyId, pubBuff.data(), pubLen, "RSA_PUB", userId, permissions,
           {KeyPermission::DECRYPT, KeyPermission::ENCRYPT});
    addKey(privKeyId, priBuff.data(), priLen, "RSA_PRIV", userId, permissions,
           {});

    return {pubKeyId, privKeyId};
}
KeyType TempHsm::getKeyTypeById(const std::string &keyId)
{
    // Check if the key exists in the map
    auto it = keyIdUsersPermissions.find(keyId);
    if (it == keyIdUsersPermissions.end()) {
        throw std::runtime_error("Key ID not found: " + keyId);
    }

    // Return the key type for the specified keyId
    return it->second.keyType;
}
std::string TempHsm::getFileNameFromKeyId(const std::string &keyId)
{
    // Check if the key ID exists in the map
    auto it = keyIdUsersPermissions.find(keyId);
    if (it == keyIdUsersPermissions.end()) {
        throw std::runtime_error("Key ID not found: " + keyId);
    }

    // Return the file name associated with the key ID
    return it->second.fileName;
}
std::pair<std::string, std::string> TempHsm::generateECCKeyPair(
    int userId, const std::vector<KeyPermission> &permissions)
{
    std::string pubKeyId =
        getPublicKeyIdByUserId(userId, AsymmetricFunction::ECC);
    std::string privKeyId =
        getPrivateKeyIdByUserId(userId, AsymmetricFunction::ECC);
    if (pubKeyId != "" || privKeyId != "") {
          log(logger::LogLevel::INFO,"User " + std::to_string(userId) + " already has ECC key. Skipping key creation.");

        return std::make_pair(pubKeyId, privKeyId);
    }
    pubKeyId = generateTimestampedKeyID();
    privKeyId = generateTimestampedKeyID();

    // ASK:: does he give other premossions? and premissions to private and
    // public?
    //  Store key pair with permissions
    mpz_class privateKey = generatePrivateKey();
    Point publicKey = generatePublicKey(privateKey);
    size_t pubLen = 2 * sizeof(uint8_t) +
                    (mpz_sizeinbase(publicKey.x.get_mpz_t(), 2) + 7) / 8 +
                    (mpz_sizeinbase(publicKey.y.get_mpz_t(), 2) + 7) / 8;
    size_t priLen = (mpz_sizeinbase(privateKey.get_mpz_t(), 2) + 7) / 8;
    std::vector<uint8_t> pubBuff(pubLen);
    std::vector<uint8_t> priBuff(priLen);
    pointToBuffer(publicKey, pubBuff.data());
    mpz_export(priBuff.data(), &priLen, 1, sizeof(uint8_t), 0, 0,
               privateKey.get_mpz_t());
    addKey(pubKeyId, pubBuff.data(), pubLen, "ECC_PUB", userId, permissions,
           {KeyPermission::DECRYPT, KeyPermission::ENCRYPT});
    addKey(privKeyId, priBuff.data(), priLen, "ECC_PRIV", userId, permissions,
           {});

    return {pubKeyId, privKeyId};
}
void TempHsm::addKey(const std::string &keyId, const uint8_t *keyBuffer,
                     size_t keySize, const std::string &keyType, int ownerId,
                     const std::vector<KeyPermission> &ownerPermissions,
                     const std::vector<KeyPermission> &allUsersPermissions,
                     int destUserId)

{
    //Create and write key file
    std::string fileName = keyId + ".key";
    writeKeyToFile(keyBuffer, keySize, fileName);

    //Load existing JSON data
    std::ifstream inFile(KEYS_CONFIG_FILE);
    nlohmann::json jsonData;
    if (inFile.is_open()) {
        inFile >> jsonData;
        inFile.close();
    }
    else {
        throw std::runtime_error("Unable to open JSON file for update.");
    }

    nlohmann::json ownerPermissionsJson =
        createPermissionsJson(ownerPermissions);
    nlohmann::json allUsersPermissionsJson = {
        {"user_id", (keyType != "AES") ? -1 : destUserId},
        {"permissions", createPermissionsJson(allUsersPermissions)}};
    nlohmann::json newKeyJson = {
        {"key_id", keyId},
        {"file_name", fileName},
        {"key_size", keySize},
        {"key_type", keyType},
        {"owner",
         {{"user_id", ownerId}, {"permissions", ownerPermissionsJson}}},
        {"other_users", nlohmann::json::array({allUsersPermissionsJson})}};

    //Add the new key entry to JSON data
    jsonData["keys"].push_back(newKeyJson);
    {
        // Scoped file stream to ensure it's closed after writing
        std::ofstream outFile(KEYS_CONFIG_FILE);
        if (!outFile) {
            throw std::runtime_error("Failed to open JSON file for writing.");
        }
        outFile << jsonData.dump(4);
        // Stream closes and flushes automatically here
    }

    //Reload the permissions map
    loadPermissionsFromJson();
}
std::string TempHsm::getPublicKeyIdByUserId(int userId,
                                            AsymmetricFunction function)
{
    for (const auto &[keyId, keyInfo] : keyIdUsersPermissions) {
        // Check if the key matches the desired type and owner ID
        if (keyInfo.ownerId == userId) {
            if ((function == AsymmetricFunction::RSA &&
                 keyInfo.keyType == KeyType::RSA_PUB) ||
                (function == AsymmetricFunction::ECC &&
                 keyInfo.keyType == KeyType::ECC_PUB)) {
                return keyId;
            }
        }
    }
    // Return an empty string if no matching key is found
    return "";
}

std::string TempHsm::getPrivateKeyIdByUserId(int userId,
                                             AsymmetricFunction function)
{
    for (const auto &[keyId, keyInfo] : keyIdUsersPermissions) {
        // Check if the key matches the desired type and owner ID
        if (keyInfo.ownerId == userId) {
            if ((function == AsymmetricFunction::RSA &&
                 keyInfo.keyType == KeyType::RSA_PRIV) ||
                (function == AsymmetricFunction::ECC &&
                 keyInfo.keyType == KeyType::ECC_PRIV)) {
                return keyId;
            }
        }
    }
    // Return an empty string if no matching key is found
    return "";
}
std::string TempHsm::getSymmetricKeyIdByUserIdAndKeySize(
    int userId, AESKeyLength aesKeyLength)
{
    for (const auto &[keyId, keyInfo] : keyIdUsersPermissions)
        // Check if the key matches the desired type and owner ID
        if (keyInfo.ownerId == userId && keyInfo.keySize == aesKeyLength &&
            keyInfo.keyType == KeyType::AES)
            return keyId;

    // Return an empty string if no matching key is found
    return "";
}
void TempHsm::getKeyByKeyId(int userId, const std::string &keyId,
                            KeyPermission usage, uint8_t *keyBuffer,
                            size_t keySize)
{
    // Check if the user has the required permission for this key
    checkPermission(keyId, userId, usage);

    // Retrieve the file name for the key ID
    std::string fileName = getFileNameFromKeyId(keyId);

    // Read the key from the file into the buffer
    readKeyFromFile(keyBuffer, keySize, fileName);

    // If the key type is AES and the usage is DECRYPT, delete the file and permissions
    if (getKeyTypeById(keyId) == KeyType::AES &&
        usage == KeyPermission::DECRYPT) {
        // Remove the key file
        fileName = KEYS_DIR + fileName;
        if (std::remove(fileName.c_str()) != 0) {
            throw std::runtime_error("Failed to delete key file: " + fileName);
        }

        // Clear permissions associated with the key
        auto it = keyIdUsersPermissions.find(keyId);
        if (it != keyIdUsersPermissions.end()) {
            keyIdUsersPermissions.erase(it);
        }

        // Update the JSON permissions file by removing the key entry
        removePermissionsJson(keyId);

        // Reload the permissions map to ensure it reflects the updated JSON file
        loadPermissionsFromJson();
    }
}
CryptoConfig TempHsm::getUserConfig(int userId)
{
    // Check if the user exists in the configuration map
    if (usersConfig.find(userId) != usersConfig.end()) {
        return usersConfig[userId];  // Return user config if found
    }
    else {
        log(logger::LogLevel::ERROR, "User ID " + std::to_string(userId) +
                                         " not found in configuration.");
        throw std::runtime_error("User config not found for user ID: " +
                                 std::to_string(userId));
    }
}

void TempHsm::checkPermission(const std::string &keyId, int userId,
                              KeyPermission usage)
{
    // Retrieve KeyInfo for the specified keyId
    auto it = keyIdUsersPermissions.find(keyId);
    if (it == keyIdUsersPermissions.end()) {
        throw std::runtime_error("Key ID not found: " + keyId);
    }

    const KeyInfo &keyInfo = it->second;

    // Check if the usage is permitted for the owner
    if (keyInfo.ownerId == userId) {
        if (keyInfo.ownerPermissions.count(usage) > 0) {
            // Owner has the permission
            return;
        }
    }
    else {
        // Check specific user permissions
        auto userPermIt = keyInfo.otherUsersPermissions.find(userId);
        if (userPermIt != keyInfo.otherUsersPermissions.end()) {
            const std::set<KeyPermission> &userPermissions = userPermIt->second;
            if (userPermissions.count(usage) > 0) {
                // Specific user has the permission
                return;
            }
        }

        // Optionally check for global permissions if needed (not defined in new structure)
        // Assuming -1 is a global user ID for demonstration purposes
        auto globalPermIt = keyInfo.otherUsersPermissions.find(-1);
        if (globalPermIt != keyInfo.otherUsersPermissions.end()) {
            const std::set<KeyPermission> &globalPermissions =
                globalPermIt->second;
            if (globalPermissions.count(usage) > 0) {
                // Global permission granted
                return;
            }
        }
    }

    // If permission check fails, throw an error
    throw std::runtime_error("Permission denied for keyId: " + keyId +
                             " and userId: " + std::to_string(userId));
}
size_t TempHsm::getKeyLengthByKeyId(const std::string &keyId)
{
    auto it = keyIdUsersPermissions.find(keyId);
    if (it != keyIdUsersPermissions.end())
        return it->second.keySize;
    else
        return 0;
}
void TempHsm::loadPermissionsFromJson()
{
    // Ensure the directory exists
    std::filesystem::path dir(KEYS_DIR);
    if (!std::filesystem::exists(dir)) {
        std::filesystem::create_directories(dir);
    }
    std::ifstream file(KEYS_CONFIG_FILE);
    if (!file) {
        // If the file doesn't exist, create it
        std::ofstream createFile(KEYS_CONFIG_FILE);
        if (!createFile) {
            throw std::runtime_error("Unable to create JSON file: " +
                                     KEYS_CONFIG_FILE);
        }
        createFile << "{}";  // Write an empty JSON object to the file
        createFile.close();

        // Re-open the file for reading
        file.open(KEYS_CONFIG_FILE);
        if (!file) {
            throw std::runtime_error(
                "Unable to open JSON file after creation: " + KEYS_CONFIG_FILE);
        }
    }

    nlohmann::json jsonData;
    file >> jsonData;

    // Clear the existing permissions before loading new ones
    keyIdUsersPermissions.clear();

    // Parse and store the permissions in a usable format
    for (const auto &keyData : jsonData["keys"]) {
        KeyInfo keyInfo;
        std::string keyId = keyData.at("key_id").get<std::string>();

        // Extract file name and key type
        keyInfo.fileName = keyData.at("file_name").get<std::string>();
        keyInfo.keySize = keyData.at("key_size").get<size_t>();
        keyInfo.keyType =
            stringKeyTypeToEnum(keyData.at("key_type").get<std::string>());

        // Extract owner information
        keyInfo.ownerId = keyData.at("owner").at("user_id").get<int>();

        // Extract owner permissions using the helper function
        keyInfo.ownerPermissions =
            extractPermissionsFromJson(keyData.at("owner").at("permissions"));

        // Extract other users' permissions
        for (const auto &user : keyData.at("other_users")) {
            int userId = user.at("user_id").get<int>();
            // Extract other user's permissions using the helper function
            keyInfo.otherUsersPermissions[userId] =
                extractPermissionsFromJson(user.at("permissions"));
        }

        // Store key information in the main map
        keyIdUsersPermissions[keyId] = keyInfo;
    }
}
TempHsm::TempHsm()
{
    loadPermissionsFromJson();
}
#pragma endregion
