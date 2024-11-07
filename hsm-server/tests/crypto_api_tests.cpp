#include "crypto_api.h"
#include "debug_utils.h"
#include "temp_hsm.h"
#include <gtest/gtest.h>

class CryptoAPIFixture : public ::testing::Test {
   protected:
    int sender = 1;
    int receiver = 2;
    size_t counter = 1;
    std::pair<std::string, std::string> rsaKeyIds;
    std::pair<std::string, std::string> eccKeyIds;
    std::vector<KeyPermission> permissions = {
        KeyPermission::DECRYPT, KeyPermission::ENCRYPT, KeyPermission::SIGN,
        KeyPermission::VERIFY, KeyPermission::EXPORTABLE};
    AESChainingMode chainingMode = AESChainingMode::CBC;  // Change as needed
    AESKeyLength keyLength = AESKeyLength::AES_128;       // Change as needed

    void SetUp() override
    {
        rsaKeyIds = generateRSAKeyPair(receiver, permissions);
        eccKeyIds = generateECCKeyPair(receiver, permissions);
    }

    void TearDown() override {}
};

#define RSA_TEST
#define ECC_TEST
#define SIGN_VERIFY_TEST

#ifdef RSA_TEST
TEST_F(CryptoAPIFixture, rsa)
{
    // Generate RSA key pair for sender

    uint8_t data[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    size_t dataLen = 6;
    printBufferHexa(data, dataLen, "rsa plain data");

    size_t encryptedLen = getRSAencryptedLength();
    uint8_t *encrypted = new uint8_t[encryptedLen];

    // RSA encryption: sender -> receiver
    CK_RV rv2 = RSAencrypt(sender, rsaKeyIds.first, data, dataLen, encrypted,
                           encryptedLen);
    EXPECT_EQ(CKR_OK, rv2);

    size_t decryptedLen = getRSAdecryptedLength();
    uint8_t *decrypted = new uint8_t[decryptedLen];

    // RSA decryption: receiver
    CK_RV rv3 = RSAdecrypt(receiver, rsaKeyIds.second, encrypted, encryptedLen,
                           decrypted, &decryptedLen);
    EXPECT_EQ(CKR_OK, rv3);

    printBufferHexa(decrypted, decryptedLen, "rsa decrypted");

    EXPECT_EQ(0, memcmp(data, decrypted, dataLen));

    delete[] encrypted;
    delete[] decrypted;
}
#endif  // RSA_TEST
#ifdef ECC_TEST
TEST_F(CryptoAPIFixture, ecc)
{
    const char *inputData = "Hello, World!";
    size_t dataLen = strlen(inputData);

    printBufferHexa(reinterpret_cast<const uint8_t *>(inputData), dataLen,
                    "ecc plain data");

    size_t encryptedLen = getECCencryptedLength();
    uint8_t *encrypted = new uint8_t[encryptedLen];

    // ECC encryption: sender -> receiver
    CK_RV rv2 = ECCencrypt(sender, eccKeyIds.first, (void *)inputData, dataLen,
                           encrypted, encryptedLen);
    EXPECT_EQ(CKR_OK, rv2);

    size_t decryptedLen = getECCdecryptedLength();
    uint8_t *decrypted = new uint8_t[decryptedLen];

    // ECC decryption: receiver
    CK_RV rv3 = ECCdecrypt(receiver, eccKeyIds.second, encrypted, encryptedLen,
                           decrypted, decryptedLen);
    EXPECT_EQ(CKR_OK, rv3);

    printBufferHexa(decrypted, decryptedLen, "ecc decrypted");

    EXPECT_EQ(0, memcmp(inputData, decrypted, dataLen));
    EXPECT_EQ(decryptedLen, dataLen);

    delete[] encrypted;
    delete[] decrypted;
}
#endif  // ECC_TEST
#ifdef SIGN_VERIFY_TEST
TEST_F(CryptoAPIFixture, SignVerifySingleChunkTest)
{
    CK_RV rv;
    // Define the data size to be within a single chunk (e.g., 32KB)
    size_t singleChunkDataLen =
        32 * 1024;  // 32KB, smaller than the 64KB chunk size
    std::vector<uint8_t> singleChunkData(singleChunkDataLen,
                                         0xAB);  // Fill the data with 0xAB

    // Define chunk size (same as the data size, ensuring only one chunk)
    size_t chunkSize =
        singleChunkDataLen;  // For single chunk, chunk size is equal to data size
    size_t numChunks = 1;    // Only one chunk in this case

    // Buffer for signature
    size_t signatureLen = getSignatureLength();
    uint8_t
        signature[signatureLen];  // Assuming RSA-2048 for a 256-byte signature

    // Sign the single chunk
    std::cout << "Signing a single chunk..." << std::endl;
    size_t offset = 0;  // No offset needed for a single chunk
    rv = signUpdate(receiver, &singleChunkData[offset], singleChunkDataLen,
                    SHA_256, 0);  // Only one call to signUpdate
    EXPECT_EQ(CKR_OK, rv) << "signUpdate failed for the single chunk";

    // Finalize signing
    rv = signFinalize(receiver, signature, signatureLen, SHA_256,
                      rsaKeyIds.second);
    EXPECT_EQ(CKR_OK, rv) << "signFinalize failed";

    // Verify the single chunk
    std::cout << "Verifying a single chunk..." << std::endl;
    rv = verifyUpdate(sender, &singleChunkData[offset], singleChunkDataLen,
                      SHA_256, 0);  // Only one call to verifyUpdate
    EXPECT_EQ(CKR_OK, rv) << "verifyUpdate failed for the single chunk";

    // Finalize verifying
    rv = verifyFinalize(sender, signature, signatureLen, SHA_256,
                        rsaKeyIds.first);
    EXPECT_EQ(CKR_OK, rv) << "verifyFinalize failed";

    // If all assertions pass, signing and verification of the single chunk were successful
    std::cout << "Sign and Verify for a single chunk Passed" << std::endl;
}

// Test for sign and verify functions
TEST_F(CryptoAPIFixture, SignVerifyChunkedTest)
{
    CK_RV rv;
    // Simulate large data (e.g., 1MB)
    size_t largeDataLen = 1024 * 1024;  // 1MB
    std::vector<uint8_t> largeData(
        largeDataLen, 0xAB);  // Fill the data with 0xAB for simulation

    // Define chunk size (e.g., 64KB)
    size_t chunkSize = 64 * 1024;
    size_t numChunks = (largeDataLen + chunkSize - 1) /
                       chunkSize;  // Calculate the number of chunks

    // Buffer for signature
    size_t signatureLen = getSignatureLength();
    uint8_t
        signature[signatureLen];  // Assuming RSA-2048 for a 256-byte signature

    // Sign in chunks
    std::cout << "Signing in chunks..." << std::endl;
    for (size_t i = 0; i < numChunks; ++i) {
        size_t offset = i * chunkSize;
        size_t currentChunkSize = std::min(
            chunkSize, largeDataLen - offset);  // Handle last chunk size
        rv = signUpdate(receiver, &largeData[offset], currentChunkSize, SHA_256,
                        i);
        EXPECT_EQ(CKR_OK, rv) << "signUpdate failed for chunk " << i;
    }

    // Finalize signing, sender
    rv = signFinalize(receiver, signature, signatureLen, SHA_256,
                      rsaKeyIds.second);
    EXPECT_EQ(CKR_OK, rv) << "signFinalize failed";

    // Now, let's verify in chunks
    std::cout << "Verifying in chunks..." << std::endl;
    for (size_t i = 0; i < numChunks; ++i) {
        size_t offset = i * chunkSize;
        size_t currentChunkSize = std::min(chunkSize, largeDataLen - offset);
        rv = verifyUpdate(sender, &largeData[offset], currentChunkSize,
                          SHA_256, i);
        EXPECT_EQ(CKR_OK, rv) << "verifyUpdate failed for chunk " << i;
    }

    // Finalize verifying
    rv = verifyFinalize(sender, signature, signatureLen, SHA_256,
                        rsaKeyIds.first);
    EXPECT_EQ(CKR_OK, rv) << "verifyFinalize failed";

    // If all assertions pass, signing and verification of large data in chunks
    // were successful
    std::cout << "Sign and Verify for large data in chunks Passed" << std::endl;
}
#endif  // SIGN_VERIFY_TEST
void testEncryptionDecryptionAPI(AESChainingMode mode, AESKeyLength keyLength)
{
    int sender = 1;
    int receiver = 2;
    size_t counter = 1;
    std::vector<KeyPermission> permissions = {
        KeyPermission::DECRYPT, KeyPermission::ENCRYPT, KeyPermission::SIGN,
        KeyPermission::VERIFY, KeyPermission::EXPORTABLE};
    AESChainingMode chainingMode = mode;  // Change as needed
    std::string keyId =
        generateAESKey(sender, keyLength, permissions, receiver);
    size_t inputLength1 = 64;
    unsigned char inputData1[inputLength1];
    memset(inputData1, 0x02, inputLength1);
    size_t inputLength2 = 32;
    unsigned char inputData2[inputLength2];
    memset(inputData2, 0x02, inputLength2);
    size_t inputLength3 = 32;
    unsigned char inputData3[inputLength3];
    memset(inputData3, 0x02, inputLength3);

    size_t encryptedLength1 = getAESencryptedLength(inputLength1, true, mode);
    uint8_t encryptedData1[encryptedLength1];
    size_t encryptedLength2 = getAESencryptedLength(inputLength2, false, mode);
    uint8_t encryptedData2[encryptedLength2];
    size_t encryptedLength3 = getAESencryptedLength(inputLength3, false, mode);
    uint8_t encryptedData3[encryptedLength3];
    counter = 3;

    // Encrypt the data
    CK_RV result1 = AESencrypt(sender, receiver, (void *)inputData1,
                               inputLength1, encryptedData1, encryptedLength1,
                               keyLength, chainingMode, counter, keyId);

    // Check for successful encryption
    EXPECT_EQ(result1, CKR_OK);
    // Encrypt the data
    CK_RV result2 = AESencrypt(sender, receiver, (void *)inputData2,
                               inputLength2, encryptedData2, encryptedLength2,
                               keyLength, chainingMode, counter, keyId);

    // Check for successful encryption
    EXPECT_EQ(result2, CKR_OK);  // Encrypt the data
    CK_RV result3 = AESencrypt(sender, receiver, (void *)inputData3,
                               inputLength3, encryptedData3, encryptedLength3,
                               keyLength, chainingMode, counter, keyId);

    // Check for successful encryption
    EXPECT_EQ(result3, CKR_OK);

    // Decrypt the data
    size_t decryptedLength1 =
        getAESdecryptedLength(encryptedLength1, true, mode);
    size_t decryptedLength2 =
        getAESdecryptedLength(encryptedLength2, false, mode);
    size_t decryptedLength3 =
        getAESdecryptedLength(encryptedLength3, false, mode);

    uint8_t decryptedData1[decryptedLength1];
    uint8_t decryptedData2[decryptedLength2];
    uint8_t decryptedData3[decryptedLength3];

    result1 = AESdecrypt(sender, receiver, encryptedData1, encryptedLength1,
                         decryptedData1, decryptedLength1, keyLength,
                         chainingMode, counter, keyId);
    EXPECT_EQ(result1, CKR_OK);
    printBufferHexa(inputData1, inputLength1, "Original Data1: ");
    printBufferHexa(decryptedData1, decryptedLength1, "Decrypted Data1: ");
    result2 = AESdecrypt(sender, receiver, encryptedData2, encryptedLength2,
                         decryptedData2, decryptedLength2, keyLength,
                         chainingMode, counter, keyId);
    EXPECT_EQ(result2, CKR_OK);

    printBufferHexa(inputData2, inputLength2, "Original Data2: ");
    printBufferHexa(decryptedData2, decryptedLength2, "Decrypted Data2: ");
    result3 = AESdecrypt(sender, receiver, encryptedData3, encryptedLength3,
                         decryptedData3, decryptedLength3, keyLength,
                         chainingMode, counter, keyId);
    printBufferHexa(inputData3, inputLength3, "Original Data3: ");
    printBufferHexa(decryptedData3, decryptedLength3, "Decrypted Data3: ");

    // Check for successful decryption
    EXPECT_EQ(result3, CKR_OK);

    // Verify the decrypted data matches the original input
    EXPECT_EQ(memcmp(inputData1, decryptedData1, decryptedLength1), 0);
    EXPECT_EQ(memcmp(inputData2, decryptedData2, decryptedLength2), 0);
    EXPECT_EQ(memcmp(inputData3, decryptedData3, decryptedLength3), 0);
    EXPECT_EQ(inputLength1, decryptedLength1);
    EXPECT_EQ(inputLength2, decryptedLength2);
    EXPECT_EQ(inputLength3, decryptedLength3);
};

// #define AES_TESTS

#ifdef AES_TESTS
TEST(KeyLengthsAPI, KeyLength128_ECB)
{
    testEncryptionDecryptionAPI(AESChainingMode::ECB, AESKeyLength::AES_128);
}

TEST(KeyLengthsAPI, KeyLength128_CBC)
{
    testEncryptionDecryptionAPI(AESChainingMode::CBC, AESKeyLength::AES_128);
}

TEST(KeyLengthsAPI, KeyLength128_CFB)
{
    testEncryptionDecryptionAPI(AESChainingMode::CFB, AESKeyLength::AES_128);
}

TEST(KeyLengthsAPI, KeyLength128_OFB)
{
    testEncryptionDecryptionAPI(AESChainingMode::OFB, AESKeyLength::AES_128);
}

TEST(KeyLengthsAPI, KeyLength128_CTR)
{
    testEncryptionDecryptionAPI(AESChainingMode::CTR, AESKeyLength::AES_128);
}

TEST(KeyLengthsAPI, KeyLength192_ECB)
{
    testEncryptionDecryptionAPI(AESChainingMode::ECB, AESKeyLength::AES_192);
}

TEST(KeyLengthsAPI, KeyLength192_CBC)
{
    testEncryptionDecryptionAPI(AESChainingMode::CBC, AESKeyLength::AES_192);
}

TEST(KeyLengthsAPI, KeyLength192_CFB)
{
    testEncryptionDecryptionAPI(AESChainingMode::CFB, AESKeyLength::AES_192);
}

TEST(KeyLengthsAPI, KeyLength192_OFB)
{
    testEncryptionDecryptionAPI(AESChainingMode::OFB, AESKeyLength::AES_192);
}

TEST(KeyLengthsAPI, KeyLength192_CTR)
{
    testEncryptionDecryptionAPI(AESChainingMode::CTR, AESKeyLength::AES_192);
}

TEST(KeyLengthsAPI, KeyLength256_ECB)
{
    testEncryptionDecryptionAPI(AESChainingMode::ECB, AESKeyLength::AES_256);
}

TEST(KeyLengthsAPI, KeyLength256_CBC)
{
    testEncryptionDecryptionAPI(AESChainingMode::CBC, AESKeyLength::AES_256);
}

TEST(KeyLengthsAPI, KeyLength256_CFB)
{
    testEncryptionDecryptionAPI(AESChainingMode::CFB, AESKeyLength::AES_256);
}

TEST(KeyLengthsAPI, KeyLength256_OFB)
{
    testEncryptionDecryptionAPI(AESChainingMode::OFB, AESKeyLength::AES_256);
}

TEST(KeyLengthsAPI, KeyLength256_CTR)
{
    testEncryptionDecryptionAPI(AESChainingMode::CTR, AESKeyLength::AES_256);
}
#endif
void GenericEncryptionDecryptionTest(CryptoConfig config)
{
    try {
        int sender = 1;
        int receiver = 2;

        std::vector<KeyPermission> permissions = {
            KeyPermission::DECRYPT, KeyPermission::ENCRYPT, KeyPermission::SIGN,
            KeyPermission::VERIFY, KeyPermission::EXPORTABLE};

        configure(sender, config);    //give encrypt-decrypt behavior
        configure(receiver, config);  //give encrypt-decrypt behavior
        bootSystem({{sender, permissions},
                    {receiver, permissions}});  //generate keys with permissions

        size_t inputLength1 = 32;
        unsigned char inputData1[inputLength1];
        memset(inputData1, 0x01, inputLength1);
        size_t inputLength2 = 32;
        unsigned char inputData2[inputLength2];
        memset(inputData2, 0x02, inputLength2);
        size_t inputLength3 = 24;
        unsigned char inputData3[inputLength3];
        memset(inputData3, 0x03, inputLength3);

        size_t encryptedLength1 = getEncryptedLen(sender, inputLength1, true);
        uint8_t encryptedData1[encryptedLength1];
        size_t encryptedLength2 = getEncryptedLen(sender, inputLength2, false);
        uint8_t encryptedData2[encryptedLength2];
        size_t encryptedLength3 = getEncryptedLen(sender, inputLength3, false);
        uint8_t encryptedData3[encryptedLength3];
        size_t counter = 3;

        size_t signatureLen = getSignatureLength();
        uint8_t *signature = new uint8_t[signatureLen];
        // Encrypt the data
        CK_RV result1 = encrypt(sender, receiver, (void *)inputData1,
                                inputLength1, encryptedData1, encryptedLength1,
                                signature, signatureLen, counter);
        // printBufferHexa(encryptedData1, encryptedLength1,
        //                 "Encrypted data1 aes through api");
        // Check for successful encryption
        EXPECT_EQ(result1, CKR_OK);
        // Encrypt the data
        CK_RV result2 = encrypt(sender, receiver, (void *)inputData2,
                                inputLength2, encryptedData2, encryptedLength2,
                                signature, signatureLen, counter);
        // printBufferHexa(encryptedData2, encryptedLength2,
        //                 "Encrypted data2 aes through api");
        // Check for successful encryption
        EXPECT_EQ(result2, CKR_OK);  // Encrypt the data
        CK_RV result3 = encrypt(sender, receiver, (void *)inputData3,
                                inputLength3, encryptedData3, encryptedLength3,
                                signature, signatureLen, counter);
        // Check for successful encryption
        EXPECT_EQ(result3, CKR_OK);

        // printBufferHexa(encryptedData3, encryptedLength3,
        //                 "Encrypted data3 aes through api");
        // Decrypt the data
        size_t decryptedLength1 =
            getDecryptedLen(sender, encryptedLength1, true);
        size_t decryptedLength2 =
            getDecryptedLen(sender, encryptedLength2, false);
        size_t decryptedLength3 =
            getDecryptedLen(sender, encryptedLength3, false);

        uint8_t decryptedData1[decryptedLength1];
        uint8_t decryptedData2[decryptedLength2];
        uint8_t decryptedData3[decryptedLength3];

        result1 = decrypt(sender, receiver, encryptedData1, encryptedLength1,
                          signature, signatureLen, decryptedData1,
                          decryptedLength1, counter);
        EXPECT_EQ(result1, CKR_OK);
        // printBufferHexa(inputData1, inputLength1, "Original Data1: ");
        // printBufferHexa(decryptedData1, decryptedLength1, "Decrypted Data1: ");
        result2 = decrypt(sender, receiver, encryptedData2, encryptedLength2,
                          signature, signatureLen, decryptedData2,
                          decryptedLength2, counter);
        EXPECT_EQ(result2, CKR_OK);
        // printBufferHexa(inputData2, inputLength2, "Original Data2: ");
        // printBufferHexa(decryptedData2, decryptedLength2, "Decrypted Data2: ");
        result3 = result1 = decrypt(sender, receiver, encryptedData3,
                                    encryptedLength3, signature, signatureLen,
                                    decryptedData3, decryptedLength3, counter);

        // printBufferHexa(inputData3, inputLength3, "Original Data3: ");
        // printBufferHexa(decryptedData3, decryptedLength3, "Decrypted Data3: ");

        // Check for successful decryption
        EXPECT_EQ(result3, CKR_OK);

        // Verify the decrypted data matches the original input
        EXPECT_EQ(memcmp(inputData1, decryptedData1, decryptedLength1), 0);
        EXPECT_EQ(memcmp(inputData2, decryptedData2, decryptedLength2), 0);
        EXPECT_EQ(memcmp(inputData3, decryptedData3, decryptedLength3), 0);
        EXPECT_EQ(inputLength1, decryptedLength1);
        EXPECT_EQ(inputLength2, decryptedLength2);
        EXPECT_EQ(inputLength3, decryptedLength3);
    }
    catch (std::exception &e) {
        std::cerr << "Error::::::::::: " << e.what() << std::endl;
    }
}

// Control macros to enable or disable RSA and ECC tests
// #define RUN_RSA_TESTS  // Set to 1 to run RSA tests, 0 to skip
// #define RUN_ECC_TESTS  // Set to 1 to run ECC tests, 0 to skip

//AES_128 combinations
#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength128_ECB_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_128,
                        AESChainingMode::ECB, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength128_ECB_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_128,
                        AESChainingMode::ECB, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength128_CBC_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_128,
                        AESChainingMode::CBC, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength128_CBC_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_128,
                        AESChainingMode::CBC, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength128_CFB_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_128,
                        AESChainingMode::CFB, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength128_CFB_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_128,
                        AESChainingMode::CFB, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength128_OFB_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_128,
                        AESChainingMode::OFB, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength128_OFB_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_128,
                        AESChainingMode::OFB, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength128_CTR_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_128,
                        AESChainingMode::CTR, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength128_CTR_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_128,
                        AESChainingMode::CTR, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

// AES_192 combinations
#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength192_ECB_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_192,
                        AESChainingMode::ECB, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength192_ECB_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_192,
                        AESChainingMode::ECB, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength192_CBC_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_192,
                        AESChainingMode::CBC, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength192_CBC_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_192,
                        AESChainingMode::CBC, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength192_CFB_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_192,
                        AESChainingMode::CFB, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength192_CFB_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_192,
                        AESChainingMode::CFB, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength192_OFB_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_192,
                        AESChainingMode::OFB, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength192_OFB_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_192,
                        AESChainingMode::OFB, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength192_CTR_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_192,
                        AESChainingMode::CTR, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength192_CTR_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_192,
                        AESChainingMode::CTR, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

// AES_256 combinations
#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength256_ECB_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_256,
                        AESChainingMode::ECB, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength256_ECB_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_256,
                        AESChainingMode::ECB, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength256_CBC_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_256,
                        AESChainingMode::CBC, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength256_CBC_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_256,
                        AESChainingMode::CBC, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength256_CFB_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_256,
                        AESChainingMode::CFB, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength256_CFB_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_256,
                        AESChainingMode::CFB, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength256_OFB_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_256,
                        AESChainingMode::OFB, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength256_OFB_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_256,
                        AESChainingMode::OFB, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength256_CTR_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_256,
                        AESChainingMode::CTR, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA256_KeyLength256_CTR_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_256, AESKeyLength::AES_256,
                        AESChainingMode::CTR, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

// SHA_3_512 combinations for AES_128
#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength128_ECB_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_128,
                        AESChainingMode::ECB, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength128_ECB_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_128,
                        AESChainingMode::ECB, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength128_CBC_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_128,
                        AESChainingMode::CBC, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength128_CBC_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_128,
                        AESChainingMode::CBC, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength128_CFB_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_128,
                        AESChainingMode::CFB, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength128_CFB_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_128,
                        AESChainingMode::CFB, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength128_OFB_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_128,
                        AESChainingMode::OFB, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength128_OFB_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_128,
                        AESChainingMode::OFB, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength128_CTR_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_128,
                        AESChainingMode::CTR, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength128_CTR_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_128,
                        AESChainingMode::CTR, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

// SHA_3_512 combinations for AES_192
#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength192_ECB_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_192,
                        AESChainingMode::ECB, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength192_ECB_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_192,
                        AESChainingMode::ECB, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength192_CBC_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_192,
                        AESChainingMode::CBC, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength192_CBC_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_192,
                        AESChainingMode::CBC, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength192_CFB_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_192,
                        AESChainingMode::CFB, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength192_CFB_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_192,
                        AESChainingMode::CFB, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength192_OFB_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_192,
                        AESChainingMode::OFB, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength192_OFB_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_192,
                        AESChainingMode::OFB, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength192_CTR_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_192,
                        AESChainingMode::CTR, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength192_CTR_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_192,
                        AESChainingMode::CTR, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

// SHA_3_512 combinations for AES_256
#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength256_ECB_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_256,
                        AESChainingMode::ECB, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength256_ECB_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_256,
                        AESChainingMode::ECB, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength256_CBC_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_256,
                        AESChainingMode::CBC, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength256_CBC_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_256,
                        AESChainingMode::CBC, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength256_CFB_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_256,
                        AESChainingMode::CFB, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength256_CFB_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_256,
                        AESChainingMode::CFB, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength256_OFB_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_256,
                        AESChainingMode::OFB, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength256_OFB_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_256,
                        AESChainingMode::OFB, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_RSA_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength256_CTR_RSA)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_256,
                        AESChainingMode::CTR, AsymmetricFunction::RSA);
    GenericEncryptionDecryptionTest(config);
}
#endif

#ifdef RUN_ECC_TESTS
TEST(EncryptDecryptAPI, SHA3_512_KeyLength256_CTR_ECC)
{
    CryptoConfig config(SHAAlgorithm::SHA_3_512, AESKeyLength::AES_256,
                        AESChainingMode::CTR, AsymmetricFunction::ECC);
    GenericEncryptionDecryptionTest(config);
}
#endif
