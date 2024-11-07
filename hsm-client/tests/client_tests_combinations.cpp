#include "crypto_api.h"
#include "general.h"
#include <cstddef>
#include <cstdint>
#include <vector>
#include <cstring>
#include <gtest/gtest.h>
#include "debug_utils.h"
#include "hsm_support.h"

// Define a struct to hold all possible parameters for CryptoConfig
struct CryptoTestParams {
    SHAAlgorithm shaAlgorithm;
    AESKeyLength aesKeyLength;
    AESChainingMode aesChainingMode;
    AsymmetricFunction asymmetricFunction;
    int testIndex;  // Added to help with unique IDs for each test case
};

// Parameterized test fixture class
class CryptoClientParameterizedTest
    : public ::testing::TestWithParam<CryptoTestParams> {
   protected:
    CryptoClient client1;
    CryptoClient client2;
    int senderId;
    int receiverId;
    size_t messageLen = 1000;
    CryptoConfig config;

    CryptoClientParameterizedTest() : client1(0), client2(0) {}

    void SetUp() override
    {
        // Get the parameters from GetParam() and configure clients
        CryptoTestParams params = GetParam();

        // Assign unique IDs based on the test index
        senderId = params.testIndex * 2 + 1;    // Odd numbers for sender
        receiverId = params.testIndex * 2 + 2;  // Even numbers for receiver

        client1 = CryptoClient(senderId);
        client2 = CryptoClient(receiverId);

        config =
            CryptoConfig(params.shaAlgorithm, params.aesKeyLength,
                         params.aesChainingMode, params.asymmetricFunction);
        client1.configure(config);
        client2.configure(config);

        client1.bootSystem({{senderId,
                             {KeyPermission::VERIFY, KeyPermission::SIGN,
                              KeyPermission::ENCRYPT, KeyPermission::DECRYPT,
                              KeyPermission::EXPORTABLE}},
                            {receiverId,
                             {KeyPermission::VERIFY, KeyPermission::SIGN,
                              KeyPermission::ENCRYPT, KeyPermission::DECRYPT,
                              KeyPermission::EXPORTABLE}}});
    }
};

// Test that runs for each combination of parameters
TEST_P(CryptoClientParameterizedTest, EncryptDecrypt)
{
    char *message = new char[messageLen];
    std::memset(message, 'A', messageLen);

    hsm::getEncryptedLen(senderId, messageLen);
    size_t encryptedLength = hsm::getEncryptedLen(senderId, messageLen);
    uint8_t encryptedData[encryptedLength];
    bool encryptResult =
        hsm::encryptData(message, messageLen, encryptedData, encryptedLength,
                         senderId, receiverId);
    LOG_BUFFER_HEXA(encryptedData, encryptedLength, "encrypted after encrypt",
                    receiverId);
    ASSERT_EQ(encryptResult, true);
    //---------------
    size_t encryptedLen = client2.getEncryptedLengthByEncrypted(encryptedData);
    ASSERT_EQ(encryptedLength, encryptedLen + 8);
    //--------------
    size_t decryptedLength = client2.getDecryptedLen(senderId, encryptedLen);
    uint8_t decryptedData[decryptedLength];
    CK_RV decryptResult1 =
        client2.decrypt(senderId, encryptedData, encryptedLen,
                        decryptedData, decryptedLength);
    LOG_BUFFER_HEXA(encryptedData, encryptedLength, "encrypted after decrypt",
                    receiverId);
    // bool decryptResult2 = hsm::decryptData(encryptedData, senderId, receiverId);

    ASSERT_EQ(decryptedLength, messageLen);
    // ASSERT_EQ(decryptResult2, true);
    ASSERT_EQ(decryptResult1, CKR_OK);
    ASSERT_FALSE(memcmp(decryptedData, message, messageLen))
        << "Decrypted data does not match original data";
    // ASSERT_FALSE(memcmp(encryptedData, message, messageLen))
    //     << "Decrypted data does not match original data";
    delete[] message;
}

// Generate all combinations of SHAAlgorithm, AESKeyLength, AESChainingMode, and AsymmetricFunction
std::vector<CryptoTestParams> GenerateCryptoTestParams()
{
    std::vector<CryptoTestParams> paramsList;
    int testIndex = 0;  // Index to help assign unique user IDs

    for (const auto &shaAlg :
         {SHAAlgorithm::SHA_256, SHAAlgorithm::SHA_3_512}) {
        for (const auto &aesKeyLen :
             {AESKeyLength::AES_128, AESKeyLength::AES_192,
              AESKeyLength::AES_256}) {
            for (const auto &aesMode :
                 {AESChainingMode::ECB, AESChainingMode::CBC,
                  AESChainingMode::CFB, AESChainingMode::OFB,
                  AESChainingMode::CTR}) {
                for (const auto &asymFunc :
                     {AsymmetricFunction::RSA, AsymmetricFunction::ECC}) {
                    paramsList.push_back(
                        {shaAlg, aesKeyLen, aesMode, asymFunc, testIndex});
                    testIndex;
                }
            }
        }
    }

    return paramsList;
}

// Instantiate the parameterized test suite with all combinations of CryptoConfig parameters
INSTANTIATE_TEST_SUITE_P(CryptoTestCombination, CryptoClientParameterizedTest,
                         ::testing::ValuesIn(GenerateCryptoTestParams()));
