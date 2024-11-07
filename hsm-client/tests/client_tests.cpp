#include "crypto_api.h"
#include "debug_utils.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>

class CryptoClientTest : public ::testing::Test {
   protected:
    int senderId = 1;
    int receiverId = 2;
    CryptoClient client1;
    CryptoClient client2;

    size_t messageLen = 2500;
    CryptoConfig config;

    CryptoClientTest()
        : client1(senderId),
          client2(receiverId),
          config(SHAAlgorithm::SHA_256, AESKeyLength::AES_128,
                 AESChainingMode::ECB, AsymmetricFunction::RSA)
    {
    }

    void SetUp() override
    {
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

TEST(CryptoClientSimpleTest, GetEncryptedLengthByEncrypted_ReturnsCorrectLength)
{
    CryptoClient cryptoClient(10);
    size_t expectedLength = 144;  // Example size_t value
    uint8_t
        buffer[sizeof(size_t)];  // Create a buffer to store the size_t value

    // Store the size_t value in the buffer
    std::memcpy(buffer, &expectedLength, sizeof(size_t));
    // Call the function and get the result
    size_t result = cryptoClient.getEncryptedLengthByEncrypted(buffer);

    // Check if the result is as expected
    EXPECT_EQ(result, expectedLength)
        << "The function did not return the correct encrypted length.";
}

TEST_F(CryptoClientTest, EncryptDecrypt)
{
    char *message = new char[messageLen];
    std::memset(message, 'A', messageLen);

    size_t encryptedLength = client1.getEncryptedLen(senderId, messageLen);
    uint8_t encryptedData[encryptedLength];
    CK_RV encryptResult =
        client1.encrypt(receiverId, (void *)message, messageLen, encryptedData,
                        encryptedLength);
    ASSERT_EQ(encryptResult, CKR_OK);
    //----------------------------------------------
    size_t encryptedLen = client2.getEncryptedLengthByEncrypted(encryptedData);
    ASSERT_EQ(encryptedLength, encryptedLen + 8);

    size_t decryptedLength = client2.getDecryptedLen(senderId, encryptedLen);
    uint8_t decryptedData[decryptedLength];
    CK_RV decryptResult = client2.decrypt(senderId, encryptedData, encryptedLen,
                                          decryptedData, decryptedLength);
    ASSERT_EQ(decryptedLength, messageLen);
    ASSERT_EQ(decryptResult, CKR_OK);
    ASSERT_FALSE(memcmp(decryptedData, message, messageLen))
        << "Decrypted data does not match original data";
    delete[] message;
}
TEST_F(CryptoClientTest, EncryptDecryptWithCustomData)
{
    for (int i = 0; i < 5; i++) {
        // Use custom data instead of generated message
        uint8_t customMessage[] = {0x12, 0xED, 0xBC, 0x0B, 0x41,
                                   0x00, 0x00, 0x00, 0x00};
        size_t messageLen = sizeof(customMessage) / sizeof(customMessage[0]);

        // Encrypt the custom message
        size_t encryptedLength = client1.getEncryptedLen(senderId, messageLen);
        uint8_t encryptedData[encryptedLength];
        CK_RV encryptResult =
            client1.encrypt(receiverId, (void *)customMessage, messageLen,
                            encryptedData, encryptedLength);
        ASSERT_EQ(encryptResult, CKR_OK);

        //----------------------------------------------
        // Verify encrypted length and decrypt the data
        size_t encryptedLen =
            client2.getEncryptedLengthByEncrypted(encryptedData);
        ASSERT_EQ(encryptedLength, encryptedLen + 8);

        size_t decryptedLength =
            client2.getDecryptedLen(senderId, encryptedLen);
        uint8_t decryptedData[decryptedLength];
        CK_RV decryptResult =
            client2.decrypt(senderId, encryptedData, encryptedLen,
                            decryptedData, decryptedLength);
        ASSERT_EQ(decryptedLength, messageLen);
        ASSERT_EQ(decryptResult, CKR_OK);

        // Compare the decrypted data with the original custom message
        ASSERT_FALSE(memcmp(decryptedData, customMessage, messageLen))
            << "Decrypted data does not match original data";
    }
}

TEST_F(CryptoClientTest, SignVerify)
{
    char *message = new char[messageLen];
    std::memset(message, 'A', messageLen);
    size_t signedMessageLen = client1.getSignedDataLength(messageLen);
    uint8_t *signedMessage = new uint8_t[signedMessageLen];
    SHAAlgorithm hashFunc = SHA_256;
    auto rsaKeysPair = client2.generateRSAKeyPair(
        {KeyPermission::VERIFY, KeyPermission::SIGN, KeyPermission::ENCRYPT,
         KeyPermission::DECRYPT, KeyPermission::EXPORTABLE});
    std::string publicKey = client1.getPublicRSAKeyByUserId(receiverId);

    CK_RV signResult = client1.sign(message, messageLen, signedMessage,
                                    signedMessageLen, hashFunc, publicKey);
    ASSERT_EQ(signResult, CKR_OK);

    size_t verifiedMessageLen = client2.getVerifiedDataLength(signedMessageLen);
    unsigned char verifiedMessage[verifiedMessageLen];

    CK_RV verifyResult =
        client2.verify(receiverId, signedMessage, signedMessageLen,
                       verifiedMessage, verifiedMessageLen, rsaKeysPair.second);
    ASSERT_EQ(verifyResult, CKR_OK);
    ASSERT_EQ(memcmp(message, verifiedMessage, messageLen), 0);
    delete[] message;
    delete[] signedMessage;
}

TEST_F(CryptoClientTest, RSAEncryptDecrypt)
{
    auto rsaKeyPair = client1.generateRSAKeyPair(
        {KeyPermission::VERIFY, KeyPermission::SIGN, KeyPermission::ENCRYPT,
         KeyPermission::DECRYPT, KeyPermission::EXPORTABLE});
    ASSERT_FALSE(rsaKeyPair.first.empty() || rsaKeyPair.second.empty());

    const char *inputData = "Hello, World!";
    size_t inputDataLen = strlen(inputData);
    size_t encryptedDataLenRSA = client1.getRSAencryptedLength();
    uint8_t *encryptedDataRSA = new uint8_t[encryptedDataLenRSA];

    CK_RV rsaEncryptResult =
        client1.RSAencrypt(rsaKeyPair.second, (void *)inputData, inputDataLen,
                           encryptedDataRSA, encryptedDataLenRSA);
    ASSERT_EQ(rsaEncryptResult, CKR_OK);
    size_t decryptedDataLenRSA = client2.getRSAdecryptedLength();
    uint8_t *decryptedDataRSA = new uint8_t[decryptedDataLenRSA];
    std::string publicKey = client2.getPublicRSAKeyByUserId(senderId);
    CK_RV rsaDecryptResult =
        client2.RSAdecrypt(publicKey, encryptedDataRSA, encryptedDataLenRSA,
                           decryptedDataRSA, decryptedDataLenRSA);
    ASSERT_EQ(rsaDecryptResult, CKR_OK);
    ASSERT_FALSE(memcmp(inputData, decryptedDataRSA, inputDataLen));
    ASSERT_EQ(decryptedDataLenRSA, decryptedDataLenRSA);

    delete[] encryptedDataRSA;
    delete[] decryptedDataRSA;
}

TEST(CryptoClient_Test, ECCEncryptDecrypt)
{
    int sender = 1;
    int receiver = 2;
    CryptoClient client1(sender);
    CryptoClient client2(receiver);
    const char *inputData = "Hello, World!";
    size_t inputDataLen = strlen(inputData);
    auto eccKey = client2.generateECCKeyPair(
        {KeyPermission::VERIFY, KeyPermission::SIGN, KeyPermission::ENCRYPT,
         KeyPermission::DECRYPT, KeyPermission::EXPORTABLE});
    size_t encryptedDataLenECC = client1.getECCencryptedLength();
    uint8_t encryptedDataECC[encryptedDataLenECC];
    std::string publicKeyId = client1.getPublicECCKeyByUserId(receiver);

    CK_RV eccEncryptResult =
        client1.ECCencrypt(publicKeyId, (void *)inputData, inputDataLen,
                           encryptedDataECC, encryptedDataLenECC);
    ASSERT_EQ(eccEncryptResult, CKR_OK);

    size_t decryptedDataLenECC = client2.getECCdecryptedLength();
    uint8_t decryptedDataECC[decryptedDataLenECC];
    CK_RV eccDecryptResult =
        client2.ECCdecrypt(eccKey.second, encryptedDataECC, encryptedDataLenECC,
                           decryptedDataECC, decryptedDataLenECC);
    ASSERT_EQ(decryptedDataLenECC, inputDataLen);

    ASSERT_EQ(eccDecryptResult, CKR_OK);
    ASSERT_FALSE(memcmp(inputData, decryptedDataECC, inputDataLen));
}

TEST_F(CryptoClientTest, AESncryptDecrypt)
{
    AESChainingMode mode = ECB;
    AESKeyLength keyLength = AES_128;
    char *inputData = new char[messageLen];
    std::memset(inputData, 'A', messageLen);
    size_t inputDataLen = messageLen;
    std::vector<KeyPermission> permissions = {
        KeyPermission::DECRYPT, KeyPermission::ENCRYPT, KeyPermission::SIGN,
        KeyPermission::VERIFY, KeyPermission::EXPORTABLE};
    AESChainingMode chainingMode = mode;
    std::string keyId =
        client1.generateAESKey(keyLength, permissions, receiverId);
    size_t encryptedLength =
        client1.getAESencryptedLength(inputDataLen, keyId, mode);
    uint8_t *encryptedData = new uint8_t[encryptedLength];
    // Encrypt the data
    CK_RV result = client1.AESencrypt(
        receiverId, (void *)inputData, inputDataLen, encryptedData,
        encryptedLength, RSA, keyLength, mode, keyId);
    //Check for successful encryption
    EXPECT_EQ(result, CKR_OK);

    // Decrypt the data
    size_t decryptedLength =
        client2.getAESdecryptedLength(encryptedData, encryptedLength);
    uint8_t *decryptedData = new uint8_t[inputDataLen];
    result =
        client2.AESdecrypt(senderId, (uint8_t *)encryptedData, encryptedLength,
                           decryptedData, decryptedLength);
    EXPECT_EQ(result, CKR_OK);
    EXPECT_EQ(memcmp(inputData, decryptedData, inputDataLen), 0);
    ASSERT_EQ(decryptedLength, messageLen);
    delete[] inputData;
    delete[] encryptedData;
    delete[] decryptedData;
}
TEST_F(CryptoClientTest, edge_cases)
{
    // size_t ans=client1.getEncryptedLen(senderId, -1);
}
int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
