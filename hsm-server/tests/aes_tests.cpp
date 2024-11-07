#include <cstring>
#include "gtest/gtest.h"
#include "aes.h"
#include "debug_utils.h"
#include "aes_stream_factory.h"  // Assuming this is where your FactoryManager is defined

/* Helper function to setup encryption and decryption */
void testEncryptionDecryption(AESChainingMode mode, AESKeyLength keyLength)
{
    // Same data as used in testEncryptionDecryptionAPI
    size_t inputLength1 = 16;
    unsigned char inputData1[inputLength1];
    memset(inputData1, 0x01, inputLength1);
    size_t inputLength2 = 16;
    unsigned char inputData2[inputLength2];
    memset(inputData2, 0x02, inputLength2);
    size_t inputLength3 = 16;
    unsigned char inputData3[inputLength3];
    memset(inputData3, 0x03, inputLength3);

    // Create a factory instance
    StreamAES *streamAES = FactoryManager::getInstance().create(mode);
    ASSERT_NE(streamAES, nullptr);

    // Allocate memory for the key
    std::unique_ptr<unsigned char[]> key(
        new unsigned char[aesKeyLengthData[keyLength].keySize]);
    generateKey(key.get(), keyLength);

    // Calculate encrypted lengths
    unsigned int encryptedLen1 =
        calculatEncryptedLenAES(inputLength1, true, mode);
    unsigned int encryptedLen2 =
        calculatEncryptedLenAES(inputLength2, false, mode);
    unsigned int encryptedLen3 =
        calculatEncryptedLenAES(inputLength3, false, mode);

    // Allocate memory for encrypted data based on the calculated lengths
    std::unique_ptr<unsigned char[]> encrypted(
        new unsigned char[encryptedLen1]);
    std::unique_ptr<unsigned char[]> encrypted2(
        new unsigned char[encryptedLen2]);
    std::unique_ptr<unsigned char[]> encrypted3(
        new unsigned char[encryptedLen3]);

    unsigned int outLenEncrypted = 0;
    unsigned int outLenEncrypted2 = 0;
    unsigned int outLenEncrypted3 = 0;

    // Use the raw pointers from unique_ptr
    unsigned char *encryptedPtr = encrypted.get();
    unsigned char *encrypted2Ptr = encrypted2.get();
    unsigned char *encrypted3Ptr = encrypted3.get();

    // Encrypt the data
    streamAES->encryptStart(inputData1, inputLength1, encryptedPtr,
                            outLenEncrypted, key.get(), keyLength);
    streamAES->encryptContinue(inputData2, inputLength2, encrypted2Ptr,
                               outLenEncrypted2);
    streamAES->encryptContinue(inputData3, inputLength3, encrypted3Ptr,
                               outLenEncrypted3);

    // Print encrypted data
    printBufferHexa(encryptedPtr, outLenEncrypted,
                    "Encrypted data1 aes through streamAES");
    printBufferHexa(encrypted2Ptr, outLenEncrypted2,
                    "Encrypted data2 aes through streamAES");
    printBufferHexa(encrypted3Ptr, outLenEncrypted3,
                    "Encrypted data3 aes through streamAES");

    // Calculate decrypted lengths
    unsigned int decryptedLen1 =
        calculatDecryptedLenAES(outLenEncrypted, true, mode);
    unsigned int decryptedLen2 =
        calculatDecryptedLenAES(outLenEncrypted2, false, mode);
    unsigned int decryptedLen3 =
        calculatDecryptedLenAES(outLenEncrypted3, false, mode);

    // Allocate memory for decrypted data
    std::unique_ptr<unsigned char[]> decrypted(
        new unsigned char[decryptedLen1]);
    std::unique_ptr<unsigned char[]> decrypted2(
        new unsigned char[decryptedLen2]);
    std::unique_ptr<unsigned char[]> decrypted3(
        new unsigned char[decryptedLen3]);

    unsigned int outLenDecrypted = 0;
    unsigned int outLenDecrypted2 = 0;
    unsigned int outLenDecrypted3 = 0;

    // Use the raw pointers from unique_ptr
    unsigned char *decryptedPtr = decrypted.get();
    unsigned char *decrypted2Ptr = decrypted2.get();
    unsigned char *decrypted3Ptr = decrypted3.get();

    // Decrypt the data
    streamAES->decryptStart(encryptedPtr, outLenEncrypted, decryptedPtr,
                            outLenDecrypted, key.get(), keyLength);
    streamAES->decryptContinue(encrypted2Ptr, outLenEncrypted2, decrypted2Ptr,
                               outLenDecrypted2);
    streamAES->decryptContinue(encrypted3Ptr, outLenEncrypted3, decrypted3Ptr,
                               outLenDecrypted3);

    // Print original and decrypted data for comparison
    printBufferHexa(inputData1, inputLength1, "Original Data1: ");
    printBufferHexa(decryptedPtr, outLenDecrypted, "Decrypted Data1: ");
    printBufferHexa(inputData2, inputLength2, "Original Data2: ");
    printBufferHexa(decrypted2Ptr, outLenDecrypted2, "Decrypted Data2: ");
    printBufferHexa(inputData3, inputLength3, "Original Data3: ");
    printBufferHexa(decrypted3Ptr, outLenDecrypted3, "Decrypted Data3: ");

    // Assertions to verify correctness
    ASSERT_EQ(memcmp(inputData1, decryptedPtr, inputLength1), 0);
    ASSERT_EQ(memcmp(inputData2, decrypted2Ptr, inputLength2), 0);
    ASSERT_EQ(memcmp(inputData3, decrypted3Ptr, inputLength3), 0);
}

TEST(KeyLengths, KeyLength128_ECB)
{
    testEncryptionDecryption(AESChainingMode::ECB, AESKeyLength::AES_128);
}

TEST(KeyLengths, KeyLength128_CBC)
{
    testEncryptionDecryption(AESChainingMode::CBC, AESKeyLength::AES_128);
}

TEST(KeyLengths, KeyLength128_CFB)
{
    testEncryptionDecryption(AESChainingMode::CFB, AESKeyLength::AES_128);
}

TEST(KeyLengths, KeyLength128_OFB)
{
    testEncryptionDecryption(AESChainingMode::OFB, AESKeyLength::AES_128);
}

TEST(KeyLengths, KeyLength128_CTR)
{
    testEncryptionDecryption(AESChainingMode::CTR, AESKeyLength::AES_128);
}

TEST(KeyLengths, KeyLength192_ECB)
{
    testEncryptionDecryption(AESChainingMode::ECB, AESKeyLength::AES_192);
}

TEST(KeyLengths, KeyLength192_CBC)
{
    testEncryptionDecryption(AESChainingMode::CBC, AESKeyLength::AES_192);
}

TEST(KeyLengths, KeyLength192_CFB)
{
    testEncryptionDecryption(AESChainingMode::CFB, AESKeyLength::AES_192);
}

TEST(KeyLengths, KeyLength192_OFB)
{
    testEncryptionDecryption(AESChainingMode::OFB, AESKeyLength::AES_192);
}

TEST(KeyLengths, KeyLength192_CTR)
{
    testEncryptionDecryption(AESChainingMode::CTR, AESKeyLength::AES_192);
}

TEST(KeyLengths, KeyLength256_ECB)
{
    testEncryptionDecryption(AESChainingMode::ECB, AESKeyLength::AES_256);
}

TEST(KeyLengths, KeyLength256_CBC)
{
    testEncryptionDecryption(AESChainingMode::CBC, AESKeyLength::AES_256);
}

TEST(KeyLengths, KeyLength256_CFB)
{
    testEncryptionDecryption(AESChainingMode::CFB, AESKeyLength::AES_256);
}

TEST(KeyLengths, KeyLength256_OFB)
{
    testEncryptionDecryption(AESChainingMode::OFB, AESKeyLength::AES_256);
}

TEST(KeyLengths, KeyLength256_CTR)
{
    testEncryptionDecryption(AESChainingMode::CTR, AESKeyLength::AES_256);
}

int main()
{
    ::testing::InitGoogleTest();
    return RUN_ALL_TESTS();
}