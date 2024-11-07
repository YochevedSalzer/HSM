#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include "../include/IHash.h"
#include "../include/hash_factory.h"

// Helper function to convert vector to a hex string for comparison
std::string to_hex_string(const std::vector<uint8_t> &data)
{
    std::ostringstream oss;
    for (auto byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(byte);
    }
    return oss.str();
}

// Test fixture class for SHA256
class HashTest : public ::testing::Test {
   protected:
    void SetUp() override
    {
        // Get the FactoryManager instance
        factoryManager = &HashFactory::getInstance();
        CK_RV result;
        // Create SHA256 object using FactoryManager
        result = factoryManager->create(SHA_256, sha256);
        if (!sha256 || result != CKR_OK) {
            FAIL() << "Failed to create SHA256 instance";
        }

        result = factoryManager->create(SHA_3_512, sha512);
        if (!sha512 || result != CKR_OK) {
            FAIL() << "Failed to create SHA512 instance";
        }
    }
    // Utility to hash a string and return the hex string of the result
    std::string hashStringSHA256(const std::string &input)
    {
        std::vector<uint8_t> output;
        std::vector<uint8_t> data(input.begin(), input.end());
        sha256->update(data);
        sha256->finalize(output);
        return to_hex_string(output);
    }

    void hashStringSHA512(const std::vector<std::vector<uint8_t>> &chunks,
                          const std::string &expectedHash)
    {
        std::vector<uint8_t> output;
        for (const auto &chunk : chunks) {
            sha512->update(chunk);
        }
        sha512->finalize(output);
        std::string res = std::string(output.begin(), output.end());

        ASSERT_EQ(res, expectedHash);
    }
    HashFactory *factoryManager;
    std::unique_ptr<IHash> sha256;
    std::unique_ptr<IHash> sha512;
};

// Test hashing an empty string
TEST_F(HashTest, HashEmptyString)
{
    std::string expectedHash =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    std::string hash = hashStringSHA256("");
    EXPECT_EQ(hash, expectedHash);
}

// Test hashing "abc"
TEST_F(HashTest, HashABC)
{
    std::string expectedHash =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    std::string hash = hashStringSHA256("abc");
    EXPECT_EQ(hash, expectedHash);
}

// Test hashing "hello world"
TEST_F(HashTest, HashHelloWorld)
{
    std::string expectedHash =
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    std::string hash = hashStringSHA256("hello world");
    EXPECT_EQ(hash, expectedHash);
}

// Test hashing a string with special characters
TEST_F(HashTest, HashSpecialCharacters)
{
    std::string specialChars = "!@#$%^&*()_+-={}[]|:;<>,.?/~`";
    std::string expectedHash =
        "64192e06fd03a054a8f7a478adfed5b15effe6f3ecc24df06df143cc1d45b7"
        "ab";  // Replace with the actual expected hash value
    std::string hash = hashStringSHA256(specialChars);
    EXPECT_EQ(hash, expectedHash);
}

// Test for hash of an empty string
TEST_F(HashTest, EmptyStringHash)
{
    std::vector<std::vector<uint8_t>> data = {{}};
    std::string expectedHash =
        "a69f73cca23a9ac5c8b567dc185a756e97c98216"
        "4fe25859e0d1dcc1475c80a615b2123af1f5f94"
        "c11e3e9402c3ac558f500199d95b6d3e3017585"
        "86281dcd26";
    hashStringSHA512(data, expectedHash);
}

// Test for hash of the string "abc"
TEST_F(HashTest, ABCStringHash)
{
    std::vector<std::vector<uint8_t>> data = {{'a', 'b', 'c'}};
    std::string expectedHash =
        "b751850b1a57168a5693cd924b6b096e08f621827"
        "444f70d884f5d0240d2712e10e116e9192af3c91"
        "a7ec57647e3934057340b4cf408d5a56592f8274"
        "eec53f0";
    hashStringSHA512(data, expectedHash);
}

// Test for hash of a string longer than 64 bytes
TEST_F(HashTest, StringLongerThan64BytesHash)
{
    std::string longString = "The quick brown fox jumps over the lazy dog";
    std::vector<std::vector<uint8_t>> data = {
        std::vector<uint8_t>(longString.begin(), longString.end())};
    std::string expectedHash =
        "01dedd5de4ef14642445ba5f5b97c15e47b9ad931"
        "326e4b0727cd94cefc44fff23f07bf543139939b"
        "49128caf436dc1bdee54fcb24023a08d9403f9b4"
        "bf0d450";
    hashStringSHA512(data, expectedHash);
}

// Test for hash of a string containing special characters
TEST_F(HashTest, SpecialCharsHash)
{
    std::string specialString = "!@#$%^&*()";
    std::vector<std::vector<uint8_t>> data = {
        std::vector<uint8_t>(specialString.begin(), specialString.end())};
    std::string expectedHash =
        "fbbcb3e21184dd4061de0b85c4756f74e36a36112"
        "5733e2c7470232fc66f71c902d1e6ff7eb60cfe6"
        "b47e8b72e1429b4ff21de0fa150a2b3e8d8e29e2"
        "64d56ab";
    hashStringSHA512(data, expectedHash);
}

// Test for multiple updates
TEST_F(HashTest, MultipleUpdatesHash)
{
    std::vector<std::vector<uint8_t>> data = {
        {'a', 'b'},  // First update with two bytes
        {'c', 'd'}   // Second update with two more bytes
    };
    std::string expectedHash =
        "6eb7b86765bf96a8467b72401231539cbb830f6c641"
        "20954c4567272f613f1364d6a80084234fa3400d30"
        "6b9f5e10c341bbdc5894d9b484a8c7deea9cbe4e265";
    hashStringSHA512(data, expectedHash);
}