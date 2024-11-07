// #include <gtest/gtest.h>
// #include <vector>
// #include "sha256.h"

// std::string bytesToHexString(const std::vector<uint8_t>& bytes) {
//     std::stringstream ss;
//     ss << std::hex << std::setfill('0');
//     for (const auto& byte : bytes) {
//         ss << std::setw(2) << static_cast<int>(byte);
//     }
//     return ss.str();
// }

// // Test for hash of an empty string
// TEST(SHA256Test, EmptyStringHash) {
//     std::vector<uint8_t> data = {};
//     std::vector<uint8_t> hash = sha256_compute(data);

//     // Expected hash value for an empty string
//     std::string expectedHash =
//     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
//     ASSERT_EQ(bytesToHexString(hash), expectedHash);
// }

// // Test for hash of the string "abc"
// TEST(SHA256Test, ABCStringHash) {
//     std::vector<uint8_t> data = {'a', 'b', 'c'};
//     std::vector<uint8_t> hash = sha256_compute(data);

//     // Expected hash value for the string "abc"
//     std::string expectedHash =
//     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
//     ASSERT_EQ(bytesToHexString(hash), expectedHash);
// }

// // Test for hash of a string longer than 64 bytes
// TEST(SHA256Test, StringLongerThan64BytesHash) {
//     std::string longString = "The quick brown fox jumps over the lazy dog";
//     std::vector<uint8_t> data(longString.begin(), longString.end());
//     std::vector<uint8_t> hash = sha256_compute(data);

//     // Expected hash value for the string "The quick brown fox jumps over the
//     lazy dog" std::string expectedHash =
//     "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
//     ASSERT_EQ(bytesToHexString(hash), expectedHash);
// }

// // Test for hash of a string containing special characters
// TEST(SHA256Test, SpecialCharsHash) {
//     std::string specialString = "!@#$%^&*()";
//     std::vector<uint8_t> data(specialString.begin(), specialString.end());
//     std::vector<uint8_t> hash = sha256_compute(data);

//     // Expected hash value for the string containing special characters
//     std::string expectedHash =
//     "95ce789c5c9d18490972709838ca3a9719094bca3ac16332cfec0652b0236141";
//     ASSERT_EQ(bytesToHexString(hash), expectedHash);
// }

// int main(int argc, char **argv) {
//     ::testing::InitGoogleTest(&argc, argv);
//     return RUN_ALL_TESTS();
// }