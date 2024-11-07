// #include "hsm.h" // כלול את הקובץ שבו נמצאת הפונקציה generateKey
// #include <filesystem>
// #include <fstream>
// #include <gtest/gtest.h>
// #include <nlohmann/json.hpp>
// // using json = nlohmann::json;

// // פונקציה מדומה ליצירת מפתח
// std::string mockEncryption(int userId) {
//   return "mockedKeyForUser" + std::to_string(userId);
// }

// // בדיקה לפונקציה generateKey
// TEST(GenerateKeyTest, GeneratesCorrectJsonFile) {
//   int userId = 123;
//   KeyPermission permission = KeyPermission::READ;
//   Hsm h;
//   // קריאה לפונקציה כדי ליצור את קובץ המפתח
//   h.generateKey(userId, permission, mockEncryption);

//   // יצירת שם הקובץ כדי לבדוק אם נוצר כהלכה
//   std::string fileName = "../keys/key_" + std::to_string(userId) + ".json";

//   // בדיקה שהקובץ נוצר
//   ASSERT_TRUE(std::filesystem::exists(fileName)) << "Key file was not created!";

//   // קריאת תוכן הקובץ
//   std::ifstream file(fileName);
//   ASSERT_TRUE(file.is_open()) << "Failed to open the key file!";

//   // קריאת תוכן הקובץ ל-json
//   nlohmann::json jsonData;
//   file >> jsonData;
//   file.close();

//   // בדיקה שהמפתח, ההרשאה וה-userId נכונים
//   EXPECT_EQ(jsonData["userId"], userId);
//   EXPECT_EQ(jsonData["permission"], "Read");
//   EXPECT_EQ(jsonData["key"], "mockedKeyForUser123");
// }

// int main(int argc, char **argv) {
//   ::testing::InitGoogleTest(&argc, argv);
//   return RUN_ALL_TESTS();
// }
// #include "hsm.h" // Include your HSM header file
// #include <filesystem>
// #include <fstream>
// #include <gtest/gtest.h>
// #include <nlohmann/json.hpp>

// using json = nlohmann::json;

// // Utility function to read file content
// std::string readFileContent(const std::string &filePath) {
//   std::ifstream file(filePath);
//   if (!file.is_open()) {
//     throw std::runtime_error("Failed to open file: " + filePath);
//   }
//   std::string content((std::istreambuf_iterator<char>(file)),
//                       std::istreambuf_iterator<char>());
//   return content;
// }

// // Test the key generation function against a data file
// TEST(HsmTests, CompareWithDataFileTest) {
//   Hsm hsm;
//   int userId = 1;
//   std::string keyId = "key_1726490958462";
//   std::vector<KeyPermission> permissions = {KeyPermission::VERIFY,
//                                             KeyPermission::SIGN};

//   // Setup: Generate a key and save it
//   auto keyIds = hsm.generateAESKey(userId, permissions);
//   std::string keyFilePath = "../keys/" + keyIds + ".key";

//   // Path to the data file for comparison
//   std::string dataFilePath = "../keys/key_1726490958462.key";

//   // Read content from the generated key file
//   std::string generatedKeyContent;
//   try {
//     generatedKeyContent = readFileContent(keyFilePath);
//   } catch (const std::exception &ex) {
//     FAIL() << "Exception while reading generated key file: " << ex.what();
//   }

//   // Read content from the expected data file
//   std::string expectedKeyContent;
//   try {
//     expectedKeyContent = readFileContent(dataFilePath);
//   } catch (const std::exception &ex) {
//     FAIL() << "Exception while reading data file: " << ex.what();
//   }

//   // Compare the contents
//   ASSERT_EQ(generatedKeyContent, expectedKeyContent)
//       << "Key content does not match expected data";

//   // Clean up: remove the key file after the test
//   // std::filesystem::remove(keyFilePath);
// }

// int main(int argc, char **argv) {
//   ::testing::InitGoogleTest(&argc, argv);
//   return RUN_ALL_TESTS();
// }
