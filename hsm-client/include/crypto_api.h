#ifndef CRYPTO_CLIENT_H
#define CRYPTO_CLIENT_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>
#include <memory>
#include <grpcpp/grpcpp.h>
#include "encryption.grpc.pb.h"
#include "general.h"
#include "encryption.pb.h"

class CryptoClient {
   public:
    //ctor
    CryptoClient(std::shared_ptr<grpc::Channel> channel)
        : stub_(crypto::CryptoService::NewStub(channel))
    {
    }
    CryptoClient(int userId)
        : stub_(crypto::CryptoService::NewStub(grpc::CreateChannel(
              ("0.0.0.0:50051"), grpc::InsecureChannelCredentials()))),
          userId(userId)
    {
    }
    //config
    CK_RV configure(CryptoConfig config);
    CK_RV bootSystem(const std::map<uint32_t, std::vector<KeyPermission>>
                         &usersIdspermissions);
    CK_RV addProccess(int userId,
                      const std::vector<KeyPermission> &permissions);
    //generate key
    std::string generateAESKey(AESKeyLength aesKeyLength,
                               std::vector<KeyPermission> permissions,
                               int destUserId);
    std::pair<std::string, std::string> generateRSAKeyPair(
        std::vector<KeyPermission> permissions);
    std::pair<std::string, std::string> generateECCKeyPair(
        std::vector<KeyPermission> permissions);
    // sign-verify
    size_t getSignatureLength();
    size_t getSignedDataLength(size_t inLen);
    size_t getVerifiedDataLength(size_t inLen);
    CK_RV sign(void *in, size_t inLen, uint8_t *out, size_t &outLen,
               SHAAlgorithm hashFunc, std::string keyId);
    CK_RV verify(int recieverId, void *in, size_t inLen, void *out,
                 size_t &outLen, std::string keyId);
    // get public key id
    std::string getPublicECCKeyByUserId(int receiverId);
    std::string getPublicRSAKeyByUserId(int receiverId);
    // ecc
    size_t getECCencryptedLength();
    size_t getECCdecryptedLength();
    CK_RV ECCencrypt(std::string keyId, void *in, size_t inLen, void *out,
                     size_t &outLen);
    CK_RV ECCdecrypt(std::string keyId, void *in, size_t inLen, void *out,
                     size_t &outLen);
    // rsa
    size_t getRSAencryptedLength();
    size_t getRSAdecryptedLength();
    CK_RV RSAencrypt(std::string keyId, void *in, size_t inLen, void *out,
                     size_t outLen);
    CK_RV RSAdecrypt(std::string keyId, void *in, size_t inLen, void *out,
                     size_t &outLen);

    // aes
    size_t getAESencryptedLength(size_t dataLen, bool isFirst,
                                 AESChainingMode chainingMode);
    size_t getAESdecryptedLength(size_t dataLen, bool isFirst,
                                 AESChainingMode chainingMode);
    size_t getAESdecryptedLength(void *in, size_t dataLend);
    size_t getAESencryptedLength(size_t dataLen, const std::string &keyId,
                                 AESChainingMode chainingMode);
    CK_RV AESencrypt(int recieverId, void *in, size_t inLen, void *out,
                     size_t &outLen, AsymmetricFunction func,
                     AESKeyLength keyLength, AESChainingMode chainingMode,
                     std::string keyId);
    CK_RV AESdecrypt(int receiverId, void *in, size_t inLen, void *out,
                     size_t &outLen);

    // encrypt-decrypt
    size_t getEncryptedLen(int senderId, size_t inLen, bool isfirst);
    size_t getDecryptedLen(int senderId, size_t encryptedLength, bool isfirst);
    size_t getDecryptedLen(int senderId, size_t encryptedLengt);
    size_t getEncryptedLen(int senderId, size_t encryptedLength);

    CK_RV encrypt(int receiverId, const void *in, size_t inLen, void *out,
                  size_t &outLen);
    CK_RV decrypt(int receiverId, const void *in, size_t inLen, void *out,
                  size_t &outLen);
    size_t getEncryptedLengthByEncrypted(void *data);

   private:
    int userId;
    std::unique_ptr<crypto::CryptoService::Stub> stub_;
    static const size_t MAX_BLOCK = 1024;
    static const size_t HSM_ID = 1;
    static const size_t IV_SIZE = 16;
};

#endif  // CRYPTO_CLIENT_H
