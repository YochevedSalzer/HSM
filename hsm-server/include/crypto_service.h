#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>
#include "encryption.pb.h"
#include "encryption.grpc.pb.h"
#include "general.h"

class CryptoServiceServer final : public crypto::CryptoService::Service {
   public:
    grpc::Status bootSystem(grpc::ServerContext *context,
                            const crypto::BootSystemRequest *request,
                            crypto::Empty *response) override;
    grpc::Status addProccess(grpc::ServerContext *context,
                             const crypto::AddProcessRequest *request,
                             crypto::Empty *response) override;
    grpc::Status configure(grpc::ServerContext *context,
                           const crypto::ConfigureRequest *request,
                           crypto::Empty *response) override;
    grpc::Status encrypt(grpc::ServerContext *context,
                         const crypto::EncryptRequest *request,
                         crypto::EncryptResponse *response) override;
    grpc::Status decrypt(grpc::ServerContext *context,
                         const crypto::DecryptRequest *request,
                         crypto::DecryptResponse *response) override;
    grpc::Status generateAESKey(
        grpc::ServerContext *context,
        const crypto::GenerateAESKeyRequest *request,
        crypto::GenerateAESKeyResponse *response) override;
    grpc::Status generateRSAKeyPair(
        grpc::ServerContext *context,
        const crypto::GenerateKeyPairRequest *request,
        crypto::GenerateKeyPairResponse *response) override;
    grpc::Status generateECCKeyPair(
        grpc::ServerContext *context,
        const crypto::GenerateKeyPairRequest *request,
        crypto::GenerateKeyPairResponse *response) override;
    grpc::Status getSignedDataLength(
        grpc::ServerContext *context,
        const crypto::GetHashLengthRequest *request,
        crypto::GetLengthResponse *response) override;
    grpc::Status getPublicECCKeyByUserId(
        grpc::ServerContext *context, const crypto::KeyRequest *request,
        crypto::KeyResponse *response) override;
    grpc::Status getPublicRSAKeyByUserId(
        grpc::ServerContext *context, const crypto::KeyRequest *request,
        crypto::KeyResponse *response) override;
    // ecc
    grpc::Status getECCencryptedLength(
        grpc::ServerContext *context, const crypto::GetLengthRequest *request,
        crypto::GetLengthResponse *response) override;
    grpc::Status getECCDecryptedLength(
        grpc::ServerContext *context, const crypto::GetLengthRequest *request,
        crypto::GetLengthResponse *response) override;
    grpc::Status ECCencrypt(
        grpc::ServerContext *context,
        const crypto::AsymetricEncryptRequest *request,
        crypto::AsymetricEncryptResponse *response) override;
    grpc::Status ECCdecrypt(
        grpc::ServerContext *context,
        const crypto::AsymetricDecryptRequest *request,
        crypto::AsymetricDecryptResponse *response) override;
    // rsa
    grpc::Status getRSAencryptedLength(
        grpc::ServerContext *context, const crypto::GetLengthRequest *request,
        crypto::GetLengthResponse *response) override;
    grpc::Status getRSAdecryptedLength(
        grpc::ServerContext *context, const crypto::GetLengthRequest *request,
        crypto::GetLengthResponse *response) override;
    grpc::Status RSAencrypt(
        grpc::ServerContext *context,
        const crypto::AsymetricEncryptRequest *request,
        crypto::AsymetricEncryptResponse *response) override;
    grpc::Status RSAdecrypt(
        grpc::ServerContext *context,
        const crypto::AsymetricDecryptRequest *request,
        crypto::AsymetricDecryptResponse *response) override;
    // aes
    grpc::Status getAESencryptedLength(
        grpc::ServerContext *context,
        const crypto::GetAESLengthRequest *request,
        crypto::GetLengthResponse *response) override;
    grpc::Status getAESdecryptedLength(
        grpc::ServerContext *context,
        const crypto::GetAESLengthRequest *request,
        crypto::GetLengthResponse *response) override;
    grpc::Status AESencrypt(grpc::ServerContext *context,
                            const crypto::AESEncryptRequest *request,
                            crypto::AESEncryptResponse *response) override;
    grpc::Status AESdecrypt(grpc::ServerContext *context,
                            const crypto::AESDecryptRequest *request,
                            crypto::AESDecryptResponse *response) override;
    //sign - verify
    grpc::Status getEncryptedLen(grpc::ServerContext *context,
                                 const crypto::GetWholeLength *request,
                                 crypto::GetLengthResponse *response) override;
    grpc::Status getDecryptedLen(grpc::ServerContext *context,
                                 const crypto::GetWholeLength *request,
                                 crypto::GetLengthResponse *response) override;
    grpc::Status signUpdate(grpc::ServerContext *context,
                            const crypto::SignRequest *request,
                            crypto::SignResponse *response) override;
    grpc::Status signFinalize(grpc::ServerContext *context,
                              const crypto::SignRequest *request,
                              crypto::SignResponse *response) override;
    grpc::Status verifyUpdate(grpc::ServerContext *context,
                              const crypto::VerifyRequest *request,
                              crypto::VerifyResponse *response) override;
    grpc::Status verifyFinalize(grpc::ServerContext *context,
                                const crypto::VerifyRequest *request,
                                crypto::VerifyResponse *response) override;

   private:
    static const size_t HSM_ID = 1;
};
