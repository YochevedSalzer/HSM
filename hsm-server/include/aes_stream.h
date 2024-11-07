#ifndef __AES_STREAM__
#define __AES_STREAM__
#include "aes.h"
#include <cstdlib>

class StreamAES {
   public:
    unsigned char *iv = nullptr;
    unsigned char *lastBlock = nullptr;
    AESKeyLength keyLength;
    unsigned char *key = nullptr;
    unsigned char *lastData = nullptr;

    StreamAES()
        : iv(new unsigned char[16]),
          lastBlock(new unsigned char[16]),
          lastData(new unsigned char[16]){};
    virtual ~StreamAES()
    {
        if (iv != nullptr) {
            delete[] iv;
            iv = nullptr;
        }
        if (lastBlock != nullptr) {
            delete[] lastBlock;
            lastBlock = nullptr;
        }
        if (key != nullptr) {
            delete[] key;
            key = nullptr;
        }
        if (lastData != nullptr) {
            delete[] lastData;
            lastData = nullptr;
        }
    }

    /** 
     @brief Encrypts the initial block of data using AES in CBC mode.
     This function generates a random initialization vector (IV) and then 
     encrypts the given block of data. The encrypted data and the IV are 
     concatenated and stored in the output buffer.
     @param block Input data block to encrypt.
     @param inLen Length of the input data block.
     @param[out] out Pointer to the output buffer where encrypted data will be stored.
     @param[out] outLen Length of the encrypted output data.
     @param key Encryption key.
     @param keyLength Length of the AES key (128, 192, or 256 bits).
    */
    virtual void encryptStart(unsigned char block[], unsigned int inLen,
                              unsigned char *out, unsigned int outLen,
                              unsigned char *key, AESKeyLength keyLength) = 0;

    /**
     @brief Continues encryption of data using AES in CBC mode.
     This function continues the encryption process for the given block of data 
     using the last encrypted block as the IV.
     @param block Input data block to encrypt.
     @param inLen Length of the input data block.
     @param[out] out Pointer to the output buffer where encrypted data will be stored.
     @param[out] outLen Length of the encrypted output data.
    */
    virtual void encryptContinue(unsigned char block[], unsigned int inLen,
                                 unsigned char *out, unsigned int outlen) = 0;

    /**
     @brief Decrypts the initial block of data using AES in CBC mode.
     This function extracts the initialization vector (IV) from the end of the 
     input data block and then decrypts the given block of data. The decrypted 
     data is stored in the output buffer.
     @param block Encrypted input data block to decrypt.
     @param inLen Length of the encrypted input data block.
     @param[out] out Pointer to the output buffer where decrypted data will be stored.
     @param outLen Length of the decrypted output data.
     @param key Decryption key.
     @param keyLength Length of the AES key (128, 192, or 256 bits).
    */
    virtual void decryptStart(unsigned char block[], unsigned int inLen,
                              unsigned char *out, unsigned int &outLen,
                              unsigned char *key, AESKeyLength keyLength) = 0;

    /**
     @brief Continues decryption of data using AES in CBC mode.
     This function continues the decryption process for the given block of data 
     using the last decrypted block as the IV.
     @param block Encrypted input data block to decrypt.
     @param inLen Length of the encrypted input data block.
     @param[out] out Pointer to the output buffer where decrypted data will be stored.
     @param outLen Length of the decrypted output data.
    */
    virtual void decryptContinue(unsigned char block[], unsigned int inLen,
                                 unsigned char *out, unsigned int &outLen) = 0;

    /**
     Decrypts data using AES in CBC mode. 
     @param in Encrypted input data.
     @param inLen Length of input data.
     @param key Decryption key.
     @param[out] out Decrypted output data.
     @param[out] outLen Length of decrypted data.
     @param iv Initialization vector.
     @param keyLength AES key length (128, 192, 256 bits).
    */
    virtual void decrypt(unsigned char in[], unsigned int inLen,
                         unsigned char *key, unsigned char *out,
                         unsigned int &outLen, const unsigned char *iv,
                         unsigned char *lastData, AESKeyLength keyLength) = 0;

    /**
     Encrypts data using AES.
     @param in Input data.
     @param inLen Length of input data.
     @param key Encryption key.
     @param[out] out Encrypted output data.
     @param[out] outLen Length of encrypted data.
     @param iv Initialization vector.
     @param keyLength AES key length (128, 192, 256 bits).
    */
    virtual void encrypt(unsigned char in[], unsigned int inLen,
                         unsigned char *key, unsigned char *out,
                         unsigned int outLen, const unsigned char *iv,
                         unsigned char *lastData, AESKeyLength keyLength) = 0;
};

class AESEcb : public StreamAES {
    void encryptStart(unsigned char block[], unsigned int inLen,
                      unsigned char *out, unsigned int outLen,
                      unsigned char *key, AESKeyLength keyLength);
    void encryptContinue(unsigned char block[], unsigned int inLen,
                         unsigned char *out, unsigned int outlen);
    void decryptStart(unsigned char block[], unsigned int inLen,
                      unsigned char *out, unsigned int &outLen,
                      unsigned char *key, AESKeyLength keyLength);
    void decryptContinue(unsigned char block[], unsigned int inLen,
                         unsigned char *out, unsigned int &outlen);
    void decrypt(unsigned char in[], unsigned int inLen, unsigned char *key,
                 unsigned char *out, unsigned int &outLen,
                 const unsigned char *iv, unsigned char *lastData,
                 AESKeyLength keyLength);
    void encrypt(unsigned char in[], unsigned int inLen, unsigned char *key,
                 unsigned char *out, unsigned int outLen,
                 const unsigned char *iv, unsigned char *lastData,
                 AESKeyLength keyLength);
};

class AESCbc : public StreamAES {
    void encryptStart(unsigned char block[], unsigned int inLen,
                      unsigned char *out, unsigned int outLen,
                      unsigned char *key, AESKeyLength keyLength);
    void encryptContinue(unsigned char block[], unsigned int inLen,
                         unsigned char *out, unsigned int outlen);
    void decryptStart(unsigned char block[], unsigned int inLen,
                      unsigned char *out, unsigned int &outLen,
                      unsigned char *key, AESKeyLength keyLength);
    void decryptContinue(unsigned char block[], unsigned int inLen,
                         unsigned char *out, unsigned int &outLen);
    void decrypt(unsigned char in[], unsigned int inLen, unsigned char *key,
                 unsigned char *out, unsigned int &outLen,
                 const unsigned char *iv, unsigned char *lastData,
                 AESKeyLength keyLength);
    void encrypt(unsigned char in[], unsigned int inLen, unsigned char *key,
                 unsigned char *out, unsigned int outLen,
                 const unsigned char *iv, unsigned char *lastData,
                 AESKeyLength keyLength);
};

class AESCfb : public StreamAES {
    void encryptStart(unsigned char block[], unsigned int inLen,
                      unsigned char *out, unsigned int outLen,
                      unsigned char *key, AESKeyLength keyLength);
    void encryptContinue(unsigned char block[], unsigned int inLen,
                         unsigned char *out, unsigned int outlen);
    void decryptStart(unsigned char block[], unsigned int inLen,
                      unsigned char *out, unsigned int &outLen,
                      unsigned char *key, AESKeyLength keyLength);
    void decryptContinue(unsigned char block[], unsigned int inLen,
                         unsigned char *out, unsigned int &outlen);
    void decrypt(unsigned char in[], unsigned int inLen, unsigned char *key,
                 unsigned char *out, unsigned int &outLen,
                 const unsigned char *iv, unsigned char *lastData,
                 AESKeyLength keyLength);
    void encrypt(unsigned char in[], unsigned int inLen, unsigned char *key,
                 unsigned char *out, unsigned int outLen,
                 const unsigned char *iv, unsigned char *lastData,
                 AESKeyLength keyLength);
};

class AESOfb : public StreamAES {
    void encryptStart(unsigned char block[], unsigned int inLen,
                      unsigned char *out, unsigned int outLen,
                      unsigned char *key, AESKeyLength keyLength);
    void encryptContinue(unsigned char block[], unsigned int inLen,
                         unsigned char *out, unsigned int outlen);
    void decryptStart(unsigned char block[], unsigned int inLen,
                      unsigned char *out, unsigned int &outLen,
                      unsigned char *key, AESKeyLength keyLength);
    void decryptContinue(unsigned char block[], unsigned int inLen,
                         unsigned char *out, unsigned int &outlen);
    void decrypt(unsigned char in[], unsigned int inLen, unsigned char *key,
                 unsigned char *out, unsigned int &outLen,
                 const unsigned char *iv, unsigned char *lastData,
                 AESKeyLength keyLength);
    void encrypt(unsigned char in[], unsigned int inLen, unsigned char *key,
                 unsigned char *out, unsigned int outLen,
                 const unsigned char *iv, unsigned char *lastData,
                 AESKeyLength keyLength);
};
class AESCtr : public StreamAES {
    void encryptStart(unsigned char block[], unsigned int inLen,
                      unsigned char *out, unsigned int outLen,
                      unsigned char *key, AESKeyLength keyLength);
    void encryptContinue(unsigned char block[], unsigned int inLen,
                         unsigned char *out, unsigned int outlen);
    void decryptStart(unsigned char block[], unsigned int inLen,
                      unsigned char *out, unsigned int &outlen,
                      unsigned char *key, AESKeyLength keyLength);
    void decryptContinue(unsigned char block[], unsigned int inLen,
                         unsigned char *out, unsigned int &outlen);
    void decrypt(unsigned char in[], unsigned int inLen, unsigned char *key,
                 unsigned char *out, unsigned int &outLen,
                 const unsigned char *iv, unsigned char *lastData,
                 AESKeyLength keyLength);
    void encrypt(unsigned char in[], unsigned int inLen, unsigned char *key,
                 unsigned char *out, unsigned int outLen,
                 const unsigned char *iv, unsigned char *lastData,
                 AESKeyLength keyLength);
};

#endif  // __AES_STREAM__