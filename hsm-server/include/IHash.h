#ifndef IHASH_H
#define IHASH_H
#include "general.h"
#include <cstdint>
#include <vector>

class IHash {
   public:
    enum SHAAlgorithm { SHA256, SHA3_512 };
    virtual CK_RV update(const std::vector<uint8_t> &data) = 0;
    virtual CK_RV finalize(std::vector<uint8_t> &output) = 0;
    virtual ~IHash() = default;
};

#endif  // IHASH_H