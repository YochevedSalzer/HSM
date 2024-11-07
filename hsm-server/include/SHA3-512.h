#ifndef SHA3_512_H
#define SHA3_512_H

#include "IHash.h"
#include "general.h"
#include <cstdint>  // For fixed-width integer types
#include <sstream>  // For std::ostringstream
#include <string>
#include <vector>

class SHA3_512 : public IHash {
   public:
    SHA3_512();  // Constructor to initialize the state
    CK_RV update(const std::vector<uint8_t> &data)
        override;  // Update the hash with more data
    CK_RV finalize(std::vector<uint8_t> &output)
        override;  // Finalize and get the hash value

   private:
    uint64_t S[5][5];           // State matrix
    uint8_t buffer[576];        // Buffer to hold input data
    std::size_t buffer_length;  // Current length of data in the buffer

    void round(uint64_t A[5][5], uint64_t RC);
    void f_function(uint64_t A[5][5]);
    void padding(uint8_t input[], std::size_t &in_len, int &absorb_times);
    void assign_S_xor_p(uint64_t S[5][5], uint64_t *p);
    void endianSwap(uint64_t &x);
    std::vector<uint8_t> hashPartToHexVector(uint64_t S[5][5]);
};

#endif  // SHA3_512_H