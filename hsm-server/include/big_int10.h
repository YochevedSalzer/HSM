#ifndef __BIG_INT_10__
#define __BIG_INT_10__
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

class BigInt10 {
    friend std::ostream &operator<<(std::ostream &out, const BigInt10 &a);
    friend BigInt10 modularExponentiation(BigInt10 base, BigInt10 exponent,
                                          const BigInt10 &modulus);
    friend BigInt10 gcd(BigInt10 a, BigInt10 b);
    friend BigInt10 karatzubaMultiply(const BigInt10 &a, const BigInt10 &b);
    friend BigInt10 longMultiplication(const BigInt10 &a, const BigInt10 &b);
    friend BigInt10 longDivision(const BigInt10 &a, const BigInt10 &b,
                                 BigInt10 &remainder);
    friend BigInt10 power(BigInt10 base, BigInt10 exponent);
    friend class BigInt64;

   public:
    // ctors
    BigInt10(const std::string &str);
    BigInt10(const char *str);
    BigInt10(long long val = 0);
    BigInt10(uint64_t uval);
    BigInt10(bool isNegative);
    BigInt10(int val);
    // operators
    // comparison
    bool operator==(const BigInt10 &b) const;
    bool operator!=(const BigInt10 &b) const;
    bool operator<(const BigInt10 &b) const;
    bool operator>(const BigInt10 &b) const;
    bool operator<=(const BigInt10 &b) const;
    bool operator>=(const BigInt10 &b) const;
    // arithematic operations
    BigInt10 &operator++();
    BigInt10 operator++(int);
    BigInt10 &operator--();
    BigInt10 operator--(int);
    // addition
    BigInt10 &operator+=(const BigInt10 &b);
    BigInt10 operator+(const BigInt10 &b) const;
    // subtruction
    BigInt10 &operator-=(const BigInt10 &b);
    BigInt10 operator-(const BigInt10 &b) const;
    // multiplication
    BigInt10 &operator*=(const BigInt10 &b);
    BigInt10 operator*(const BigInt10 &b) const;
    // division
    BigInt10 &operator/=(const BigInt10 &b);
    BigInt10 operator/(const BigInt10 &b) const;
    // modulus
    BigInt10 &operator%=(const BigInt10 &b);
    BigInt10 operator%(const BigInt10 &b) const;
    // power
    BigInt10 &operator^=(const BigInt10 &b);
    BigInt10 operator^(const BigInt10 &b) const;
    std::string toString() const;
    uint64_t toU64() const;
    void removeLeadingZeros();
    bool isZero() const;
    int limbsCount() const;
    void insertZroes(int n);

   private:
    // uint8_t is 1B, like unsigned char
    std::vector<uint8_t> limbs;
    bool isNegative;
    // logic
    bool isSmallerThanUnsigned(const BigInt10 &b) const;
    void prefixPlusPlusUnsigned();
    void prefixMinusMinusUnsigned();
    void addUnsigned(const BigInt10 &b);
    void subtractUnsigned(const BigInt10 &b);
    void initFromString(const char *str, int n);
    void thisEqualsbBSubthis(const BigInt10 &b);
};

#endif  // __BIG_INT_10__