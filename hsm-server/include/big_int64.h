#ifndef __BIG_INT_64__
#define __BIG_INT_64__
#include <cstdint>
#include <iostream>
#include <string>
#include "big_int10.h"
#include "big_int_utils.h"

constexpr int BYTES_IN_LIMB = 8;
constexpr int BITS_IN_BYTE = 8;
constexpr int BITS_IN_LIMB = 64;

#ifdef USE_SYCL
#include <sycl/sycl.hpp>
#include <oneapi/dpl/random>

class BigInt64 {
    friend std::ostream &operator<<(std::ostream &out, const BigInt64 &a);
    friend BigInt64 power(BigInt64 base, BigInt64 exponent);
    friend BigInt64 modularExponentiation(BigInt64 base, BigInt64 exponent,
                                          const BigInt64 &modulus)
    {
        BigInt64 res(1);
        base %= modulus;
        while (!exponent.isZero()) {
            if (!exponent.isEven())
                res = (res * base) % modulus;
            base = (base * base) % modulus;
            exponent >>= 1;
        }

        return res;
    }

    SYCL_EXTERNAL friend BigInt64 gcd(BigInt64 a, BigInt64 b);
    friend BigInt64 extendedGcd(BigInt64 a, BigInt64 b, BigInt64 &x,
                                BigInt64 &y);
    friend BigInt64 modularInverse(BigInt64 a, BigInt64 b);

   public:
    enum CreateModes { RANDOM, BIG_ENDIANESS, LITTLE_ENDIANESS };
    // ctors
    BigInt64(const std::string &str);
    SYCL_EXTERNAL BigInt64(uint64_t min, const BigInt64 &max,
                           oneapi::dpl::uniform_real_distribution<float> &distr,
                           oneapi::dpl::minstd_rand &engine)
    {
        isNegative = false;
        for (int i = 0; i < max.limbsCount(); i++) {
            float r1 = distr(engine);
            float r2 = distr(engine);
            limbs[i] = floatsToUint64(r1, r2);
        }

        std::uint64_t maxMsb = max.getMsb();
        if (maxMsb == 1)
            size = max.limbsCount() - 1;
        else {
            std::uint64_t msbMask = (1ULL << (::bitsCount(maxMsb) - 1)) - 1;
            limbs[max.limbsCount() - 1] &= msbMask;
            size = max.limbsCount();
        }

        removeLeadingZeros();
        if (limbs[0] < min && size == 1) {
            limbs[0] = min;
            size = 1;
        }
    }

    SYCL_EXTERNAL BigInt64(long long val = 0) : size(0)
    {
        isNegative = false;
        if (val == 0) {
            limbs[size++] = 0;
            return;
        }

        if (val < 0) {
            isNegative = true;
            val *= -1;
        }

        limbs[size++] = val;
    }

    BigInt64(uint64_t uval);
    SYCL_EXTERNAL BigInt64(int val) : BigInt64(static_cast<long long>(val)) {}
    SYCL_EXTERNAL BigInt64(bool isNegative);
    BigInt64(const char *str);
    BigInt64(const uint8_t *str, size_t strLen, CreateModes mode);
    BigInt64(CreateModes mode, int bits);
    BigInt64(CreateModes mode, uint64_t min, const BigInt64 &max);
    // copy ctor
    SYCL_EXTERNAL BigInt64(const BigInt64 &other)
    {
        isNegative = other.isNegative;
        size = other.size;
        copyLimbsFrom(other.limbs, 0, size, 0, size);
    }

    // assignment operator
    SYCL_EXTERNAL BigInt64 &operator=(const BigInt64 &other)
    {
        if (this == &other)
            return *this;

        isNegative = other.isNegative;
        size = other.size;
        copyLimbsFrom(other.limbs, 0, size, 0, size);
        return *this;
    }

    // operators
    // comparison
    SYCL_EXTERNAL bool operator==(const BigInt64 &b) const;
    SYCL_EXTERNAL bool operator!=(const BigInt64 &b) const;
    SYCL_EXTERNAL bool operator<(const BigInt64 &b) const;
    SYCL_EXTERNAL bool operator>(const BigInt64 &b) const;
    SYCL_EXTERNAL bool operator<=(const BigInt64 &b) const;
    SYCL_EXTERNAL bool operator>=(const BigInt64 &b) const;
    // arithematic operations
    SYCL_EXTERNAL BigInt64 &operator++();
    SYCL_EXTERNAL BigInt64 operator++(int);
    SYCL_EXTERNAL BigInt64 &operator--();
    SYCL_EXTERNAL BigInt64 operator--(int);
    // addition
    SYCL_EXTERNAL BigInt64 &operator+=(const BigInt64 &b);
    SYCL_EXTERNAL BigInt64 operator+(const BigInt64 &b) const;
    // subtruction
    SYCL_EXTERNAL BigInt64 &operator-=(const BigInt64 &b);
    SYCL_EXTERNAL BigInt64 operator-(const BigInt64 &b) const;
    // multiplication
    SYCL_EXTERNAL BigInt64 &operator*=(const BigInt64 &b);
    SYCL_EXTERNAL BigInt64 operator*(const BigInt64 &b) const;
    // division
    SYCL_EXTERNAL BigInt64 &operator/=(const BigInt64 &b);
    SYCL_EXTERNAL BigInt64 operator/(const BigInt64 &b) const;
    // modulus
    SYCL_EXTERNAL BigInt64 &operator%=(const BigInt64 &b);
    SYCL_EXTERNAL BigInt64 operator%(const BigInt64 &b) const;
    // power
    BigInt64 &operator^=(const BigInt64 &b);
    BigInt64 operator^(const BigInt64 &b) const;
    // right shift - division
    SYCL_EXTERNAL BigInt64 &operator>>=(uint64_t n);
    SYCL_EXTERNAL BigInt64 operator>>(uint64_t n) const;
    // left shift - multiplication
    BigInt64 &operator<<=(uint64_t n);
    BigInt64 operator<<(uint64_t n) const;
    // basic utils
    SYCL_EXTERNAL bool isZero() const;
    SYCL_EXTERNAL int limbsCount() const;
    SYCL_EXTERNAL std::uint64_t getMsb() const;
    SYCL_EXTERNAL std::uint64_t getLsb() const;
    int bitsCount() const;
    SYCL_EXTERNAL bool isEven() const;
    void exportTo(uint8_t *out, size_t outLen, CreateModes mode) const;
    size_t bytesCount() const;
    void longMultiplication(const BigInt64 &b);
    std::string toString() const;

   private:
    // uint64_t is 8B, like unsigned long long
    uint64_t limbs[150];
    size_t size;
    bool isNegative;
    // logic
    bool isSmallerThanUnsigned(const BigInt64 &b) const;
    void prefixPlusPlusUnsigned();
    void prefixMinusMinusUnsigned();
    void addUnsigned(const BigInt64 &b);
    void subtractUnsigned(const BigInt64 &b);
    void longDivision(const BigInt64 &b, BigInt64 &remainder,
                      BigInt64 &quotient) const;
    BigInt10 toDecimal() const;
    void initFromString(const char *str, int n);
    void rightShift(uint64_t n);
    void leftShift(uint64_t n);
    // helpers
    void thisEqualsbBSubthis(const BigInt64 &b);
    SYCL_EXTERNAL void removeLeadingZeros();
    void insert(int n, uint64_t limb);
    void erase(int n);
    void generateNLimbsRandom(int limbsCnt);
    uint64_t randomLimb(uint64_t min, uint64_t max);
    void zero();
    bool hasLeadingZero();
    SYCL_EXTERNAL void copyLimbsFrom(const uint64_t *other, size_t otherStart,
                                     size_t count, size_t meStart,
                                     size_t newSize);
    void setLimbs(uint64_t val, size_t count, size_t meStart, size_t newSize);
    void reverse();
};
#else
#include <vector>

class BigInt64 {
    friend std::ostream &operator<<(std::ostream &out, const BigInt64 &a);
    friend BigInt64 modularExponentiation(BigInt64 base, BigInt64 exponent,
                                          const BigInt64 &modulus);
    friend BigInt64 gcd(BigInt64 a, BigInt64 b);
    friend BigInt64 karatzubaMultiplication(const BigInt64 &a,
                                            const BigInt64 &b);
    friend BigInt64 extendedGcd(BigInt64 a, BigInt64 b, BigInt64 &x,
                                BigInt64 &y);
    friend BigInt64 modularInverse(BigInt64 a, BigInt64 b);
    friend BigInt64 longMultiplication(const BigInt64 &a, const BigInt64 &b);
    friend BigInt64 longDivision(const BigInt64 &a, const BigInt64 &b,
                                 BigInt64 &remainder);
    friend BigInt64 power(BigInt64 base, BigInt64 exponent);

   public:
    enum CreateModes { RANDOM, BIG_ENDIANESS, LITTLE_ENDIANESS };
    // ctors
    BigInt64(const std::string &str);
    BigInt64(long long val = 0);
    BigInt64(uint64_t uval);
    BigInt64(int val);
    BigInt64(bool isNegative);
    BigInt64(const char *str);
    BigInt64(const uint8_t *str, size_t strLen, CreateModes mode);
    BigInt64(std::vector<uint64_t> v, bool isNegative);
    BigInt64(CreateModes mode, int bits);
    BigInt64(CreateModes mode, uint64_t min, const BigInt64 &max);
    // operators
    // comparison
    bool operator==(const BigInt64 &b) const;
    bool operator!=(const BigInt64 &b) const;
    bool operator<(const BigInt64 &b) const;
    bool operator>(const BigInt64 &b) const;
    bool operator<=(const BigInt64 &b) const;
    bool operator>=(const BigInt64 &b) const;
    // arithematic operations
    BigInt64 &operator++();
    BigInt64 operator++(int);
    BigInt64 &operator--();
    BigInt64 operator--(int);
    // addition
    BigInt64 &operator+=(const BigInt64 &b);
    BigInt64 operator+(const BigInt64 &b) const;
    // subtruction
    BigInt64 &operator-=(const BigInt64 &b);
    BigInt64 operator-(const BigInt64 &b) const;
    // multiplication
    BigInt64 &operator*=(const BigInt64 &b);
    BigInt64 operator*(const BigInt64 &b) const;
    // division
    BigInt64 &operator/=(const BigInt64 &b);
    BigInt64 operator/(const BigInt64 &b) const;
    // modulus
    BigInt64 &operator%=(const BigInt64 &b);
    BigInt64 operator%(const BigInt64 &b) const;
    // power
    BigInt64 &operator^=(const BigInt64 &b);
    BigInt64 operator^(const BigInt64 &b) const;
    // right shift - division
    BigInt64 &operator>>=(uint64_t n);
    BigInt64 operator>>(uint64_t n) const;
    // left shift - multiplication
    BigInt64 &operator<<=(uint64_t n);
    BigInt64 operator<<(uint64_t n) const;
    // basic utils
    bool isZero() const;
    int limbsCount() const;
    int bitsCount() const;
    bool isEven() const;
    void exportTo(uint8_t *out, size_t outLen, CreateModes mode) const;
    size_t bytesCount() const;
    std::string toString() const;

   private:
    // uint64_t is 8B, like unsigned long long
    std::vector<uint64_t> limbs;
    bool isNegative;
    // logic
    bool isSmallerThanUnsigned(const BigInt64 &b) const;
    void prefixPlusPlusUnsigned();
    void prefixMinusMinusUnsigned();
    void addUnsigned(const BigInt64 &b);
    void subtractUnsigned(const BigInt64 &b);
    BigInt10 toDecimal() const;
    void initFromString(const char *str, int n);
    void rightShift(uint64_t n);
    void leftShift(uint64_t n);
    // helpers
    void thisEqualsbBSubthis(const BigInt64 &b);
    void removeLeadingZeros();
    void insertZroes(int n);
    void generateNLimbsRandom(int limbsCnt);
    uint64_t randomLimb(uint64_t min, uint64_t max);
    void zero();
};

#endif
#endif  // __BIG_INT_64__