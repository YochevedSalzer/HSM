#include <cstring>
#include <algorithm>
#include <random>
#include <sstream>
#include <vector>
#include "../include/big_int64.h"

using namespace std;

#ifdef USE_SYCL
BigInt64::BigInt64(const string &str)
{
    initFromString(str.c_str(), str.size());
}

BigInt64::BigInt64(const char *str)
{
    initFromString(str, std::strlen(str));
}

BigInt64::BigInt64(const uint8_t *str, size_t strLen, CreateModes mode)
    : isNegative(false)
{
    if (strLen == 0) {
        size = 1;
        limbs[0] = 0;
        return;
    }
    int fullLimbs = strLen / BYTES_IN_LIMB;
    int msbParts = strLen % BYTES_IN_LIMB;
    int limbsCnt = fullLimbs + (msbParts + BYTES_IN_LIMB - 1) / BYTES_IN_LIMB;
    size = limbsCnt;
    if (mode == CreateModes::LITTLE_ENDIANESS) {
        for (int i = 0; i < fullLimbs; i++) {
            int index = strLen - 1 - i * BYTES_IN_LIMB;
            // little endian-> {0,1,2,3,4,5,6,7} becones 0x 07 06 05 04 03 02 01 00
            limbs[i] = ((static_cast<uint64_t>(str[index]) << 56) |
                        (static_cast<uint64_t>(str[index - 1]) << 48) |
                        (static_cast<uint64_t>(str[index - 2]) << 40) |
                        (static_cast<uint64_t>(str[index - 3]) << 32) |
                        (static_cast<uint64_t>(str[index - 4]) << 24) |
                        (static_cast<uint64_t>(str[index - 5]) << 16) |
                        (static_cast<uint64_t>(str[index - 6]) << 8) |
                        static_cast<uint64_t>(str[index - 7]));
        }
        if (msbParts != 0) {
            uint64_t msb = 0;
            for (int i = 0; i < msbParts; i++) {
                msb |= static_cast<uint64_t>(str[i]) << (i * BITS_IN_BYTE);
            }
            limbs[size++] = msb;
        }
    }
    else {
        // big endian-> {0,1,2,3,4,5,6,7} becones 0x 00 01 02 03 04 05 06 07
        for (int i = 0; i < fullLimbs; i++) {
            int index = strLen - 1 - i * BYTES_IN_LIMB;
            limbs[i] = (static_cast<uint64_t>(str[index]) |
                        (static_cast<uint64_t>(str[index - 1]) << 8) |
                        (static_cast<uint64_t>(str[index - 2]) << 16) |
                        (static_cast<uint64_t>(str[index - 3]) << 24) |
                        (static_cast<uint64_t>(str[index - 4]) << 32) |
                        (static_cast<uint64_t>(str[index - 5]) << 40) |
                        (static_cast<uint64_t>(str[index - 6]) << 48) |
                        (static_cast<uint64_t>(str[index - 7]) << 56));
        }
        if (msbParts != 0) {
            uint64_t msb = 0;
            for (int i = 0; i < msbParts; i++) {
                msb |= static_cast<uint64_t>(str[msbParts - 1 - i])
                       << (i * BITS_IN_BYTE);
            }
            limbs[size++] = msb;
        }
    }
    removeLeadingZeros();
}

BigInt64::BigInt64(CreateModes mode, int bits) : isNegative(false)
{
    if (bits >= BITS_IN_LIMB)
        generateNLimbsRandom(bits / BITS_IN_LIMB);
    bits = bits % BITS_IN_LIMB;  // 0-63
    if (bits != 0) {
        uint64_t one = static_cast<uint64_t>(1);
        limbs[size++] = randomLimb(0, (one << bits) - 1) | (one << (bits - 1));
    }
    else
        limbs[size - 1] |= 0x8000000000000000ULL;
}

BigInt64::BigInt64(CreateModes mode, uint64_t min, const BigInt64 &max)
    : size(0), isNegative(false)
{
    if (max.isSmallerThanUnsigned(min))
        throw invalid_argument("min must be <= max");

    if (max.limbsCount() == 1) {
        uint64_t number = randomLimb(min, max.limbs[max.size - 1]);
        limbs[size++] = number;
    }
    else {
        generateNLimbsRandom(max.limbsCount() - 1);
        uint64_t number = randomLimb(0, max.limbs[max.size - 1]);
        limbs[size++] = number;
        removeLeadingZeros();
    }
}

BigInt64::BigInt64(bool isNegative) : BigInt64(0)
{
    this->isNegative = isNegative;
}

BigInt64::BigInt64(uint64_t uval) : size(0)
{
    isNegative = false;
    limbs[size++] = uval;
}

bool BigInt64::operator==(const BigInt64 &b) const
{
    if (isNegative != b.isNegative || size != b.size)
        return false;

    for (int i = 0; i < size; i++)
        if (limbs[i] != b.limbs[i])
            return false;

    return true;
}

bool BigInt64::operator!=(const BigInt64 &b) const
{
    return !(*this == b);
}

bool BigInt64::operator<(const BigInt64 &b) const
{
    if (isNegative && !b.isNegative)
        return true;

    if (!isNegative && b.isNegative)
        return false;

    // same sign
    if (isNegative)
        return b.isSmallerThanUnsigned(*this);

    else
        return isSmallerThanUnsigned(b);
}

bool BigInt64::operator>(const BigInt64 &b) const
{
    return b < *this;
}

bool BigInt64::operator<=(const BigInt64 &b) const
{
    return !(b < *this);
}

bool BigInt64::operator>=(const BigInt64 &b) const
{
    return !(*this < b);
}

BigInt64 &BigInt64::operator++()
{
    if (!isNegative)
        prefixPlusPlusUnsigned();
    else {
        prefixMinusMinusUnsigned();
        if (isZero())
            //-1 -> 0
            isNegative = false;
    }

    return *this;
}

BigInt64 BigInt64::operator++(int)
{
    BigInt64 temp = *this;
    ++*this;
    return temp;
}

BigInt64 &BigInt64::operator--()
{
    if (isNegative)
        prefixPlusPlusUnsigned();
    else {
        if (isZero()) {
            // 0 -> -1
            limbs[0] = 1;
            isNegative = true;
        }
        else
            prefixMinusMinusUnsigned();
    }
    return *this;
}

BigInt64 BigInt64::operator--(int)
{
    BigInt64 temp = *this;
    --*this;
    return temp;
}

BigInt64 &BigInt64::operator+=(const BigInt64 &b)
{
    if (isNegative == b.isNegative)  // same sign
        addUnsigned(b);
    else {
        if ((isNegative && !b.isSmallerThanUnsigned(*this)) ||
            (!isNegative && isSmallerThanUnsigned(b))) {
            // -3 + +4/-3 + +3 ||  +3 + -4
            thisEqualsbBSubthis(b);
            isNegative = b.isNegative;
        }
        else                      // -4 + +3 ||  +3 + -3 / +4 + -3
            subtractUnsigned(b);  // this-=b
    }
    return *this;
}

BigInt64 BigInt64::operator+(const BigInt64 &b) const
{
    BigInt64 c(*this);
    c += b;
    return c;
}

BigInt64 &BigInt64::operator-=(const BigInt64 &b)
{
    if (isNegative != b.isNegative)  // -this - +b / +a - -b
        addUnsigned(b);
    else {
        if ((isNegative && !b.isSmallerThanUnsigned(*this)) ||
            (!isNegative && (isSmallerThanUnsigned(b)))) {
            // -3 - -4/ -4 - -4 ||  +3 - +7
            thisEqualsbBSubthis(b);
            isNegative = !b.isNegative;
        }
        else                      //  -4 - -3 ||+4 - +3/ +3 - +3
            subtractUnsigned(b);  // this-=b
    }

    return *this;
}

BigInt64 BigInt64::operator-(const BigInt64 &b) const
{
    BigInt64 c(*this);
    c -= b;
    return c;
}

BigInt64 &BigInt64::operator*=(const BigInt64 &b)
{
    longMultiplication(b);
    return *this;
}

BigInt64 BigInt64::operator*(const BigInt64 &b) const
{
    BigInt64 c(*this);
    c *= b;
    return c;
}

BigInt64 &BigInt64::operator/=(const BigInt64 &b)
{
    BigInt64 remainder, quotient;
    longDivision(b, remainder, quotient);
    *this = quotient;
    return *this;
}

BigInt64 BigInt64::operator/(const BigInt64 &b) const
{
    BigInt64 c(*this);
    c /= b;
    return c;
}

BigInt64 &BigInt64::operator%=(const BigInt64 &b)
{
    BigInt64 remainder, quotient;
    longDivision(b, remainder, quotient);
    if (isNegative != b.isNegative)
        *this = b - remainder;
    else
        *this = remainder;
    return *this;
}

BigInt64 BigInt64::operator%(const BigInt64 &b) const
{
    BigInt64 c(*this);
    c %= b;
    return c;
}

BigInt64 &BigInt64::operator^=(const BigInt64 &b)
{
    *this = power(*this, b);
    return *this;
}

BigInt64 BigInt64::operator^(const BigInt64 &b) const
{
    BigInt64 c(*this);
    c ^= b;
    return c;
}

BigInt64 &BigInt64::operator>>=(uint64_t n)
{
    rightShift(n);
    return *this;
}

BigInt64 BigInt64::operator>>(uint64_t n) const
{
    BigInt64 c(*this);
    c >>= n;
    return c;
}

BigInt64 &BigInt64::operator<<=(uint64_t n)
{
    leftShift(n);
    return *this;
}

BigInt64 BigInt64::operator<<(uint64_t n) const
{
    BigInt64 c(*this);
    c <<= n;
    return c;
}

std::ostream &operator<<(std::ostream &out, const BigInt64 &a)
{
    if (a.limbsCount() == 1) {
        if (a.isNegative)
            out << "-";
        out << a.limbs[0];
    }

    else {
        BigInt10 decimal = a.toDecimal();
        out << decimal;
    }

    return out;
}

bool BigInt64::isSmallerThanUnsigned(const BigInt64 &b) const
{
    if (limbsCount() > b.limbsCount())
        // a is longer
        return false;

    if (limbsCount() < b.limbsCount())
        // b is longer
        return true;

    // same length
    for (int i = limbsCount() - 1; i >= 0; i--)
        if (limbs[i] != b.limbs[i])
            return limbs[i] < b.limbs[i];

    // they are equal
    return false;
}

void BigInt64::prefixPlusPlusUnsigned()
{
    int i, n = limbsCount();
    // zero alll the MAX_VAL_64 lsb's
    for (i = 0; i < n && limbs[i] == MAX_VAL_64; i++) {
        limbs[i] = 0;
    }
    if (i == n)
        // it was all MAX_VAL_64
        limbs[size++] = 1;
    else
        limbs[i]++;
}

void BigInt64::prefixMinusMinusUnsigned()
{
    if (isZero())
        return;

    int i = 0, n = limbsCount();
    // starting zeros case 0 0 0 X
    while (i < n && limbs[i] == 0) {
        limbs[i] = MAX_VAL_64;
        i++;
    }
    limbs[i]--;  // subtruct the first valid limb
    // remove leading zero if exists
    if (limbs[i] == 0 && i != 0)
        size--;
}

void BigInt64::addUnsigned(const BigInt64 &b)
{
    int n = limbsCount(), m = b.limbsCount();
    uint64_t carry = 0;  //(1/0)
    uint64_t bLimb;
    if (n < m) {
        setLimbs(0, m - n, 1, m);
        n = m;
    }
    for (int i = 0; i < n; i++) {
        bLimb = i < m ? b.limbs[i] : 0;
        adder3_64(limbs[i], bLimb, carry, limbs[i], carry);
    }
    if (carry == 1)
        limbs[size++] = carry;
}

void BigInt64::subtractUnsigned(const BigInt64 &b)
{
    if (this->isSmallerThanUnsigned(b))
        // make sure this>=b;
        return;

    int n = limbsCount(), m = b.limbsCount();
    int borrow = 0;  //(1/0)
    uint64_t bLimb;

    for (int i = 0; i < n; i++) {
        bLimb = i < m ? b.limbs[i] : 0;
        if ((borrow == 1 && limbs[i] == 0) || (limbs[i] - borrow < bLimb)) {
            // need to borrow from next limb
            limbs[i] = limbs[i] + toBase64(bLimb) - borrow;
            borrow = 1;
        }
        else {
            limbs[i] = limbs[i] - bLimb - borrow;
            borrow = 0;
        }
    }
    removeLeadingZeros();
}

void BigInt64::longMultiplication(const BigInt64 &b)
{
    if (isZero() || b.isZero()) {
        zero();
        return;
    }
    int n = limbsCount(), m = b.limbsCount();
    uint64_t result[200] = {0};
    uint64_t high, low, carry;

    for (int i = 0; i < n; i++) {
        carry = 0;
        for (int j = 0; j < m; j++) {
            mul2Limbs64(limbs[i], b.limbs[j], high, low);
            adder3_64(low, result[i + j], carry, result[i + j], carry);
            carry += high;
        }
        result[i + m] = carry;
    }
    size = m + n;
    copyLimbsFrom(result, 0, size, 0, size);
    removeLeadingZeros();
    isNegative = isNegative != b.isNegative;
}

std::string BigInt64::toString() const
{
    std::ostringstream oss;
    oss << *this;
    return oss.str();
}

void BigInt64::exportTo(uint8_t *out, size_t outLen, CreateModes mode) const
{
    if (outLen < bytesCount())
        throw std::runtime_error("Not enough space in output buffer");

    if (mode == CreateModes::LITTLE_ENDIANESS)
        for (int i = 0; i < limbsCount(); i++)
            for (int j = 0; j < BYTES_IN_LIMB; j++)
                out[outLen - 1 - i * BYTES_IN_LIMB - (7 - j)] =
                    static_cast<uint8_t>(limbs[i] >> (j * BITS_IN_BYTE));
    else
        for (int i = 0; i < limbsCount(); i++)
            for (int j = 0; j < BYTES_IN_LIMB; j++)
                out[outLen - 1 - i * BYTES_IN_LIMB - j] =
                    static_cast<uint8_t>(limbs[i] >> (j * BITS_IN_BYTE));
}

int BigInt64::bitsCount() const
{
    if (isZero())
        return 0;

    uint64_t mostSignificantLimb = limbs[size - 1];
    int inMsb = ::bitsCount(mostSignificantLimb);
    return inMsb + (limbsCount() - 1) * BITS_IN_LIMB;
}

void BigInt64::thisEqualsbBSubthis(const BigInt64 &b)
{
    BigInt64 copyB(b);
    copyB.subtractUnsigned(*this);
    *this = std::move(copyB);
}

void BigInt64::removeLeadingZeros()
{
    while (size > 1 && limbs[size - 1] == 0)
        size--;
}

void BigInt64::insert(int n, uint64_t limb)
{
    for (int i = size - 1; i >= 0; i--)
        limbs[i + n] = limbs[i];
    for (int i = 0; i < n; i++)
        limbs[i] = limb;
    size += n;
}

void BigInt64::erase(int n)
{
    for (int i = 0; i < n; i++)
        limbs[i] = limbs[i + n];
    size -= n;
}

void BigInt64::generateNLimbsRandom(int limbsCnt)
{
    if (limbsCnt < 1)
        throw std::invalid_argument("limbsCnt less than 1");

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);
    size = limbsCnt;

    for (int i = 0; i < limbsCnt; i++) {
        uint64_t number = distrib(gen);
        limbs[i] = number;
    }
}

uint64_t BigInt64::randomLimb(uint64_t min, uint64_t max)
{
    if (min > max)
        throw std::invalid_argument("cant random limb");

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(min, max);
    return distrib(gen);
}

void BigInt64::zero()
{
    size = 1;
    limbs[0] = 0;
    isNegative = false;
}

bool BigInt64::hasLeadingZero()
{
    return limbs[size - 1] == 0 && limbsCount() > 1;
}

void BigInt64::copyLimbsFrom(const uint64_t *other, size_t otherStart,
                             size_t count, size_t meStart, size_t newSize)
{
    for (int i = 0; i < count; i++)
        limbs[meStart + i] = other[otherStart + i];
    size = newSize;
}

void BigInt64::reverse()
{
    int start = 0;
    int end = size - 1;

    while (start < end) {
        uint64_t temp = limbs[start];
        limbs[start] = limbs[end];
        limbs[end] = temp;
        start++;
        end--;
    }
}

void BigInt64::setLimbs(uint64_t val, size_t count, size_t meStart,
                        size_t newSize)
{
    for (int i = 0; i < count; i++)
        limbs[meStart + i] = val;
    size = newSize;
}

void BigInt64::longDivision(const BigInt64 &b, BigInt64 &remainder,
                            BigInt64 &quotient) const
{
    if (b.isZero())
        return;

    remainder.isNegative = b.isNegative;
    if (isSmallerThanUnsigned(b)) {
        remainder.copyLimbsFrom(limbs, 0, size, 0, size);
        quotient.zero();
        return;
    }

    remainder.size = 0;
    quotient.size = 0;

    for (int i = limbsCount() - 1; i >= 0; i--) {  // msb-lsb
        remainder.insert(1, limbs[i]);             // insert msb as lsb
        if (remainder.hasLeadingZero())
            remainder.size--;  // remove leading zero
        uint64_t times = 0;
        if (!remainder.isSmallerThanUnsigned(b)) {
            uint64_t left = 1, right = MAX_VAL_64;
            // after inserting next limb, most times t contains b is max value
            // of singe limb, find in range of [0...max]
            while (left <= right) {
                uint64_t mid = left + (right - left) / 2;
                if (!remainder.isSmallerThanUnsigned(
                        b * mid)) {  // b*mid<=remainder
                    times = mid;
                    if (left == right)
                        break;
                    left = mid + 1;
                }
                else
                    right = mid - 1;
            }

            remainder.subtractUnsigned(b * times);
        }

        if (quotient.size > 0 || times > 0)
            quotient.limbs[quotient.size++] = times;
    }

    quotient.reverse();
    quotient.isNegative = isNegative != b.isNegative;
}
BigInt64 power(BigInt64 base, BigInt64 exponent)
{
    if (exponent.isNegative)
        throw std::invalid_argument("Invalid input: negative exponent");

    BigInt64 result(1);

    while (!exponent.isZero()) {
        if (!exponent.isEven())
            result *= base;
        base *= base;
        exponent >>= 1;
    }

    return result;
}

BigInt10 BigInt64::toDecimal() const
{
    BigInt10 decimal;
    BigInt10 base(MAX_VAL_64);
    base++;
    for (int i = limbsCount() - 1; i >= 0; i--) {
        BigInt10 limb = limbs[i];
        decimal *= base;
        decimal += limb;
    }

    decimal.isNegative = isNegative;
    return decimal;
}

void BigInt64::initFromString(const char *str, int n)
{
    BigInt10 decimal = str;
    size = 0;
    isNegative = decimal.isNegative;
    BigInt10 base = MAX_VAL_64;
    base++;
    if (decimal.isZero())
        limbs[size++] = 0;
    else
        while (!decimal.isZero()) {
            limbs[size++] = (decimal % base).toU64();
            decimal /= base;
        }
}

BigInt64 gcd(BigInt64 a, BigInt64 b)
{
    a.isNegative = false;
    b.isNegative = false;
    while (!b.isZero()) {
        BigInt64 copyB = b;
        b = a % b;
        a = copyB;
    }

    return a;
}

void BigInt64::rightShift(uint64_t n)
{
    if (n >= bitsCount()) {
        zero();
        return;
    }
    uint64_t shiftEachLimb = n % BITS_IN_LIMB;
    uint64_t dropLimbs = n / BITS_IN_LIMB;
    if (shiftEachLimb != 0) {
        for (int i = 0; i < limbsCount() - 1 - dropLimbs; i++)  // lsb...msb
            limbs[i] = limbs[i + dropLimbs] >> shiftEachLimb |
                       limbs[i + dropLimbs + 1]
                           << (BITS_IN_LIMB - shiftEachLimb);
        limbs[limbsCount() - 1 - dropLimbs] >>= shiftEachLimb;
        size -= dropLimbs;
        if (hasLeadingZero() && !isZero())
            size--;
    }
    else
        erase(dropLimbs);
}

void BigInt64::leftShift(uint64_t n)
{
    if (n >= bitsCount()) {
        zero();
        return;
    }

    uint64_t shiftEachLimb = n % BITS_IN_LIMB;
    uint64_t dropLimbs = n / BITS_IN_LIMB;
    if (shiftEachLimb != 0) {
        for (int i = limbsCount() - 1; i > dropLimbs; i--) {  // msb-lst
            limbs[i] =
                limbs[i - dropLimbs] << shiftEachLimb |
                limbs[i - dropLimbs - 1] >> (BITS_IN_LIMB - shiftEachLimb);
        }

        limbs[0] <<= shiftEachLimb;
    }
    else {
        for (int i = limbsCount() - 1; i >= dropLimbs; i--)
            limbs[i] = limbs[i - dropLimbs];
        for (int i = dropLimbs - 1; i >= 0; i--)
            limbs[i] = 0;
    }

    removeLeadingZeros();
}

BigInt64 extendedGcd(BigInt64 a, BigInt64 b, BigInt64 &x, BigInt64 &y)
{
    x = 1;
    y = 0;
    BigInt64 x1 = 0, y1 = 1;
    BigInt64 q, temp;

    while (b != 0) {
        q = a / b;
        temp = b;
        b = a % b;
        a = temp;

        temp = x1;

        x1 = x - q * x1;
        x = temp;

        temp = y1;
        y1 = y - q * y1;
        y = temp;
    }

    return a;
}

BigInt64 modularInverse(BigInt64 a, BigInt64 b)
{
    BigInt64 x, y;
    BigInt64 gcdResult = extendedGcd(a, b, x, y);
    if (gcdResult != 1)
        throw std::invalid_argument("Modular inverse does not exist.");

    return x % b;  // Ensure result is positive
}

size_t BigInt64::bytesCount() const
{
    return limbsCount() * BYTES_IN_LIMB;
}

bool BigInt64::isZero() const
{
    return limbsCount() == 1 && limbs[0] == 0;
}

int BigInt64::limbsCount() const
{
    return size;
}

std::uint64_t BigInt64::getMsb() const
{
    return limbs[size - 1];
}

std::uint64_t BigInt64::getLsb() const
{
    return limbs[0];
}

bool BigInt64::isEven() const
{
    return (limbs[0] & 1) == 0;
}
#else
BigInt64::BigInt64(const string &str)
{
    initFromString(str.c_str(), str.size());
}

BigInt64::BigInt64(const char *str)
{
    initFromString(str, std::strlen(str));
}

BigInt64::BigInt64(const uint8_t *str, size_t strLen, CreateModes mode)
    : isNegative(false)
{
    if (strLen == 0) {
        limbs.push_back(0);
        return;
    }

    int fullLimbs = strLen / BYTES_IN_LIMB;
    int msbParts = strLen % BYTES_IN_LIMB;
    int limbsCnt = fullLimbs + (msbParts + BYTES_IN_LIMB - 1) / BYTES_IN_LIMB;
    limbs.reserve(limbsCnt);
    if (mode == CreateModes::LITTLE_ENDIANESS) {
        for (int i = 0; i < fullLimbs; i++) {
            int index = strLen - 1 - i * BYTES_IN_LIMB;
            // little endian-> {0,1,2,3,4,5,6,7} becones 0x 07 06 05 04 03 02 01 00
            limbs.push_back((static_cast<uint64_t>(str[index]) << 56) |
                            (static_cast<uint64_t>(str[index - 1]) << 48) |
                            (static_cast<uint64_t>(str[index - 2]) << 40) |
                            (static_cast<uint64_t>(str[index - 3]) << 32) |
                            (static_cast<uint64_t>(str[index - 4]) << 24) |
                            (static_cast<uint64_t>(str[index - 5]) << 16) |
                            (static_cast<uint64_t>(str[index - 6]) << 8) |
                            static_cast<uint64_t>(str[index - 7]));
        }

        if (msbParts != 0) {
            uint64_t msb = 0;
            for (int i = 0; i < msbParts; i++)
                msb |= static_cast<uint64_t>(str[i]) << (i * BITS_IN_BYTE);
            limbs.push_back(msb);
        }
    }
    else {
        // big endian-> {0,1,2,3,4,5,6,7} becones 0x 00 01 02 03 04 05 06 07
        for (int i = 0; i < fullLimbs; i++) {
            int index = strLen - 1 - i * BYTES_IN_LIMB;
            limbs.push_back(static_cast<uint64_t>(str[index]) |
                            (static_cast<uint64_t>(str[index - 1]) << 8) |
                            (static_cast<uint64_t>(str[index - 2]) << 16) |
                            (static_cast<uint64_t>(str[index - 3]) << 24) |
                            (static_cast<uint64_t>(str[index - 4]) << 32) |
                            (static_cast<uint64_t>(str[index - 5]) << 40) |
                            (static_cast<uint64_t>(str[index - 6]) << 48) |
                            (static_cast<uint64_t>(str[index - 7]) << 56));
        }

        if (msbParts != 0) {
            uint64_t msb = 0;
            for (int i = 0; i < msbParts; i++) {
                msb |= static_cast<uint64_t>(str[msbParts - 1 - i])
                       << (i * BITS_IN_BYTE);
            }

            limbs.push_back(msb);
        }
    }

    removeLeadingZeros();
}

BigInt64::BigInt64(std::vector<uint64_t> v, bool isNegative)
    : limbs(v), isNegative(isNegative)
{
}

BigInt64::BigInt64(CreateModes mode, int bits) : isNegative(false)
{
    if (bits >= BITS_IN_LIMB)
        generateNLimbsRandom(bits / BITS_IN_LIMB);
    bits = bits % BITS_IN_LIMB;  // 0-63
    if (bits != 0) {
        uint64_t one = static_cast<uint64_t>(1);
        limbs.push_back(randomLimb(0, (one << bits) - 1) | (one << (bits - 1)));
    }
    else
        limbs.back() |= 0x8000000000000000ULL;
}

BigInt64::BigInt64(CreateModes mode, uint64_t min, const BigInt64 &max)
    : isNegative(false)
{
    if (max.isSmallerThanUnsigned(min))
        throw invalid_argument("min must be <= max");

    if (max.limbsCount() == 1) {
        uint64_t number = randomLimb(min, max.limbs.back());
        limbs.push_back(number);
    }
    else {
        generateNLimbsRandom(max.limbsCount() - 1);
        uint64_t number = randomLimb(0, max.limbs.back());
        limbs.push_back(number);
        removeLeadingZeros();
    }
}

BigInt64::BigInt64(long long val)
{
    isNegative = false;
    if (val == 0) {
        limbs.push_back(0);
        return;
    }

    if (val < 0) {
        isNegative = true;
        val *= -1;
    }

    limbs.push_back(val);
}

BigInt64::BigInt64(bool isNegative) : BigInt64(0)
{
    this->isNegative = isNegative;
}

BigInt64::BigInt64(uint64_t uval)
{
    isNegative = false;
    limbs.push_back(uval);
}

BigInt64::BigInt64(int val) : BigInt64(static_cast<long long>(val)) {}

bool BigInt64::operator==(const BigInt64 &b) const
{
    return limbs == b.limbs && isNegative == b.isNegative;
}

bool BigInt64::operator!=(const BigInt64 &b) const
{
    return !(*this == b);
}

bool BigInt64::operator<(const BigInt64 &b) const
{
    if (isNegative && !b.isNegative)
        return true;

    if (!isNegative && b.isNegative)
        return false;

    // same sign
    if (isNegative)
        return b.isSmallerThanUnsigned(*this);

    else
        return isSmallerThanUnsigned(b);
}

bool BigInt64::operator>(const BigInt64 &b) const
{
    return b < *this;
}

bool BigInt64::operator<=(const BigInt64 &b) const
{
    return !(b < *this);
}

bool BigInt64::operator>=(const BigInt64 &b) const
{
    return !(*this < b);
}

BigInt64 &BigInt64::operator++()
{
    if (!isNegative)
        prefixPlusPlusUnsigned();
    else {
        prefixMinusMinusUnsigned();
        if (isZero())
            //-1 -> 0
            isNegative = false;
    }

    return *this;
}

BigInt64 BigInt64::operator++(int)
{
    BigInt64 temp = *this;
    ++*this;
    return temp;
}

BigInt64 &BigInt64::operator--()
{
    if (isNegative)
        prefixPlusPlusUnsigned();
    else {
        if (isZero()) {
            // 0 -> -1
            limbs[0] = 1;
            isNegative = true;
        }
        else
            prefixMinusMinusUnsigned();
    }

    return *this;
}

BigInt64 BigInt64::operator--(int)
{
    BigInt64 temp = *this;
    --*this;
    return temp;
}

BigInt64 &BigInt64::operator+=(const BigInt64 &b)
{
    if (isNegative == b.isNegative)  // same sign
        addUnsigned(b);
    else {
        if (isNegative && !b.isSmallerThanUnsigned(*this) ||
            !isNegative && isSmallerThanUnsigned(b)) {
            // -3 + +4/-3 + +3 ||  +3 + -4
            thisEqualsbBSubthis(b);
            isNegative = b.isNegative;
        }
        else                      // -4 + +3 ||  +3 + -3 / +4 + -3
            subtractUnsigned(b);  // this-=b
    }

    return *this;
}

BigInt64 BigInt64::operator+(const BigInt64 &b) const
{
    BigInt64 c(*this);
    c += b;
    return c;
}

BigInt64 &BigInt64::operator-=(const BigInt64 &b)
{
    if (isNegative != b.isNegative)  // -this - +b / +a - -b
        addUnsigned(b);
    else {
        if (isNegative && !b.isSmallerThanUnsigned(*this) ||
            !isNegative && (isSmallerThanUnsigned(b))) {
            // -3 - -4/ -4 - -4 ||  +3 - +7
            thisEqualsbBSubthis(b);
            isNegative = !b.isNegative;
        }
        else                      //  -4 - -3 ||+4 - +3/ +3 - +3
            subtractUnsigned(b);  // this-=b
    }

    return *this;
}

BigInt64 BigInt64::operator-(const BigInt64 &b) const
{
    BigInt64 c(*this);
    c -= b;
    return c;
}

BigInt64 &BigInt64::operator*=(const BigInt64 &b)
{
    *this = longMultiplication(*this, b);
    return *this;
}

BigInt64 BigInt64::operator*(const BigInt64 &b) const
{
    BigInt64 c(*this);
    c *= b;
    return c;
}
BigInt64 &BigInt64::operator/=(const BigInt64 &b)
{
    BigInt64 remainder;
    *this = longDivision(*this, b, remainder);
    return *this;
}

BigInt64 BigInt64::operator/(const BigInt64 &b) const
{
    BigInt64 c(*this);
    c /= b;
    return c;
}

BigInt64 &BigInt64::operator%=(const BigInt64 &b)
{
    BigInt64 remainder;
    longDivision(*this, b, remainder);
    if (isNegative != b.isNegative)
        *this = b - remainder;
    else
        *this = remainder;
    return *this;
}

BigInt64 BigInt64::operator%(const BigInt64 &b) const
{
    BigInt64 c(*this);
    c %= b;
    return c;
}

BigInt64 &BigInt64::operator^=(const BigInt64 &b)
{
    *this = power(*this, b);
    return *this;
}

BigInt64 BigInt64::operator^(const BigInt64 &b) const
{
    BigInt64 c(*this);
    c ^= b;
    return c;
}

BigInt64 &BigInt64::operator>>=(uint64_t n)
{
    rightShift(n);
    return *this;
}

BigInt64 BigInt64::operator>>(uint64_t n) const
{
    BigInt64 c(*this);
    c >>= n;
    return c;
}

BigInt64 &BigInt64::operator<<=(uint64_t n)
{
    leftShift(n);
    return *this;
}

BigInt64 BigInt64::operator<<(uint64_t n) const
{
    BigInt64 c(*this);
    c <<= n;
    return c;
}

std::ostream &operator<<(std::ostream &out, const BigInt64 &a)
{
    if (a.limbsCount() == 1) {
        if (a.isNegative)
            out << "-";
        out << a.limbs[0];
    }
    else {
        BigInt10 decimal = a.toDecimal();
        out << decimal;
    }

    return out;
}

bool BigInt64::isSmallerThanUnsigned(const BigInt64 &b) const
{
    if (limbsCount() > b.limbsCount())
        // a is longer
        return false;

    if (limbsCount() < b.limbsCount())
        // b is longer
        return true;

    // same length
    for (int i = limbsCount() - 1; i >= 0; i--)
        if (limbs[i] != b.limbs[i])
            return limbs[i] < b.limbs[i];

    // they are equal
    return false;
}

void BigInt64::prefixPlusPlusUnsigned()
{
    int i, n = limbsCount();
    // zero alll the MAX_VAL_64 lsb's
    for (i = 0; i < n && limbs[i] == MAX_VAL_64; i++)
        limbs[i] = 0;
    if (i == n)
        // it was all MAX_VAL_64
        limbs.push_back(1);
    else
        limbs[i]++;
}

void BigInt64::prefixMinusMinusUnsigned()
{
    if (isZero())
        throw std::invalid_argument("cant --0");

    int i = 0, n = limbsCount();
    // starting zeros case 0 0 0 X
    while (i < n && limbs[i] == 0) {
        limbs[i] = MAX_VAL_64;
        i++;
    }

    limbs[i]--;  // subtruct the first valid limb
    // remove leading zero if exists
    if (limbs[i] == 0 && i != 0)
        limbs.pop_back();
}

void BigInt64::addUnsigned(const BigInt64 &b)
{
    int n = limbsCount(), m = b.limbsCount();
    uint64_t carry = 0;  //(1/0)
    uint64_t bLimb;
    if (n < m) {
        limbs.resize(m);
        n = m;
    }

    for (int i = 0; i < n; i++) {
        bLimb = i < m ? b.limbs[i] : 0;
        adder3_64(limbs[i], bLimb, carry, limbs[i], carry);
    }

    if (carry == 1)
        limbs.push_back(carry);
}

void BigInt64::subtractUnsigned(const BigInt64 &b)
{
    if (this->isSmallerThanUnsigned(b))
        // make sure this>=b;
        throw std::invalid_argument("cant -: this < b");

    int n = limbsCount(), m = b.limbsCount();
    int borrow = 0;  //(1/0)
    uint64_t bLimb;

    for (int i = 0; i < n; i++) {
        bLimb = i < m ? b.limbs[i] : 0;
        if ((borrow == 1 && limbs[i] == 0) || (limbs[i] - borrow < bLimb)) {
            // need to borrow from next limb
            limbs[i] = limbs[i] + toBase64(bLimb) - borrow;
            borrow = 1;
        }
        else {
            limbs[i] = limbs[i] - bLimb - borrow;
            borrow = 0;
        }
    }

    removeLeadingZeros();
}
BigInt64 longMultiplication(const BigInt64 &a, const BigInt64 &b)
{
    if (a.isZero() || b.isZero())
        return BigInt64();

    int n = a.limbsCount(), m = b.limbsCount();
    std::vector<uint64_t> result(n + m, 0);
    uint64_t high, low, carry;

    for (int i = 0; i < n; i++) {
        carry = 0;
        for (int j = 0; j < m; j++) {
            mul2Limbs64(a.limbs[i], b.limbs[j], high, low);
            adder3_64(low, result[i + j], carry, result[i + j], carry);
            carry += high;
        }
        // Handle any remaining carry after the inner loop
        result[i + m] = carry;
    }

    BigInt64 res;
    res.limbs = std::move(result);
    res.removeLeadingZeros();
    res.isNegative = a.isNegative != b.isNegative;
    return res;
}

void BigInt64::exportTo(uint8_t *out, size_t outLen, CreateModes mode) const
{
    if (outLen < bytesCount())
        throw std::runtime_error("Not enough space in output buffer");

    if (mode == CreateModes::LITTLE_ENDIANESS)
        for (int i = 0; i < limbsCount(); i++)
            for (int j = 0; j < BYTES_IN_LIMB; j++)
                out[outLen - 1 - i * BYTES_IN_LIMB - (7 - j)] =
                    static_cast<uint8_t>(limbs[i] >> (j * BITS_IN_BYTE));
    else
        for (int i = 0; i < limbsCount(); i++)
            for (int j = 0; j < BYTES_IN_LIMB; j++)
                out[outLen - 1 - i * BYTES_IN_LIMB - j] =
                    static_cast<uint8_t>(limbs[i] >> (j * BITS_IN_BYTE));
}

int BigInt64::bitsCount() const
{
    if (isZero())
        return 0;

    // Count bits in the most significant limb manually
    uint64_t mostSignificantLimb = limbs.back();
    int inMsb = ::bitsCount(mostSignificantLimb);
    return inMsb + (limbsCount() - 1) * BITS_IN_LIMB;
}

void BigInt64::thisEqualsbBSubthis(const BigInt64 &b)
{
    BigInt64 copyB(b);
    copyB.subtractUnsigned(*this);
    *this = std::move(copyB);
}

void BigInt64::removeLeadingZeros()
{
    while (limbs.size() > 1 && limbs.back() == 0)
        limbs.pop_back();
}

void BigInt64::insertZroes(int n)
{
    limbs.insert(limbs.begin(), n, 0);
}

void BigInt64::generateNLimbsRandom(int limbsCnt)
{
    if (limbsCnt < 1)
        throw std::invalid_argument("limbsCnt less than 1");

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(0, UINT64_MAX);

    limbs.reserve(limbsCnt);

    for (int i = 0; i < limbsCnt; i++) {
        uint64_t number = distrib(gen);
        limbs.push_back(number);
    }
}

uint64_t BigInt64::randomLimb(uint64_t min, uint64_t max)
{
    if (min > max)
        throw std::invalid_argument("cant random limb");

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> distrib(min, max);
    return distrib(gen);
}

void BigInt64::zero()
{
    limbs.clear();
    limbs.push_back(0);
    isNegative = false;
}

BigInt64 longDivision(const BigInt64 &a, const BigInt64 &b, BigInt64 &remainder)
{
    if (b.isZero())
        throw std::invalid_argument("Invalid input: non-digit character");

    remainder.isNegative = b.isNegative;
    if (a.isSmallerThanUnsigned(b)) {
        remainder.limbs = a.limbs;
        return BigInt64();
    }

    remainder.limbs.clear();
    std::vector<uint64_t> quotient;

    for (int i = a.limbsCount() - 1; i >= 0; i--) {  // msb-lsb
        remainder.limbs.insert(remainder.limbs.begin(),
                               a.limbs[i]);  // insert msb as lsb
        if (remainder.limbsCount() > 1 && remainder.limbs.back() == 0)
            remainder.limbs.pop_back();  // remove leading zero
        uint64_t times = 0;
        if (!remainder.isSmallerThanUnsigned(b)) {
            uint64_t left = 1, right = MAX_VAL_64;
            // after inserting next limb, most times t contains b is max value
            // of singe limb, find in range of [0...max]
            while (left <= right) {
                uint64_t mid = left + (right - left) / 2;
                if (!remainder.isSmallerThanUnsigned(
                        b * mid)) {  // b*mid<=remainder
                    times = mid;
                    if (left == right)
                        break;
                    left = mid + 1;
                }
                else
                    right = mid - 1;
            }

            remainder.subtractUnsigned(b * times);
        }
        if (quotient.size() > 0 || times > 0)
            quotient.push_back(times);
    }

    std::reverse(quotient.begin(), quotient.end());
    BigInt64 quoti(a.isNegative != b.isNegative);
    quoti.limbs = std::move(quotient);
    return quoti;
}

BigInt64 power(BigInt64 base, BigInt64 exponent)
{
    if (exponent.isNegative)
        throw std::invalid_argument("Invalid input: negative exponent");

    BigInt64 result(1);
    while (!exponent.isZero()) {
        if (!exponent.isEven()) {
            result *= base;
        }
        base *= base;
        exponent >>= 1;
    }

    return result;
}

BigInt10 BigInt64::toDecimal() const
{
    BigInt10 decimal;
    BigInt10 base(MAX_VAL_64);
    base++;
    for (int i = limbsCount() - 1; i >= 0; i--) {
        BigInt10 limb = limbs[i];
        decimal *= base;
        decimal += limb;
    }

    decimal.isNegative = isNegative;
    return decimal;
}

void BigInt64::initFromString(const char *str, int n)
{
    BigInt10 decimal = str;
    isNegative = decimal.isNegative;
    BigInt10 base = MAX_VAL_64;
    base++;
    if (decimal.isZero())
        limbs.push_back(0);
    else
        while (!decimal.isZero()) {
            limbs.push_back((decimal % base).toU64());
            decimal /= base;
        }
}

BigInt64 modularExponentiation(BigInt64 base, BigInt64 exponent,
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

BigInt64 gcd(BigInt64 a, BigInt64 b)
{
    a.isNegative = false;
    b.isNegative = false;
    while (!b.isZero()) {
        BigInt64 copyB = b;
        b = a % b;
        a = copyB;
    }

    return a;
}

BigInt64 karatzubaMultiplication(const BigInt64 &a, const BigInt64 &b)
{
    int n = a.limbsCount(), m = b.limbsCount();
    if (n == 1 || m == 1)
        return longMultiplication(a, b);

    const BigInt64 *longerX, *shorterY;
    int xLen, yLen;
    if (n >= m) {
        longerX = &a;
        xLen = n;
        shorterY = &b;
        yLen = m;
    }
    else {
        longerX = &b;
        xLen = m;
        shorterY = &a;
        yLen = n;
    }

    int xLsbHalf = xLen / 2;
    int yLsbHalf = min(xLsbHalf, yLen);
    BigInt64 xM, xL, yL, yM;
    xM.limbs.reserve(xLen - xLsbHalf);
    xL.limbs.reserve(xLsbHalf);
    yM.limbs.reserve(yLen - yLsbHalf);
    yL.limbs.reserve(yLsbHalf);
    // Msb Lsb
    //  xM aL =longer <-[L M], [xL ......  xM]
    //  yM bL =shorter<-[L M], [yL  yM]
    xL.limbs.assign(longerX->limbs.begin(), longerX->limbs.begin() + xLsbHalf);
    xL.removeLeadingZeros();
    xM.limbs.assign(longerX->limbs.begin() + xLsbHalf,
                    longerX->limbs.begin() + xLen);
    yL.limbs.assign(shorterY->limbs.begin(),
                    shorterY->limbs.begin() + yLsbHalf);
    yL.removeLeadingZeros();
    if (yLen - yLsbHalf != 0)
        yM.limbs.assign(shorterY->limbs.begin() + yLsbHalf,
                        shorterY->limbs.begin() + yLen);
    BigInt64 sum4Mult = karatzubaMultiplication(xL + xM, yL + yM);
    BigInt64 xyL = karatzubaMultiplication(xL, yL);
    BigInt64 xyM = karatzubaMultiplication(xM, yM);
    BigInt64 xLyM_xMyL = sum4Mult - xyL - xyM;
    xyM.insertZroes(xLsbHalf * 2);
    xLyM_xMyL.insertZroes(xLsbHalf);
    BigInt64 res = xyM + xLyM_xMyL + xyL;
    res.isNegative = a.isNegative != b.isNegative;
    return res;
}

void BigInt64::rightShift(uint64_t n)
{
    if (n >= bitsCount()) {
        zero();
        return;
    }
    uint64_t shiftEachLimb = n % BITS_IN_LIMB;
    uint64_t dropLimbs = n / BITS_IN_LIMB;
    if (shiftEachLimb != 0) {
        for (int i = 0; i < limbsCount() - 1 - dropLimbs; i++)  // lsb...msb
            limbs[i] = limbs[i + dropLimbs] >> shiftEachLimb |
                       limbs[i + dropLimbs + 1]
                           << (BITS_IN_LIMB - shiftEachLimb);
        limbs[limbsCount() - 1 - dropLimbs] >>= shiftEachLimb;
        limbs.resize(limbsCount() - dropLimbs);
        if (limbs.back() == 0 && !isZero())
            limbs.pop_back();
    }
    else
        limbs.erase(limbs.begin(), limbs.begin() + dropLimbs);
}

void BigInt64::leftShift(uint64_t n)
{
    if (n >= bitsCount()) {
        zero();
        return;
    }
    uint64_t shiftEachLimb = n % BITS_IN_LIMB;
    uint64_t dropLimbs = n / BITS_IN_LIMB;
    if (shiftEachLimb != 0) {
        for (int i = limbsCount() - 1; i > dropLimbs; i--) {  // msb-lst
            limbs[i] =
                limbs[i - dropLimbs] << shiftEachLimb |
                limbs[i - dropLimbs - 1] >> (BITS_IN_LIMB - shiftEachLimb);
        }
        limbs[0] <<= shiftEachLimb;
    }
    else {
        for (int i = limbsCount() - 1; i >= dropLimbs; i--)
            limbs[i] = limbs[i - dropLimbs];
        for (int i = dropLimbs - 1; i >= 0; i--)
            limbs[i] = 0;
    }

    removeLeadingZeros();
}

BigInt64 extendedGcd(BigInt64 a, BigInt64 b, BigInt64 &x, BigInt64 &y)
{
    x = 1;
    y = 0;
    BigInt64 x1 = 0, y1 = 1;
    BigInt64 q, temp;

    while (b != 0) {
        q = a / b;
        temp = b;
        b = a % b;
        a = temp;

        temp = x1;

        x1 = x - q * x1;
        x = temp;

        temp = y1;
        y1 = y - q * y1;
        y = temp;
    }

    return a;
}

BigInt64 modularInverse(BigInt64 a, BigInt64 b)
{
    BigInt64 x, y;
    BigInt64 gcdResult = extendedGcd(a, b, x, y);
    if (gcdResult != 1)
        throw std::invalid_argument("Modular inverse does not exist.");

    return x % b;  // Ensure result is positive
}

size_t BigInt64::bytesCount() const
{
    return limbsCount() * BYTES_IN_LIMB;
}

std::string BigInt64::toString() const
{
    std::ostringstream oss;
    oss << *this;
    return oss.str();
}

bool BigInt64::isZero() const
{
    return limbsCount() == 1 && limbs[0] == 0;
}

int BigInt64::limbsCount() const
{
    return limbs.size();
}

bool BigInt64::isEven() const
{
    return (limbs[0] & 1) == 0;
}
#endif