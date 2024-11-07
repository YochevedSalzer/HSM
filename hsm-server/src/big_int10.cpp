#include <sstream>
#include <stdexcept>
#include <algorithm>
#include "../include/big_int10.h"
#include "../include/big_int_utils.h"
using namespace std;

BigInt10::BigInt10(const std::string &str)
{
    initFromString(str.c_str(), str.size());
}

BigInt10::BigInt10(const char *str)
{
    initFromString(str, std::strlen(str));
}

BigInt10::BigInt10(long long val)
{
    isNegative = val < 0;
    do {
        limbs.push_back(val % 10);
        val /= 10;
    } while (val != 0);
}

BigInt10::BigInt10(uint64_t uval)
{
    isNegative = false;
    do {
        limbs.push_back(uval % 10);
        uval /= 10;
    } while (uval != 0);
}

BigInt10::BigInt10(bool isNegative) : BigInt10(0)
{
    this->isNegative = isNegative;
}

BigInt10::BigInt10(int val) : BigInt10(static_cast<long long>(val)) {}

bool BigInt10::operator==(const BigInt10 &b) const
{
    return limbs == b.limbs && isNegative == b.isNegative;
}

bool BigInt10::operator!=(const BigInt10 &b) const
{
    return !(*this == b);
}

bool BigInt10::operator<(const BigInt10 &b) const
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

bool BigInt10::operator>(const BigInt10 &b) const
{
    return b < *this;
}

bool BigInt10::operator<=(const BigInt10 &b) const
{
    return !(b < *this);
}

bool BigInt10::operator>=(const BigInt10 &b) const
{
    return !(*this < b);
}

BigInt10 &BigInt10::operator++()
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

BigInt10 BigInt10::operator++(int)
{
    BigInt10 temp = *this;
    ++*this;
    return temp;
}

BigInt10 &BigInt10::operator--()
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
BigInt10 BigInt10::operator--(int)
{
    BigInt10 temp = *this;
    --*this;
    return temp;
}

void BigInt10::thisEqualsbBSubthis(const BigInt10 &b)
{
    BigInt10 copyB(b);
    copyB.subtractUnsigned(*this);  // copyB-=this
    *this = std::move(copyB);
}

BigInt10 &BigInt10::operator+=(const BigInt10 &b)
{
    if (isNegative == b.isNegative)  // same sign
        addUnsigned(b);
    else if (isNegative && !b.isSmallerThanUnsigned(*this) ||
             !isNegative && isSmallerThanUnsigned(b)) {
        // -3 + +4/-3 + +3 ||  +3 + -4
        thisEqualsbBSubthis(b);
        isNegative = b.isNegative;
    }
    else                      // -4 + +3 ||  +3 + -3 / +4 + -3
        subtractUnsigned(b);  // this-=b
    return *this;
}

BigInt10 BigInt10::operator+(const BigInt10 &b) const
{
    BigInt10 c(*this);
    c += b;
    return c;
}

BigInt10 &BigInt10::operator-=(const BigInt10 &b)
{
    if (isNegative != b.isNegative)  // -this - +b / +a - -b
        addUnsigned(b);
    else if (isNegative && !b.isSmallerThanUnsigned(*this) ||
             !isNegative && (isSmallerThanUnsigned(b))) {
        // -3 - -4/ -4 - -4 ||  +3 - +7
        thisEqualsbBSubthis(b);
        isNegative = !b.isNegative;
    }
    else                      //  -4 - -3 ||+4 - +3/ +3 - +3
        subtractUnsigned(b);  // this-=b
    return *this;
}

BigInt10 BigInt10::operator-(const BigInt10 &b) const
{
    BigInt10 c(*this);
    c -= b;
    return c;
}

BigInt10 &BigInt10::operator*=(const BigInt10 &b)
{
    *this = karatzubaMultiply(*this, b);
    return *this;
}

BigInt10 BigInt10::operator*(const BigInt10 &b) const
{
    BigInt10 c(*this);
    c *= b;
    return c;
}

BigInt10 &BigInt10::operator/=(const BigInt10 &b)
{
    BigInt10 remainder;
    *this = longDivision(*this, b, remainder);
    return *this;
}

BigInt10 BigInt10::operator/(const BigInt10 &b) const
{
    BigInt10 c(*this);
    c /= b;
    return c;
}

BigInt10 &BigInt10::operator%=(const BigInt10 &b)
{
    BigInt10 remainder;
    longDivision(*this, b, remainder);
    *this = remainder;
    return *this;
}

BigInt10 BigInt10::operator%(const BigInt10 &b) const
{
    BigInt10 c(*this);
    c %= b;
    return c;
}

BigInt10 &BigInt10::operator^=(const BigInt10 &b)
{
    *this = power(*this, b);
    return *this;
}

BigInt10 BigInt10::operator^(const BigInt10 &b) const
{
    BigInt10 c(*this);
    c ^= b;
    return c;
}

std::string BigInt10::toString() const
{
    std::ostringstream oss;
    oss << *this;
    return oss.str();
}

uint64_t BigInt10::toU64() const
{
    BigInt10 base = MAX_VAL_64;
    if (base.isSmallerThanUnsigned(*this))
        throw std::invalid_argument("this bigger than uint64");

    uint64_t result = 0;
    for (int i = limbsCount() - 1; i >= 0; i--) {
        result *= 10;
        result += limbs[i];
    }

    return result;
}

void BigInt10::removeLeadingZeros()
{
    while (limbs.size() > 1 && limbs.back() == 0)
        limbs.pop_back();
}

bool BigInt10::isZero() const
{
    return limbsCount() == 1 && limbs[0] == 0;
}

int BigInt10::limbsCount() const
{
    return limbs.size();
}

void BigInt10::insertZroes(int n)
{
    limbs.insert(limbs.begin(), n, 0);
}

bool BigInt10::isSmallerThanUnsigned(const BigInt10 &b) const
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

void BigInt10::prefixPlusPlusUnsigned()
{
    int i, n = limbsCount();
    // zero alll the MAX_VAL lsb's
    for (i = 0; i < n && limbs[i] == MAX_VAL_10; i++) {
        limbs[i] = 0;
    }

    if (i == n)
        // it was all MAX_VAL
        limbs.push_back(1);
    else
        limbs[i]++;
}

void BigInt10::prefixMinusMinusUnsigned()
{
    if (isZero())
        throw std::invalid_argument("cant --0");

    int i = 0, n = limbsCount();
    // starting zeros case 0 0 0 X
    while (i < n && limbs[i] == 0) {
        limbs[i] = MAX_VAL_10;
        i++;
    }

    limbs[i]--;  // subtruct the first valid limb
    // remove leading zero if exists
    if (limbs[i] == 0 && i != 0)
        limbs.pop_back();
}

void BigInt10::addUnsigned(const BigInt10 &b)
{
    int n = limbsCount(), m = b.limbsCount();
    uint8_t carry = 0;  //(1/0)
    uint8_t bLimb;
    if (n < m) {
        limbs.resize(m);
        n = m;
    }

    for (int i = 0; i < n; i++) {
        bLimb = i < m ? b.limbs[i] : 0;
        adder3_10(limbs[i], bLimb, carry, limbs[i], carry);
    }

    if (carry == 1)
        limbs.push_back(carry);
}

void BigInt10::subtractUnsigned(const BigInt10 &b)
{
    if (this->isSmallerThanUnsigned(b))
        // make sure this>=b;
        throw std::invalid_argument("cant -: this < b");

    int n = limbsCount(), m = b.limbsCount();
    int borrow = 0;  //(1/0)
    uint8_t bLimb;

    for (int i = 0; i < n; i++) {
        bLimb = i < m ? b.limbs[i] : 0;
        if ((borrow == 1 && limbs[i] == 0) || (limbs[i] - borrow < bLimb)) {
            // need to borrow from next limb
            limbs[i] = limbs[i] + (bLimb == 0 ? 10 : toBase10(bLimb)) - borrow;
            borrow = 1;
        }
        else {
            limbs[i] = limbs[i] - bLimb - borrow;
            borrow = 0;
        }
    }

    removeLeadingZeros();
}

BigInt10 longMultiplication(const BigInt10 &a, const BigInt10 &b)
{
    if (a.isZero() || b.isZero())
        return BigInt10();

    int n = a.limbsCount(), m = b.limbsCount();
    std::vector<uint8_t> result(n + m, 0);
    uint8_t high, low, carry;

    for (int i = 0; i < n; i++) {
        carry = 0;
        for (int j = 0; j < m; j++) {
            mul2Limbs10(a.limbs[i], b.limbs[j], high, low);
            adder3_10(low, result[i + j], carry, result[i + j], carry);
            carry = high + carry;
        }

        // Handle any remaining carry after the inner loop
        result[i + m] = carry;
    }

    BigInt10 res;
    res.limbs = std::move(result);
    res.removeLeadingZeros();  // Remove leading zeros
    res.isNegative = a.isNegative != b.isNegative;
    return res;
}

BigInt10 longDivision(const BigInt10 &a, const BigInt10 &b, BigInt10 &remainder)
{
    if (b.isZero())
        throw std::invalid_argument("Invalid input: non-digit character");

    remainder.isNegative = false;
    if (a.isSmallerThanUnsigned(b)) {
        remainder.limbs = a.limbs;
        return BigInt10();
    }

    remainder.limbs.clear();
    std::vector<uint8_t> quotient;

    for (int i = a.limbsCount() - 1; i >= 0; i--) {  // msb-lsb
        remainder.limbs.insert(remainder.limbs.begin(),
                               a.limbs[i]);  // insert msb as lsb
        if (remainder.limbsCount() > 1 && remainder.limbs.back() == 0)
            remainder.limbs.pop_back();  // remove 1 leading zero
        int times = 0;
        if (!remainder.isSmallerThanUnsigned(b)) {
            int left = 1, right = 9;
            while (left <= right) {
                int mid = left + (right - left) / 2;
                if (!remainder.isSmallerThanUnsigned(
                        b * mid)) {  // b*times<=remainder
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
    BigInt10 quoti(a.isNegative != b.isNegative);
    quoti.limbs = std::move(quotient);
    return quoti;
}

BigInt10 power(BigInt10 base, BigInt10 exponent)
{
    if (exponent.isNegative)
        throw std::invalid_argument("Invalid input: negative exponent");

    BigInt10 result(1);
    while (!exponent.isZero()) {
        if (exponent.limbs[0] & 1) {
            result *= base;
        }

        base *= base;
        exponent /= 2;
    }

    return result;
}

void BigInt10::initFromString(const char *str, int n)
{
    isNegative = str[0] == '-';
    limbs.reserve(n);
    for (int i = n - 1; i >= isNegative; i--) {
        uint8_t digit = str[i] - '0';
        if (!isDigit10(digit))
            throw std::invalid_argument("Invalid input: non-digit character");

        limbs.push_back(digit);
    }
}

std::ostream &operator<<(std::ostream &out, const BigInt10 &a)
{
    if (a.isNegative)
        out << '-';
    for (int i = a.limbsCount() - 1; i >= 0; i--)
        out << static_cast<int>(a.limbs[i]);
    return out;
}

BigInt10 modularExponentiation(BigInt10 base, BigInt10 exponent,
                               const BigInt10 &modulus)
{
    BigInt10 res(1);
    base %= modulus;
    while (!exponent.isZero()) {
        if (exponent.limbs[0] & 1)
            res = (res * base) % modulus;
        res = (res * res) % modulus;
        exponent /= 2;
    }

    return res;
}

BigInt10 gcd(BigInt10 a, BigInt10 b)
{
    while (!b.isZero()) {
        BigInt10 copyB = b;
        b = a % b;
        a = copyB;
    }

    return a;
}

BigInt10 karatzubaMultiply(const BigInt10 &a, const BigInt10 &b)
{
    int n = a.limbsCount(), m = b.limbsCount();
    if (n == 1 || m == 1)
        return longMultiplication(a, b);

    const BigInt10 *longerX, *shorterY;
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
    BigInt10 xM, xL, yL, yM;
    xM.limbs.reserve(xLen - xLsbHalf);
    xL.limbs.reserve(xLsbHalf);
    yM.limbs.reserve(yLen - yLsbHalf);
    yL.limbs.reserve(yLsbHalf);
    // M L
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

    BigInt10 sum4Mult = karatzubaMultiply(xL + xM, yL + yM);
    BigInt10 xyL = karatzubaMultiply(xL, yL);
    BigInt10 xyM = karatzubaMultiply(xM, yM);
    BigInt10 xLyM_xMyL = sum4Mult - xyL - xyM;
    xyM.insertZroes(xLsbHalf * 2);
    xLyM_xMyL.insertZroes(xLsbHalf);
    BigInt10 res = xyM + xLyM_xMyL + xyL;
    res.isNegative = a.isNegative != b.isNegative;
    return res;
}