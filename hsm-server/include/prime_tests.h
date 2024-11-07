#ifndef __PRIME_TESTS_H__
#define __PRIME_TESTS_H__
#include "big_int64.h"
#include "../logger/logger.h"

bool millerRabinPrimalityTest(const BigInt64 &number, size_t k);
bool fermatPrimalityTest(const BigInt64 &number, size_t k);
bool isDivisibleBySmallPrimes(const BigInt64 &n);
BigInt64 nextPrimeSequential(const BigInt64 &number, size_t k);
BigInt64 nextPrimeDivideToChunks(const BigInt64 &number, size_t k);

#ifdef USE_SYCL
#include <sycl/sycl.hpp>
bool isDivisibleBySmallPrimesUSM(sycl::queue &q, const BigInt64 &n);
bool isDivisibleBySmallPrimesBuffers(sycl::queue &q, const BigInt64 &n);
bool millerRabinPrimalityTestUSM(sycl::queue &q, const BigInt64 &number,
                                 size_t k);
bool millerRabinPrimalityTestBuffers(sycl::queue &q, const BigInt64 &number,
                                     size_t k);
#else

bool millerRabinPrimalityTestThreads(const BigInt64 &number, size_t k);

#endif
#endif  // __PRIME_TESTS_H__