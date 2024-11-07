#include "../include/sha256.h"
#include <cstring>

#ifdef USE_SYCL
#include <CL/sycl.hpp>
using namespace sycl;
#endif  //USE_SYCL
using namespace std;

// Constants used in SHA-256 processing
#define CHOOSE(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJORITY(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))
#define SIGMA0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define SIGMA1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define GAMMA0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define GAMMA1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))
/**
 * SHA256 constructor initializes the hash values with SHA-256 specific constants.
 * Sets the initial message size and bit length to 0.
 */
SHA256::SHA256()
{
    result[0] = 0x6a09e667;
    result[1] = 0xbb67ae85;
    result[2] = 0x3c6ef372;
    result[3] = 0xa54ff53a;
    result[4] = 0x510e527f;
    result[5] = 0x9b05688c;
    result[6] = 0x1f83d9ab;
    result[7] = 0x5be0cd19;
    messageSize = 0;
    bitLength = 0;
}
/**
 * Updates the SHA-256 hash with the provided data.
 * Processes data in 64-byte chunks, calling `transform` for each chunk.
 *
 * @param data A vector of bytes to be added to the hash.
 */
CK_RV SHA256::update(const std::vector<uint8_t> &data)
{
    log(logger::LogLevel::DEBUG, "Updating SHA-256 with data.");

    // Get the size of the input data
    size_t length = data.size();

    // Process the input data byte by byte
    for (size_t i = 0; i < length; i++) {
        message[messageSize++] = static_cast<uint8_t>(data[i]);

        // If the message buffer is full (64 bytes), apply the SHA-256 transform
        if (messageSize == 64) {
            CK_RV transform_status = transform();
            if (transform_status != CKR_OK) {
                log(logger::LogLevel::ERROR,
                    "Transform failed during SHA-256 update.");
                return transform_status;  // Return the error code from the transform function
            }

            // Reset the message size and increment the bit length
            messageSize = 0;
            bitLength += 512;
        }
    }
    return CKR_OK;  // Return success if everything goes well
}

/**
 * Adds padding to the message and appends the length of the original message.
 * The message is padded so its length is congruent to 56 modulo 64.
 */
void SHA256::padding()
{
    log(logger::LogLevel::DEBUG,
        "Padding the message and appending its length to make it congruent to "
        "56 mod 64.");

    uint64_t currentLength = messageSize;
    uint8_t paddingEnd = currentLength < 56 ? 56 : 64;

    // Append the 0x80 byte (0b10000000)
    message[currentLength++] = 0x80;

    // Pad with 0x00 bytes until the length of the message is 56 bytes mod 64
    memset(message + currentLength, 0, paddingEnd - currentLength);
    currentLength = paddingEnd;

    // If message length is >= 56, process the current block and reset for new padding
    if (messageSize >= 56) {
        transform();
        memset(message, 0, 56);
        currentLength = 56;
    }

    // Append the length of the original message in bits (64-bit big-endian)
    bitLength += messageSize * 8;
    for (int i = 0; i < 8; i++) {
        message[63 - i] = bitLength >> (i * 8);
    }
    transform();
}

#ifdef USE_SYCL

/**
 * Transforms the message block by applying SHA-256 compression.
 * This function runs in parallel using SYCL if the USE_SYCL flag is enabled.
 *
 * The function computes the message schedule array (`temp`) and then
 * updates the hash state by processing the message in 64 rounds.
 */
CK_RV SHA256::transform()
{
    log(logger::LogLevel::DEBUG,
        "Transforming message block and updating hash state using 64 rounds of "
        "SHA-256 compression.");
    uint32_t temp[64];
    queue q;

    // Check if message size is correct
    if (messageSize != 64) {
        log(logger::LogLevel::ERROR, "Message size is not 64 bytes.");
        return CKR_FUNCTION_FAILED;  // Return an error code if the message size is incorrect
    }

    // Initialize the first 16 elements of temp with the message schedule
    for (uint8_t i = 0, j = 0; i < 16; i++, j += 4)
        temp[i] = (message[j] << 24) | (message[j + 1] << 16) |
                  (message[j + 2] << 8) | (message[j + 3]);

    for (uint8_t k = 16; k < 64; k++)
        temp[k] = GAMMA1(temp[k - 2]) + temp[k - 7] + GAMMA0(temp[k - 15]) +
                  temp[k - 16];

    // Save the current state
    uint32_t s[8];
    for (uint8_t i = 0; i < 8; i++)
        s[i] = result[i];

    for (size_t i = 0; i < 64; i++) {
        uint32_t choose, sum, majority, newA, newE;

        choose = CHOOSE(s[4], s[5], s[6]);
        majority = MAJORITY(s[0], s[1], s[2]);
        sum = temp[i] + bytes[i] + s[7] + choose + SIGMA1(s[4]);
        newA = SIGMA0(s[0]) + majority + sum;
        newE = s[3] + sum;

        s[7] = s[6];
        s[6] = s[5];
        s[5] = s[4];
        s[4] = newE;
        s[3] = s[2];
        s[2] = s[1];
        s[1] = s[0];
        s[0] = newA;
    }
    // Process the message in 64-byte chunks, parallelizing where feasible
    {
        buffer<uint32_t, 1> state_buf(s, range<1>(8));
        buffer<uint32_t, 1> result_buf(result, range<1>(8));

        // Update the result with the state
        q.submit([&](handler &h) {
             auto state_acc = state_buf.get_access<access::mode::read>(h);
             auto result_acc =
                 result_buf.get_access<access::mode::read_write>(h);

             h.parallel_for(range<1>(8), [=](id<1> idx) {
                 result_acc[idx] += state_acc[idx];
             });
         }).wait();
    }
    return CKR_OK;
}

/**
 * Finalizes the SHA-256 hash computation.
 * Applies padding and appends the length of the original message.
 * Returns the final hash as a vector of bytes.
 *
 * @param state The SHA256State object to finalize.
 * @return A vector containing the SHA-256 hash value.
 */
CK_RV SHA256::finalize(std::vector<uint8_t> &output)
{
    log(logger::LogLevel::DEBUG,
        "Finalizing SHA-256 hash computation and returning the hash value.");

    try {
        // Perform padding
        padding();

        // SHA-256 hash size is 32 bytes (256 bits)
        std::vector<uint8_t> hash(32);

        // Define SYCL buffers
        sycl::buffer<uint32_t, 1> result_buf(result, sycl::range<1>(8));
        sycl::buffer<uint8_t, 1> hash_buf(hash.data(), sycl::range<1>(32));

        // Submit SYCL command group
        sycl::queue q;
        q.submit([&](sycl::handler &h) {
             auto result_acc =
                 result_buf.get_access<sycl::access::mode::read>(h);
             auto hash_acc = hash_buf.get_access<sycl::access::mode::write>(h);
             h.parallel_for(sycl::range<1>(8), [=](sycl::id<1> idx) {
                 size_t i = idx[0];
                 hash_acc[i * 4 + 0] = (result_acc[i] >> 24) & 0xff;
                 hash_acc[i * 4 + 1] = (result_acc[i] >> 16) & 0xff;
                 hash_acc[i * 4 + 2] = (result_acc[i] >> 8) & 0xff;
                 hash_acc[i * 4 + 3] = (result_acc[i] >> 0) & 0xff;
             });
         }).wait();

        // Copy the hash to the output vector
        output = hash;

        return CKR_OK;  // Return success
    }
    catch (const sycl::exception &e) {
        // Handle SYCL exceptions
        log(logger::LogLevel::ERROR, "SYCL error: " + std::string(e.what()));
        return CKR_FUNCTION_FAILED;
    }
    catch (const std::exception &e) {
        // Handle other exceptions
        log(logger::LogLevel::ERROR,
            "Standard error: " + std::string(e.what()));
        return CKR_FUNCTION_FAILED;
    }
}

#else

/**
 * Processes a 64-byte block of the message and updates the hash state.
 * Applies the SHA-256 compression function to the current block.
 */
CK_RV SHA256::transform()
{
    log(logger::LogLevel::DEBUG,
        "Transforming message block and updating hash state using 64 rounds of "
        "SHA-256 compression.");

    uint32_t temp[64];

    // Initialize temp array with message data
    for (uint8_t i = 0, j = 0; i < 16; i++, j += 4)
        temp[i] = (message[j] << 24) | (message[j + 1] << 16) |
                  (message[j + 2] << 8) | (message[j + 3]);

    // Compute remaining values for temp array
    for (uint8_t k = 16; k < 64; k++)
        temp[k] = GAMMA1(temp[k - 2]) + temp[k - 7] + GAMMA0(temp[k - 15]) +
                  temp[k - 16];

    // Initialize working variables
    uint32_t a, b, c, d, e, f, g, h;
    a = result[0];
    b = result[1];
    c = result[2];
    d = result[3];
    e = result[4];
    f = result[5];
    g = result[6];
    h = result[7];

    // Perform the 64 rounds of SHA-256 compression
    for (size_t i = 0; i < 64; i++) {
        uint32_t temp1 = h + SIGMA1(e) + CHOOSE(e, f, g) + bytes[i] + temp[i];
        uint32_t temp2 = SIGMA0(a) + MAJORITY(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // Update result with compressed values
    result[0] += a;
    result[1] += b;
    result[2] += c;
    result[3] += d;
    result[4] += e;
    result[5] += f;
    result[6] += g;
    result[7] += h;

    return CKR_OK;  // Return success if no errors occurred
}

/**
 * Finalizes the SHA-256 hash computation.
 * Applies padding and appends the length of the original message.
 * Returns the final hash as a vector of bytes.
 *
 * @return A vector containing the SHA-256 hash value.
 */
CK_RV SHA256::finalize(std::vector<uint8_t> &output)
{
    log(logger::LogLevel::DEBUG, "Finalizing SHA-256 hash computation.");

    // Check if the internal state is valid
    if (result == nullptr) {
        log(logger::LogLevel::ERROR,
            "SHA-256 computation has not been initialized or has failed.");
        return CKR_FUNCTION_FAILED;
    }

    try {
        // Apply padding to the data
        padding();
    }
    catch (const std::exception &e) {
        log(logger::LogLevel::ERROR,
            std::string("Padding failed: ") + e.what());
        return CKR_FUNCTION_FAILED;
    }

    // Ensure the output vector has the correct size
    if (output.size() != 32) {
        output.resize(32);
    }

    for (size_t i = 0; i < 8; i++) {
        output[i * 4 + 0] = (result[i] >> 24) & 0xFF;
        output[i * 4 + 1] = (result[i] >> 16) & 0xFF;
        output[i * 4 + 2] = (result[i] >> 8) & 0xFF;
        output[i * 4 + 3] = (result[i]) & 0xFF;
    }

    return CKR_OK;
}

#endif  //USE_SYCL