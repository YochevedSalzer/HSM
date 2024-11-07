#include "../include/SHA3-512.h"
#include "../logger/logger.h"
#include <cstddef>
#include <cstring>
#include <iomanip>
#include <vector>

#define BLOCK_SIZE 72
// Macro for circular left shift (rotation) of x by y bits
#define ROT(x, y) (((x) << (y)) | ((x) >> ((64) - (y))))

// constants representing the rotation values for the Keccak-f permutation based
// on the (x, y) position
const uint64_t r[5][5] = {{0, 36, 3, 41, 18},
                          {1, 44, 10, 45, 2},
                          {62, 6, 43, 15, 61},
                          {28, 55, 25, 21, 56},
                          {27, 20, 39, 8, 14}};

// Round constants used in the Keccak-f permutation
static const uint64_t RC[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

/**
 * @brief Constructor to initialize the SHA3_512 object.
 *
 * This constructor initializes the internal state and buffer of the SHA3-512
 * object to zero. It also logs the initialization process.
 *
 * @note The logger is initialized to log messages related to the SHA3-512
 * algorithm.
 */
SHA3_512::SHA3_512()
{
    log(logger::LogLevel::INFO, "SHA3-512: Initializing...");
    std::memset(S, 0, sizeof(S));            // Clear state
    std::memset(buffer, 0, sizeof(buffer));  // Clear buffer
    buffer_length = 0;                       // Reset buffer length
}

/**
 * @brief Perform one round of the Keccak-f permutation.
 *
 * This function executes a single round of the Keccak-f permutation, which
 * includes the θ, ρ, π, χ, and ι steps. The state matrix is updated with
 * new values based on these transformations, and the round constant is applied.
 *
 * @param A The state matrix to be updated.
 * @param RC The round constant for the current round.
 *
 * @note This function logs the start and completion of the round operation.
 */
void SHA3_512::round(uint64_t A[5][5], uint64_t RC)
{
    uint64_t C[5];
    for (int x = 0; x < 5; x++)
        C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4];

    uint64_t D[5];
    for (int x = 0; x < 5; x++)
        D[x] = C[(x + 4) % 5] ^ ROT(C[(x + 1) % 5], 1);

    // Update state matrix A with D values
    for (int x = 0; x < 5; x++)
        for (int y = 0; y < 5; y++)
            A[x][y] = A[x][y] ^ D[x];

    // ρ & π steps: Perform rotation and permutation
    uint64_t B[5][5];
    for (int x = 0; x < 5; x++)
        for (int y = 0; y < 5; y++)
            B[y][(2 * x + 3 * y) % 5] = ROT(A[x][y], r[x][y]);

    // χ step: Apply the χ transformation
    for (int x = 0; x < 5; x++)
        for (int y = 0; y < 5; y++)
            A[x][y] = B[x][y] ^ ((~(B[(x + 1) % 5][y])) & B[(x + 2) % 5][y]);

    // ι step: Apply the round constant
    A[0][0] = A[0][0] ^ RC;
}

/**
 * @brief Perform the Keccak-f permutation for 24 rounds.
 *
 * This function applies the Keccak-f permutation to the state matrix `A` for a
 * total of 24 rounds. It iteratively calls the `round` function with the
 * appropriate round constant from the `RC` array.
 *
 * @param A The state matrix to be permuted. This 5x5 matrix undergoes multiple
 * transformations as defined by the Keccak-f permutation.
 *
 * @note This function logs the start and completion of the permutation process.
 */
void SHA3_512::f_function(uint64_t A[5][5])
{
    log(logger::LogLevel::DEBUG, "SHA3-512: Starting f_function.");

    for (int i = 0; i < 24; i++)
        round(A, RC[i]);

    log(logger::LogLevel::DEBUG, "SHA3-512: Done f_function.");
}

/**
 * @brief Apply padding to the input data for the SHA3-512 algorithm.
 *
 * This function pads the input data to ensure it aligns with the block size
 * required by the SHA3-512 algorithm. Padding is done according to the SHA3-512
 * padding scheme, which involves appending specific bytes to the end of the
 * data to make its length a multiple of the block size.
 *
 * @param input A pointer to the input data array that will be padded.
 * @param in_len A reference to the size of the input data. This value will be
 * updated to reflect the length of the padded data.
 * @param absorb_times An integer reference that will be set to the number of
 * full blocks (including the padded block) after padding is applied.
 *
 * @throws std::runtime_error If padding fails due to an unexpected error.
 *
 * @note If the input data length modulo the block size is 1, a special padding
 * byte (0x86) is used. Otherwise, the general padding scheme is applied, which
 * involves adding a 0x06 byte followed by zeroes, and ending with a 0x80 byte.
 * The function logs various stages of padding and any errors encountered.
 */
void SHA3_512::padding(uint8_t input[], std::size_t &in_len, int &absorb_times)
{
    absorb_times = in_len / BLOCK_SIZE;          // Number of full blocks
    std::size_t add_last = in_len % BLOCK_SIZE;  // Remaining bytes
    log(logger::LogLevel::DEBUG,
        "SHA3-512: Remaining bytes: " + std::to_string(add_last));

    if (BLOCK_SIZE - add_last == 1) {
        log(logger::LogLevel::DEBUG,
            "SHA3-512: Padding byte for the case where only one byte is left");
        input[in_len] =
            0x86;  // Padding byte for the case where only one byte is left
    }
    else if (BLOCK_SIZE - add_last > 1) {
        log(logger::LogLevel::DEBUG, "SHA3-512: Applying general padding");
        input[in_len] = 0x06;  // Padding byte for general case
        for (int i = 1; i < (BLOCK_SIZE - 1 - add_last); i++)
            input[in_len + i] = 0x00;  // Fill with zeroes
        input[in_len + (BLOCK_SIZE - 1 - add_last)] =
            0x80;                           // Final padding byte
        in_len += (BLOCK_SIZE - add_last);  // Update length
    }
    else {
        log(logger::LogLevel::ERROR, "SHA3-512: Unexpected padding error");
        throw std::runtime_error(
            "Padding failed due to unexpected error. Remaining bytes: " +
            std::to_string(add_last));
    }

    absorb_times += 1;  // Include the final padding block
}

/**
 * @brief XOR the state matrix S with the block p.
 *
 * This function performs an XOR operation between the state matrix `S` and the
 * given block `p`. It updates the state matrix in-place with the result of the
 * XOR operation. Additionally, it logs the block data before and after the XOR
 * operation for debugging purposes.
 *
 * @param S A 5x5 matrix of 64-bit integers representing the state matrix. This
 * matrix will be updated with the XOR result.
 * @param p A pointer to an array of 64-bit integers representing the block of
 * data to XOR with the state matrix. The array is expected to have at least 25
 * elements.
 *
 * @note The function assumes that the size of the block `p` is 25 elements. It
 * logs the block data and state matrix before and after the XOR operation.
 */
void SHA3_512::assign_S_xor_p(uint64_t S[5][5], uint64_t *p)
{
    // Perform XOR of the block with the state matrix
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            int index = x + 5 * y;
            if (index < 25) {
                S[x][y] ^= p[index];
            }
        }
    }
}

/**
 * @brief Swap byte order (endianess) for a 64-bit integer.
 *
 * This function swaps the byte order of a 64-bit integer from little-endian to
 * big-endian or vice versa. It modifies the integer in place and logs its value
 * before and after the swap operation.
 *
 * @param x A reference to a 64-bit integer whose byte order is to be swapped.
 * The value will be updated to its byte-swapped equivalent.
 *
 * @note The function logs the value of `x` before and after performing the
 * endian swap for debugging purposes. Ensure that the integer is appropriately
 * sized (64-bit) for this operation.
 */
void SHA3_512::endianSwap(uint64_t &x)
{
    // Perform endian swap
    x = (x >> 56) | ((x << 40) & 0x00FF000000000000) |
        ((x << 24) & 0x0000FF0000000000) | ((x << 8) & 0x000000FF00000000) |
        ((x >> 8) & 0x00000000FF000000) | ((x >> 24) & 0x0000000000FF0000) |
        ((x >> 40) & 0x000000000000FF00) | (x << 56);
}

/**
 * @brief Convert the state matrix to a hexadecimal string.
 *
 * This function converts the state matrix `S` of the SHA3-512 algorithm into a
 * hexadecimal string representation. It serializes the matrix values in a
 * specific order, ensuring that each 64-bit integer is represented as a
 * 16-digit hexadecimal number with leading zeros if necessary.
 *
 * @param S A 5x5 matrix of 64-bit integers representing the state of the
 * SHA3-512 algorithm.
 *
 * @return A `std::string` containing the hexadecimal representation of the
 * state matrix. The string concatenates the values in a specified order: the
 * first column of each row, followed by the next rows.
 *
 * @note The function uses `std::ostringstream` to format the output and
 * `std::setw` to ensure each 64-bit integer is represented as a 16-character
 * wide hexadecimal string.
 */
std::vector<uint8_t> SHA3_512::hashPartToHexVector(uint64_t S[5][5])
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    // Append values in the specified order
    oss << std::setw(16) << S[0][0] << std::setw(16) << S[1][0] << std::setw(16)
        << S[2][0] << std::setw(16) << S[3][0] << std::setw(16) << S[4][0]
        << std::setw(16) << S[0][1] << std::setw(16) << S[1][1] << std::setw(16)
        << S[2][1];
    std::string res = oss.str();
    std::vector<uint8_t> vec;
    vec.reserve(res.size());  // Optional: reserve space for performance
    for (char c : res)
        vec.push_back(static_cast<uint8_t>(c));
    return vec;
}

/**
 * @brief Update the hash with additional data.
 *
 * This function absorbs additional data into the SHA3-512 hash computation. It
 * processes the input data in chunks and updates the internal state
 * accordingly. The data is absorbed into a buffer and, once the buffer is full,
 * the data is processed by XORing it with the current state and applying the
 * Keccak-f permutation.
 *
 * @param input A pointer to the data to be absorbed into the hash.
 * @param length The length of the data to be absorbed, in bytes.
 *
 * @return CK_RV Returns `CKR_OK` on success or `CKR_FUNCTION_FAILED` if an
 * error occurs.
 *
 * @note The buffer size used for absorption is fixed at 72 bytes. If the buffer
 * length exceeds its size, an error will be logged, and the function will
 * return `CKR_FUNCTION_FAILED`.
 */
CK_RV SHA3_512::update(const std::vector<uint8_t> &data)
{
    log(logger::LogLevel::INFO, "SHA3-512: Starting update with length: " +
                                    std::to_string(data.size()));

    // Define the input size and starting pointer
    std::size_t length = data.size();
    std::size_t data_index = 0;

    // Absorb input into the buffer and process in 72-byte chunks (576 bits)
    while (length > 0) {
        if (buffer_length > sizeof(buffer)) {
            log(logger::LogLevel::ERROR,
                "SHA3-512: Buffer length is bigger then buffer size");
            return CKR_FUNCTION_FAILED;
        }
        // Calculate the number of bytes we can copy into the buffer
        std::size_t to_copy = std::min(length, sizeof(buffer) - buffer_length);

        // Copy input data into the buffer
        std::memcpy(buffer + buffer_length, data.data(), to_copy);

        // Update buffer length and input pointers
        buffer_length += to_copy;
        data_index += to_copy;
        length -= to_copy;

        log(logger::LogLevel::DEBUG,
            "SHA3-512: Copied " + std::to_string(to_copy) +
                " bytes, remaining: " + std::to_string(length));

        // If the buffer is full, process the absorbed data
        if (buffer_length == sizeof(buffer)) {
            // Convert the buffer into a block and XOR with state
            uint64_t *block = reinterpret_cast<uint64_t *>(buffer);
            assign_S_xor_p(S, block);

            // Apply the Keccak-f function to update the state
            f_function(S);

            // Reset buffer length for the next block of data
            buffer_length = 0;
            log(logger::LogLevel::DEBUG, "SHA3-512: Processed a full block.");
        }
    }

    log(logger::LogLevel::INFO, "SHA3-512: Update completed successfully.");

    return CKR_OK;
}

/**
 * @brief Finalize the hash computation and produce the final hash value.
 *
 * This function finalizes the SHA3-512 hashing process. It handles any
 * remaining data in the buffer by applying padding, processes the data
 * including the padding, and performs necessary transformations to produce the
 * final hash value. The result is then converted to a hexadecimal string.
 *
 * @param[out] output A reference to a `std::string` that will be set to the
 * resulting hexadecimal representation of the hash value.
 *
 * @return CK_RV Returns `CKR_OK` on success or `CKR_FUNCTION_FAILED` if an
 * error occurs.
 *
 * @note The buffer is padded and processed as necessary to ensure that all
 * input data is correctly absorbed and hashed. The function also performs an
 * endian swap on the state matrix elements before converting the hash value to
 * a hexadecimal string.
 */

CK_RV SHA3_512::finalize(std::vector<uint8_t> &output)
{
    log(logger::LogLevel::INFO, "SHA3-512: Finalizing");

    // Handle remaining data in the buffer with padding
    std::size_t remaining_length = buffer_length;
    log(logger::LogLevel::DEBUG,
        "SHA3-512: Length of remaining unprocessed data: " +
            std::to_string(remaining_length));

    // Apply padding to the buffer
    int absorb_times = 0;

    try {
        padding(buffer, remaining_length,
                absorb_times);  // Call padding in try block
        log(logger::LogLevel::DEBUG,
            "SHA3-512: Number of blocks to be processed after padding: " +
                std::to_string(absorb_times));
    }
    catch (const std::exception &e) {
        // Log the exception error message
        log(logger::LogLevel::ERROR,
            "SHA3-512: Padding error: " + std::string(e.what()));
        return CKR_FUNCTION_FAILED;
    }

    // Process any remaining data including padding
    for (int i = 0; i < absorb_times; i++) {
        // Convert the buffer into a block and XOR with state
        uint64_t *block = reinterpret_cast<uint64_t *>(buffer + i * BLOCK_SIZE);
        assign_S_xor_p(S, block);

        // Apply the Keccak-f function to update the state
        f_function(S);
    }

    // Perform endianess swap for each element of the state matrix
    for (int i = 0; i < 5; i++)
        for (int j = 0; j < 5; j++)
            endianSwap(S[i][j]);

    // Convert the state to a hex string
    output = hashPartToHexVector(S);
    log(logger::LogLevel::INFO, "SHA3-512: Finalize completed successfully.");
    return CKR_OK;
}