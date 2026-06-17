/**
 * Hash prefix brute-force search using OpenSSL EVP digest API.
 * Finds a message whose hash starts with a given bit prefix.
 * Supports any OpenSSL digest algorithm (sha256, sha384, ...).
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <string>
#include <vector>
#include <memory>

#include <openssl/evp.h>
#include <openssl/rand.h>

int findHash (
    const uint8_t prefix[],
    const unsigned int prefixBitLen,
    std::unique_ptr<uint8_t[]>& outputMessage,
    size_t& outputMessageLen,
    std::unique_ptr<uint8_t[]>& outputHash,
    size_t& outputHashLen,
    const char hashName[] = "sha256"
) {
    // Validate inputs
    const EVP_MD* algorithm = EVP_get_digestbyname(hashName);
    if (algorithm == nullptr || (prefix == nullptr && prefixBitLen > 0)) return EXIT_FAILURE;

    int alg_size = EVP_MD_size(algorithm);
    if (int(prefixBitLen) > 8 * alg_size) return EXIT_FAILURE;

    auto ctx = EVP_MD_CTX_new();
    auto output_hash = std::make_unique<uint8_t[]>(alg_size);

    // If no prefix required, just hash a random message and return
    if (prefix == nullptr) {
        uint8_t message[32];
        RAND_bytes(message, 32);

        EVP_DigestInit_ex(ctx, algorithm, nullptr);
        EVP_DigestUpdate(ctx, message, 32);
        unsigned int size;
        EVP_DigestFinal_ex(ctx, output_hash.get(), &size);

        outputMessage = std::make_unique<uint8_t[]>(32);
        memcpy(outputMessage.get(), message, 32);
        outputMessageLen = 32;
        outputHash = std::make_unique<uint8_t[]>(size);
        memcpy(outputHash.get(), output_hash.get(), size);
        outputHashLen = size;
        EVP_MD_CTX_free(ctx);
        return EXIT_SUCCESS;
    }

    // Pre-initialize base context once and copy it each iteration
    // (faster than calling DigestInit on every counter value)
    EVP_MD_CTX* base_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(base_ctx, algorithm, nullptr);

    uint64_t counter = 0;
    while (1) {
        counter++;

        // Copy base context and hash the current counter value
        EVP_MD_CTX_copy_ex(ctx, base_ctx);
        EVP_DigestUpdate(ctx, &counter, sizeof(counter));
        unsigned int size;
        EVP_DigestFinal_ex(ctx, output_hash.get(), &size);

        // Check if hash matches the required bit prefix
        for (unsigned int i = 0; ; i++) {
            if (8 * i >= prefixBitLen) {
                // All prefix bits matched — return this counter as the message
                outputMessage = std::make_unique<uint8_t[]>(sizeof(counter));
                memcpy(outputMessage.get(), &counter, sizeof(counter));
                outputMessageLen = sizeof(counter);
                outputHash = std::make_unique<uint8_t[]>(size);
                memcpy(outputHash.get(), output_hash.get(), size);
                outputHashLen = size;
                EVP_MD_CTX_free(base_ctx);
                EVP_MD_CTX_free(ctx);
                return EXIT_SUCCESS;
            }

            // Build bitmask for the current byte (handle partial last byte)
            uint8_t bitMask = (8 * (i + 1) <= prefixBitLen)
                ? 0xFF
                : (0xFF << (8 - (prefixBitLen - 8 * i)));

            if ((output_hash[i] & bitMask) != (prefix[i] & bitMask)) break;
        }
    }
}

int main (void) {
    size_t outputMessageLen, outputHashLen;

    // No prefix — just return any hash
    {
        std::unique_ptr<uint8_t[]> outputMessage, outputHash;
        assert(EXIT_SUCCESS == findHash(nullptr, 0, outputMessage, outputMessageLen, outputHash, outputHashLen));
        assert(outputHashLen == 32);
    }

    // 8-bit prefix
    {
        std::unique_ptr<uint8_t[]> outputMessage, outputHash;
        uint8_t prefix[] = {0x12};
        assert(EXIT_SUCCESS == findHash(prefix, 8, outputMessage, outputMessageLen, outputHash, outputHashLen));
    }

    // 12-bit prefix
    {
        std::unique_ptr<uint8_t[]> outputMessage, outputHash;
        uint8_t prefix[] = {0x12, 0x30};
        assert(EXIT_SUCCESS == findHash(prefix, 12, outputMessage, outputMessageLen, outputHash, outputHashLen));
    }

    // Invalid inputs
    {
        std::unique_ptr<uint8_t[]> outputMessage, outputHash;
        uint8_t prefix[] = {0x12, 0x30};
        assert(EXIT_FAILURE == findHash(nullptr, 10, outputMessage, outputMessageLen, outputHash, outputHashLen));
        assert(EXIT_FAILURE == findHash(prefix, 1000, outputMessage, outputMessageLen, outputHash, outputHashLen));
        assert(EXIT_FAILURE == findHash(prefix, 10, outputMessage, outputMessageLen, outputHash, outputHashLen, nullptr));
    }

    // SHA-384 with 15-bit prefix
    {
        std::unique_ptr<uint8_t[]> outputMessage, outputHash;
        uint8_t prefix[] = {0x12, 0x34};
        assert(EXIT_SUCCESS == findHash(prefix, 15, outputMessage, outputMessageLen, outputHash, outputHashLen, "sha384"));
    }

    return EXIT_SUCCESS;
}
