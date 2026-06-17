#ifndef __PROGTEST__
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>
#include <memory>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

#endif /* __PROGTEST__ */

int findHash (const uint8_t prefix[], const unsigned int prefixBitLen, std::unique_ptr<uint8_t[]>& outputMessage, size_t& outputMessageLen, std::unique_ptr<uint8_t[]>& outputHash, size_t& outputHashLen, const char hashName[] = "sha256"){

    // TODO: Remove this condition if you are aiming for 3 points.
    // if(hashName == nullptr || strcmp(hashName, "sha256") != 0) return EXIT_FAILURE;

    /* TODO: Your code here */
    const EVP_MD* alghoritm = EVP_get_digestbyname(hashName);
    if (alghoritm == nullptr || (prefix == nullptr && prefixBitLen > 0)) return EXIT_FAILURE;
    auto alg_size = EVP_MD_size(alghoritm);
    if (int(prefixBitLen) > 8 * alg_size) return EXIT_FAILURE;

    auto ctx =EVP_MD_CTX_new();
    auto output_hash = std::make_unique<uint8_t[]>(alg_size);

    uint8_t message[32];
    RAND_bytes(message, 32);

    if(prefix == nullptr) {
        EVP_DigestInit_ex(ctx, alghoritm, nullptr);
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

    EVP_MD_CTX* base_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(base_ctx, alghoritm, nullptr);

    uint64_t counter = 0;
    while(1) {
        counter++;
        EVP_MD_CTX_copy_ex(ctx, base_ctx);
        EVP_DigestUpdate(ctx, &counter, sizeof(counter));
        unsigned int size;
        EVP_DigestFinal_ex(ctx, output_hash.get(), &size);
        
        for(unsigned int i = 0; 1; i++) {
            if ( 8*i >= prefixBitLen) {
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
            uint8_t bitMask;
            if(8*(i+1) <= prefixBitLen) {
                bitMask = 0xFF;
            }
            else {
                bitMask = 0xFF << (8 - (prefixBitLen - 8*i));
            }

            if((output_hash[i] & bitMask) != (prefix[i] & bitMask)) {
                break;
            }
        }
    }
}

#ifndef __PROGTEST__

int checkHash(const uint8_t prefix[], const unsigned int prefixBitLen, const std::unique_ptr<uint8_t[]>& outputHash) {
    // TODO: implement if needed
    return EXIT_SUCCESS;
}


int main (void) {
    size_t outputMessageLen, outputHashLen;
    // BASIC TEST
    {
        std::unique_ptr<uint8_t[]> outputMessage, outputHash;
        assert(EXIT_SUCCESS == findHash(nullptr, 0, outputMessage, outputMessageLen, outputHash, outputHashLen));
        assert(outputHashLen == 32);
        //Check if the outputHash is correct for the outputMessage.
        //For instance, in CMD: "echo abcdef | xxd -r -ps | openssl sha256", where "abcdef" is a hexadecimal message
    }

    {
        std::unique_ptr<uint8_t[]> outputMessage, outputHash;
        uint8_t prefix[] = {0x12};
        assert(EXIT_SUCCESS == findHash(prefix, 8, outputMessage, outputMessageLen, outputHash, outputHashLen));
        assert(EXIT_SUCCESS == checkHash(prefix, 8, outputHash));
    }

    {
        std::unique_ptr<uint8_t[]> outputMessage, outputHash;
        uint8_t prefix[] = {0x12, 0x30};
        assert(EXIT_SUCCESS == findHash(prefix, 12, outputMessage, outputMessageLen, outputHash, outputHashLen));
        assert(EXIT_SUCCESS == checkHash(prefix, 12, outputHash));
    }

    // INVALID INPUT TEST
    {
        std::unique_ptr<uint8_t[]> outputMessage, outputHash;
        uint8_t prefix[] = {0x12, 0x30};
        assert(EXIT_FAILURE == findHash(nullptr, 10, outputMessage, outputMessageLen, outputHash, outputHashLen));
        assert(EXIT_FAILURE == findHash(prefix, 1000, outputMessage, outputMessageLen, outputHash, outputHashLen));
        assert(EXIT_FAILURE == findHash(prefix, 10, outputMessage, outputMessageLen, outputHash, outputHashLen, nullptr));
    }

    // BASIC TEST FOR 3 POINTS
    {
        std::unique_ptr<uint8_t[]> outputMessage, outputHash;
        uint8_t prefix[] = {0x12, 0x34};
        assert(EXIT_SUCCESS == findHash(prefix, 15, outputMessage, outputMessageLen, outputHash, outputHashLen, "sha384"));
        assert(EXIT_SUCCESS == checkHash(prefix, 15, outputHash));
    }

    return EXIT_SUCCESS;
}
#endif /* __PROGTEST__ */