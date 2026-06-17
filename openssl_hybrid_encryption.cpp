/**
 * Hybrid file encryption using RSA + symmetric cipher (OpenSSL EVP API).
 *
 * seal(): encrypts a file with a randomly generated symmetric key,
 *         then wraps that key using the recipient's RSA public key.
 *         Output format: [cipher NID | ek length | encrypted key | IV | ciphertext]
 *
 * open(): reads the encrypted key from the file header, unwraps it
 *         using the RSA private key, and decrypts the file content.
 */

#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <iostream>
#include <string>
#include <memory>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

int seal( const std::string & inFile, const std::string & outFile,
          const std::string & publicKeyFile, const std::string & symmetricCipher )
{
    // Load cipher and public key
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(symmetricCipher.c_str());
    if (!cipher) return EXIT_FAILURE;

    FILE* f = fopen(publicKeyFile.c_str(), "r");
    if (!f) return EXIT_FAILURE;
    EVP_PKEY* pubkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!pubkey) return EXIT_FAILURE;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { EVP_PKEY_free(pubkey); return EXIT_FAILURE; }

    // EVP_SealInit generates a random symmetric key, encrypts it with RSA public key,
    // and initializes the cipher context
    unsigned char* ek = new unsigned char[EVP_PKEY_size(pubkey)];
    int eklen;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    EVP_PKEY* pubkeys[1] = { pubkey };

    if (EVP_SealInit(ctx, cipher, &ek, &eklen, iv, pubkeys, 1) != 1) {
        delete[] ek; EVP_PKEY_free(pubkey); EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    FILE* out = fopen(outFile.c_str(), "wb");
    if (!out) {
        delete[] ek; EVP_PKEY_free(pubkey); EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // Write header: cipher NID, encrypted key length, encrypted key, IV
    int nid   = EVP_CIPHER_nid(cipher);
    int ivlen = EVP_CIPHER_iv_length(cipher);
    fwrite(&nid,   sizeof(int), 1,     out);
    fwrite(&eklen, sizeof(int), 1,     out);
    fwrite(ek,     1,           eklen, out);
    fwrite(iv,     1,           ivlen, out);

    FILE* in = fopen(inFile.c_str(), "rb");
    if (!in) {
        fclose(out); remove(outFile.c_str());
        delete[] ek; EVP_PKEY_free(pubkey); EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // Encrypt file content in chunks
    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int outlen, nread;

    while ((nread = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (EVP_SealUpdate(ctx, outbuf, &outlen, inbuf, nread) != 1) {
            fclose(in); fclose(out); remove(outFile.c_str());
            delete[] ek; EVP_PKEY_free(pubkey); EVP_CIPHER_CTX_free(ctx);
            return EXIT_FAILURE;
        }
        fwrite(outbuf, 1, outlen, out);
    }

    // Flush final padded block
    if (EVP_SealFinal(ctx, outbuf, &outlen) != 1) {
        fclose(in); fclose(out); remove(outFile.c_str());
        delete[] ek; EVP_PKEY_free(pubkey); EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    fwrite(outbuf, 1, outlen, out);

    fclose(in); fclose(out);
    delete[] ek; EVP_PKEY_free(pubkey); EVP_CIPHER_CTX_free(ctx);
    return EXIT_SUCCESS;
}

int open( const std::string & inFile, const std::string & outFile,
          const std::string & privateKeyFile )
{
    // Load private key
    FILE* f = fopen(privateKeyFile.c_str(), "r");
    if (!f) return EXIT_FAILURE;
    EVP_PKEY* privkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!privkey) return EXIT_FAILURE;

    FILE* in = fopen(inFile.c_str(), "rb");
    if (!in) { EVP_PKEY_free(privkey); return EXIT_FAILURE; }

    // Read header: cipher NID, encrypted key length, encrypted key, IV
    int nid, eklen;
    fread(&nid,   sizeof(int), 1, in);
    fread(&eklen, sizeof(int), 1, in);

    const EVP_CIPHER* cipher = EVP_get_cipherbynid(nid);
    if (!cipher) { fclose(in); EVP_PKEY_free(privkey); return EXIT_FAILURE; }

    unsigned char* ek = new unsigned char[eklen];
    fread(ek, 1, eklen, in);

    int ivlen = EVP_CIPHER_iv_length(cipher);
    unsigned char iv[EVP_MAX_IV_LENGTH];
    fread(iv, 1, ivlen, in);

    // EVP_OpenInit unwraps the symmetric key using RSA private key
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { delete[] ek; fclose(in); EVP_PKEY_free(privkey); return EXIT_FAILURE; }

    if (EVP_OpenInit(ctx, cipher, ek, eklen, iv, privkey) != 1) {
        delete[] ek; fclose(in); EVP_PKEY_free(privkey); EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    FILE* out = fopen(outFile.c_str(), "wb");
    if (!out) {
        delete[] ek; fclose(in); EVP_PKEY_free(privkey); EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // Decrypt file content in chunks
    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int outlen, nread;

    while ((nread = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (EVP_OpenUpdate(ctx, outbuf, &outlen, inbuf, nread) != 1) {
            fclose(in); fclose(out); remove(outFile.c_str());
            delete[] ek; EVP_PKEY_free(privkey); EVP_CIPHER_CTX_free(ctx);
            return EXIT_FAILURE;
        }
        fwrite(outbuf, 1, outlen, out);
    }

    // Finalize and strip padding
    if (EVP_OpenFinal(ctx, outbuf, &outlen) != 1) {
        fclose(in); fclose(out); remove(outFile.c_str());
        delete[] ek; EVP_PKEY_free(privkey); EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    fwrite(outbuf, 1, outlen, out);

    fclose(in); fclose(out);
    delete[] ek; EVP_PKEY_free(privkey); EVP_CIPHER_CTX_free(ctx);
    return EXIT_SUCCESS;
}

int main ( void )
{
    assert(EXIT_SUCCESS == seal("sample_plaintext.txt", "sealed.bin", "PublicKey.pem", "aes-128-cbc"));
    assert(EXIT_SUCCESS == open("sealed.bin", "opened.bin", "PrivateKey.pem"));
    assert(EXIT_SUCCESS == open("sample_ciphertext.bin", "opened.bin", "PrivateKey.pem"));
    return 0;
}
