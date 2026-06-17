#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <sys/stat.h>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>


struct crypto_config
{
	const char * m_crypto_function;
	std::unique_ptr<uint8_t[]> m_key;
	std::unique_ptr<uint8_t[]> m_IV;
	size_t m_key_len;
	size_t m_IV_len;
};

#endif

int encrypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config )
{

	if (config.m_crypto_function == nullptr ) return EXIT_FAILURE;
	auto cipher = EVP_get_cipherbyname(config.m_crypto_function);
	if (!cipher) return EXIT_FAILURE;

	size_t keyLen = EVP_CIPHER_key_length(cipher); 
	size_t ivLen = EVP_CIPHER_iv_length(cipher);

	if(config.m_key_len < keyLen || !config.m_key) {
		config.m_key = std::make_unique<uint8_t[]>(keyLen);
		RAND_bytes(config.m_key.get(), keyLen);
		config.m_key_len = keyLen;
	}

	if(ivLen > 0 && (config.m_IV_len < ivLen || !config.m_IV)) {
		config.m_IV = std::make_unique<uint8_t[]>(ivLen);
		RAND_bytes(config.m_IV.get(), ivLen);
		config.m_IV_len = ivLen;		
	}

	if (!config.m_key) return EXIT_FAILURE;
	if (ivLen > 0 && !config.m_IV) return EXIT_FAILURE;

	
	std::ifstream ifs(in_filename, std::ios::binary);
	std::ofstream ofs(out_filename, std::ios::binary);
	if(!ifs || !ofs) return EXIT_FAILURE;
	char buf_header[18];
	ifs.read(buf_header, 18);
	if(ifs.gcount() < 18) return EXIT_FAILURE;
	ofs.write(buf_header, 18);

	EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
	if (ctx == nullptr) return EXIT_FAILURE;

	if(EVP_EncryptInit_ex(ctx, cipher, NULL, config.m_key.get(), config.m_IV.get()) != 1) {
		EVP_CIPHER_CTX_free(ctx);
    	return EXIT_FAILURE;
	};
	int out_len;
	unsigned char buf_in[4096];
	unsigned char buf_out[4096 + 16];

	while(1) {
		ifs.read(reinterpret_cast<char*>(buf_in), 4096);
		std::streamsize bytesRead = ifs.gcount();

		if(bytesRead == 0) break;

		if(EVP_EncryptUpdate(ctx, buf_out, &out_len, buf_in, bytesRead) != 1) {
			EVP_CIPHER_CTX_free(ctx);
    		return EXIT_FAILURE;
		};

		ofs.write(reinterpret_cast<char*>(buf_out), out_len);

	}
	if(EVP_EncryptFinal_ex(ctx, buf_out, &out_len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return EXIT_FAILURE;		
	};
	ofs.write(reinterpret_cast<char*>(buf_out), out_len);
	EVP_CIPHER_CTX_free(ctx);

	ofs.close();
	if (ifs.bad() || ofs.fail()) return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

int decrypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config )
{
	if (config.m_crypto_function == nullptr ) return EXIT_FAILURE;
	auto cipher = EVP_get_cipherbyname(config.m_crypto_function);
	if (!cipher) return EXIT_FAILURE;

	size_t keyLen = EVP_CIPHER_key_length(cipher); 
	size_t ivLen = EVP_CIPHER_iv_length(cipher);

	if(config.m_key_len < keyLen) {
		return EXIT_FAILURE;
	}

	if(config.m_IV_len < ivLen) {
		return EXIT_FAILURE;
	}

	if (!config.m_key) return EXIT_FAILURE;
	if (ivLen > 0 && !config.m_IV) return EXIT_FAILURE;

	std::ifstream ifs(in_filename, std::ios::binary);
	std::ofstream ofs(out_filename, std::ios::binary);
	if(!ifs || !ofs) return EXIT_FAILURE;
	char buf_header[18];
	ifs.read(buf_header, 18);
	if(ifs.gcount() < 18) return EXIT_FAILURE;
	ofs.write(buf_header, 18);

	EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
	if (ctx == nullptr) return EXIT_FAILURE;

	if(EVP_DecryptInit_ex(ctx, cipher, NULL, config.m_key.get(), config.m_IV.get()) != 1) {
		EVP_CIPHER_CTX_free(ctx);
    	return EXIT_FAILURE;
	};
	int out_len;
	unsigned char buf_in[4096];
	unsigned char buf_out[4096 + 16];

	while(1) {
		ifs.read(reinterpret_cast<char*>(buf_in), 4096);
		std::streamsize bytesRead = ifs.gcount();

		if(bytesRead == 0) break;

		if(EVP_DecryptUpdate(ctx, buf_out, &out_len, buf_in, bytesRead) != 1) {
			EVP_CIPHER_CTX_free(ctx);
    		return EXIT_FAILURE;
		};
		ofs.write(reinterpret_cast<char*>(buf_out), out_len);

	}
	if(EVP_DecryptFinal_ex(ctx, buf_out, &out_len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return EXIT_FAILURE;		
	};
	ofs.write(reinterpret_cast<char*>(buf_out), out_len);
	EVP_CIPHER_CTX_free(ctx);

	ofs.close();
	if (ifs.bad() || ofs.fail()) return EXIT_FAILURE;

	return EXIT_SUCCESS;
}


#ifndef __PROGTEST__

bool compare_files ( const char * name1, const char * name2 )
{

	std::ifstream ifs1(name1, std::ios::binary);
	if(!ifs1) return false;

	std::ifstream ifs2(name2, std::ios::binary);
	if(!ifs2) return false;

	while(1) {
		char buf1[4096];
		ifs1.read(buf1, 4096);
		std::streamsize bytesRead1 = ifs1.gcount();

		char buf2[4096];
		ifs2.read(buf2, 4096);
		std::streamsize bytesRead2 = ifs2.gcount();

		if(bytesRead2 != bytesRead1) return false;

		if(memcmp(buf1, buf2, bytesRead1) != 0) return false;

		if(bytesRead1 == 0) return true;
	}
}

int main ( void )
{
	crypto_config config {nullptr, nullptr, nullptr, 0, 0};

	// ECB mode
	config.m_crypto_function = "AES-128-ECB";
	config.m_key = std::make_unique<uint8_t[]>(16);
 	memset(config.m_key.get(), 0, 16);
	config.m_key_len = 16;
	assert( EXIT_SUCCESS == encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson_enc_ecb.TGA") );

	assert( EXIT_SUCCESS == decrypt_data  ("homer-simpson_enc_ecb.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( EXIT_SUCCESS == encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8_enc_ecb.TGA") );

	assert( EXIT_SUCCESS == decrypt_data  ("UCM8_enc_ecb.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( EXIT_SUCCESS == encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_1_enc_ecb.TGA") );

	assert( EXIT_SUCCESS == encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_2_enc_ecb.TGA") );

	assert( EXIT_SUCCESS == decrypt_data ("image_3_enc_ecb.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_3_dec_ecb.TGA") );

	assert( EXIT_SUCCESS == decrypt_data ("image_4_enc_ecb.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_4_dec_ecb.TGA") );

	// CBC mode
	config.m_crypto_function = "AES-128-CBC";
	config.m_IV = std::make_unique<uint8_t[]>(16);
	config.m_IV_len = 16;
	memset(config.m_IV.get(), 0, 16);

	assert( EXIT_SUCCESS == encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8_enc_cbc.TGA") );

	assert( EXIT_SUCCESS == decrypt_data  ("UCM8_enc_cbc.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( EXIT_SUCCESS == encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson_enc_cbc.TGA") );

	assert( EXIT_SUCCESS == decrypt_data  ("homer-simpson_enc_cbc.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( EXIT_SUCCESS == encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_5_enc_cbc.TGA") );

	assert( EXIT_SUCCESS == encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_6_enc_cbc.TGA") );

	assert( EXIT_SUCCESS == decrypt_data ("image_7_enc_cbc.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_7_dec_cbc.TGA") );

	assert( EXIT_SUCCESS == decrypt_data ("image_8_enc_cbc.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_8_dec_cbc.TGA") );
	return 0;
}

#endif
