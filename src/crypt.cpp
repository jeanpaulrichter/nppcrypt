/*
This file is part of the NppCrypt Plugin [www.cerberus-design.de] for Notepad++ [ Copyright (C)2003 Don HO <don.h@free.fr> ]

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
*/


#include "crypt.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include "bcrypt/crypt_blowfish.h"
#include "keccak/KeccakHash.h"
#include "scrypt/crypto_scrypt.h"
#include "encoding.h"

#ifdef max
#undef max
#endif

// ---------------------------- SUPPORTED CIPHER MODES -------------------------------------------------------------------------------------------------------------------------------------------

enum { ecb=1, cbc=2, cfb=4, ofb=8, ctr=16, xts=32, ccm=64, gcm=128 };
static const unsigned int cipher_modes[unsigned(crypt::Cipher::COUNT)] = 
		{	cbc|ecb|cfb|ofb, 
			cbc|ecb|cfb|ofb,
			cbc|ecb|cfb|ofb,
			cbc,
			cbc|ecb|cfb|ofb,
			0,
			cbc|ecb|cfb|ofb,
			cbc|ecb|cfb|ofb,
			cbc|ecb|cfb|ofb, 
			cbc|ecb|cfb|ofb,
			cbc|ecb|cfb|ofb|ctr|xts|ccm|gcm,
			cbc|ecb|cfb|ofb|ctr|ccm|gcm,
			cbc|ecb|cfb|ofb|ctr|xts|ccm|gcm, 
		};

// ----------------------------- STRINGS ---------------------------------------------------------------------------------------------------------------------------------------------------------

static const TCHAR* cipher_str[] = { TEXT("des"), TEXT("des_ede"), TEXT("des_ede3"), TEXT("desx"), TEXT("rc2"), TEXT("rc4"), TEXT("rc5"), TEXT("idea"), TEXT("blowfish"), TEXT("cast5"), TEXT("aes128"), TEXT("aes192"), TEXT("aes256") };
static const char* cipher_str_c[] = { "des", "des_ede", "des_ede3", "desx", "rc2", "rc4", "rc5", "idea", "blowfish", "cast5", "aes128", "aes192", "aes256" };

static const TCHAR* mode_str[] = { TEXT("ecb"), TEXT("cbc"), TEXT("cfb"), TEXT("ofb"), TEXT("ctr"), TEXT("xts"), TEXT("ccm"), TEXT("gcm") };
static const char* mode_str_c[] = { "ecb", "cbc", "cfb", "ofb", "ctr", "xts", "ccm", "gcm" };

static const char* iv_str_c[] = { "random", "keyderivation", "zero" };

static const TCHAR* hash_str[] = { TEXT("md4"), TEXT("md5"), TEXT("mdc2"), TEXT("sha1"), TEXT("sha256"), TEXT("sha512"), TEXT("ripemd160"), TEXT("whirlpool"), TEXT("sha3_256"), TEXT("sha3_384"), TEXT("sha3_512") };
static const char* hash_str_c[] = { "md4", "md5", "mdc2", "sha1", "sha256", "sha512", "ripemd160", "whirlpool", "sha3_256", "sha3_384", "sha3_512" };

static const char* encoding_str_c[] = { "ascii", "base16", "base64" };
static const char* key_algo_str_c[] = { "pbkdf2", "bcrypt", "scrypt" };
static const char* random_mode_str_c[] = { "charnum", "specials", "ascii", "base16" , "base64" };

static TCHAR help_url_wikipedia[100] = TEXT("https://en.wikipedia.org/wiki/");
static const int help_url_wikipedia_len = 30;
static const TCHAR* help_url_cipher[] = { TEXT("Data_Encryption_Standard"), TEXT("Data_Encryption_Standard"), TEXT("Data_Encryption_Standard"), TEXT("DES-X"), TEXT("RC2"), TEXT("RC4"), TEXT("RC5"), TEXT("International_Data_Encryption_Algorithm"), TEXT("Blowfish_(cipher)"), TEXT("CAST-128"), TEXT("Advanced_Encryption_Standard"), TEXT("Advanced_Encryption_Standard"), TEXT("Advanced_Encryption_Standard") };
static const TCHAR* help_url_mode[] = { TEXT("Block_cipher_mode_of_operation"), TEXT("Block_cipher_mode_of_operation"), TEXT("Block_cipher_mode_of_operation"), TEXT("Block_cipher_mode_of_operation"), TEXT("Block_cipher_mode_of_operation"), TEXT("Disk_encryption_theory"), TEXT("CCM_mode"), TEXT("Galois/Counter_Mode") };

static const TCHAR* help_url_encoding[] = { TEXT("ASCII"), TEXT("Hexadecimal"), TEXT("Base64") };
static const TCHAR* help_url_hash[] = { TEXT("MD4"), TEXT("MD5"), TEXT("MDC-2"), TEXT("SHA-1"), TEXT("SHA-2"), TEXT("SHA-2"), TEXT("RIPEMD"), TEXT("Whirlpool_(cryptography)"), TEXT("SHA-3"), TEXT("SHA-3"), TEXT("SHA-3") };
static const TCHAR* help_url_keyderiv[] = { TEXT("PBKDF2"), TEXT("Bcrypt"), TEXT("Scrypt") };

// ----------------------------- HELP FUNCTIONS --------------------------------------------------------------------------------------------------------------------------------------------------

const EVP_CIPHER* getEVPCipher(crypt::Cipher c, crypt::Mode m)
{
	switch(c) {
	case crypt::Cipher::blowfish: 
		switch(m) {
		case crypt::Mode::cbc: return EVP_bf_cbc();
		case crypt::Mode::ecb: return EVP_bf_ecb();
		case crypt::Mode::cfb: return EVP_bf_cfb();
		case crypt::Mode::ofb: return EVP_bf_ofb();
		}
		break;
	case crypt::Cipher::des:
		switch(m) {
		case crypt::Mode::cbc: return EVP_des_cbc();
		case crypt::Mode::ecb: return EVP_des_ecb();
		case crypt::Mode::cfb: return EVP_des_cfb();
		case crypt::Mode::ofb: return EVP_des_ofb();
		}
		break;
	case crypt::Cipher::des_ede:
		switch(m) {
		case crypt::Mode::cbc: return EVP_des_ede_cbc();
		case crypt::Mode::ecb: return EVP_des_ede_ecb();
		case crypt::Mode::cfb: return EVP_des_ede_cfb();
		case crypt::Mode::ofb: return EVP_des_ede_ofb();
		}
		break;
	case crypt::Cipher::des_ede3:
		switch(m) {
		case crypt::Mode::cbc: return EVP_des_ede3_cbc();
		case crypt::Mode::ecb: return EVP_des_ede3_ecb();
		case crypt::Mode::cfb: return EVP_des_ede3_cfb();
		case crypt::Mode::ofb: return EVP_des_ede3_ofb();
		}
		break;
	case crypt::Cipher::rc2:
		switch(m) {
		case crypt::Mode::cbc: return EVP_rc2_cbc();
		case crypt::Mode::ecb: return EVP_rc2_ecb();
		case crypt::Mode::cfb: return EVP_rc2_cfb();
		case crypt::Mode::ofb: return EVP_rc2_ofb();
		}
		break;
	case crypt::Cipher::idea:
		switch(m) {
		case crypt::Mode::cbc: return EVP_idea_cbc();
		case crypt::Mode::ecb: return EVP_idea_ecb();
		case crypt::Mode::cfb: return EVP_idea_cfb();
		case crypt::Mode::ofb: return EVP_idea_ofb();
		}
		break;
	case crypt::Cipher::cast5:
		switch(m) {
		case crypt::Mode::cbc: return EVP_cast5_cbc();
		case crypt::Mode::ecb: return EVP_cast5_ecb();
		case crypt::Mode::cfb: return EVP_cast5_cfb();
		case crypt::Mode::ofb: return EVP_cast5_ofb();
		}
		break;
	case crypt::Cipher::aes128:
		switch(m) {
		case crypt::Mode::cbc: return EVP_aes_128_cbc();
		case crypt::Mode::ecb: return EVP_aes_128_ecb();
		case crypt::Mode::cfb: return EVP_aes_128_cfb();
		case crypt::Mode::ofb: return EVP_aes_128_ofb();
		case crypt::Mode::ctr: return EVP_aes_128_ctr();
		case crypt::Mode::xts: return EVP_aes_128_xts();
		case crypt::Mode::ccm: return EVP_aes_128_ccm();
		case crypt::Mode::gcm: return EVP_aes_128_gcm();
		}
		break;
	case crypt::Cipher::aes192:
		switch(m) {
		case crypt::Mode::cbc: return EVP_aes_192_cbc();
		case crypt::Mode::ecb: return EVP_aes_192_ecb();
		case crypt::Mode::cfb: return EVP_aes_192_cfb();
		case crypt::Mode::ofb: return EVP_aes_192_ofb();
		case crypt::Mode::ctr: return EVP_aes_192_ctr();
		case crypt::Mode::ccm: return EVP_aes_192_ccm();
		case crypt::Mode::gcm: return EVP_aes_192_gcm();
		}
		break;
	case crypt::Cipher::aes256:
		switch(m) {
		case crypt::Mode::cbc: return EVP_aes_256_cbc();
		case crypt::Mode::ecb: return EVP_aes_256_ecb();
		case crypt::Mode::cfb: return EVP_aes_256_cfb();
		case crypt::Mode::ofb: return EVP_aes_256_ofb();
		case crypt::Mode::ctr: return EVP_aes_256_ctr();
		case crypt::Mode::xts: return EVP_aes_256_xts();
		case crypt::Mode::ccm: return EVP_aes_256_ccm();
		case crypt::Mode::gcm: return EVP_aes_256_gcm();
		}
		break;
	case crypt::Cipher::desx:
		switch(m) {
			case crypt::Mode::cbc: return EVP_desx_cbc();
		}
		break;
	case crypt::Cipher::rc4:
		return EVP_rc4();
	case crypt::Cipher::rc5:
		switch(m) {
		case crypt::Mode::cbc: return EVP_rc5_32_12_16_cbc();
		case crypt::Mode::ecb: return EVP_rc5_32_12_16_ecb();
		case crypt::Mode::cfb: return EVP_rc5_32_12_16_cfb();
		case crypt::Mode::ofb: return EVP_rc5_32_12_16_ofb();
		}
		break;
	}
	return NULL;
}

const EVP_MD* getEVPHash(crypt::Hash algo)
{
	switch(algo) {
	case crypt::Hash::md4: return EVP_md4();
	case crypt::Hash::md5: return EVP_md5();
	case crypt::Hash::mdc2: return EVP_mdc2();
	case crypt::Hash::sha1: return EVP_sha1();
	case crypt::Hash::sha256: return EVP_sha256();
	case crypt::Hash::sha512: return EVP_sha512();
	case crypt::Hash::ripemd160: return EVP_ripemd160();
	case crypt::Hash::whirlpool: return EVP_whirlpool();
	}
	return NULL;
}

// ===========================================================================================================================================================================================

void crypt::encrypt(const unsigned char* in, size_t in_len, std::vector<unsigned char>& buffer, const Options::Crypt& options, InitStrings& init)
{
	if (!in || !in_len)
		throw CExc(CExc::File::crypt, __LINE__);
	if (!options.password.size())
		throw CExc(CExc::File::crypt, __LINE__);

	const EVP_CIPHER* tCipher = getEVPCipher(options.cipher, options.mode);
	if (!tCipher)
		throw CExc(CExc::File::crypt, __LINE__);

	EVP_CIPHER_CTX				ctx;
	std::vector<unsigned char>	tKey;
	std::vector<unsigned char>	tVec;
	std::vector<unsigned char>	tSalt;
	const unsigned char*		ptVec = NULL;
	const unsigned char*		ptSalt = NULL;
	unsigned int				iv_len = 0;

	// --------------------------- prepare salt vector:
	if (options.key.salt_bytes > 0)
	{
		if(options.key.algorithm == crypt::KeyDerivation::bcrypt && options.key.salt_bytes != 16)
			throw CExc(CExc::Code::bcrypt_salt);
		tSalt.resize(options.key.salt_bytes);
		RAND_bytes(&tSalt[0], options.key.salt_bytes);
		ptSalt = &tSalt[0];
	}

	// --------------------------- prepare iv & key vector
	switch (options.mode)
	{
	case crypt::Mode::gcm: iv_len = Constants::gcm_iv_length; break;
	case crypt::Mode::ccm: iv_len = Constants::ccm_iv_length; break;
	default: iv_len = iv_len = tCipher->iv_len; break;
	}

	if (options.iv == crypt::IV::keyderivation)
	{
		tKey.resize(tCipher->key_len + iv_len);
		if (iv_len > 0)
			ptVec = &tKey[tCipher->key_len];

	}
	else if (options.iv == crypt::IV::random)
	{
		tKey.resize(tCipher->key_len);
		if (iv_len > 0)
		{
			tVec.resize(iv_len);
			RAND_bytes(&tVec[0], iv_len);
			ptVec = &tVec[0];
		}
	}
	else if (options.iv == crypt::IV::zero)
	{
		tKey.resize(tCipher->key_len);
		ptVec = NULL;
	}

	// --------------------------- key derivation:
	switch (options.key.algorithm)
	{
	case crypt::KeyDerivation::pbkdf2:
	{
		const EVP_MD* hash_md = getEVPHash((Hash)options.key.option1);
		if (!hash_md)
			throw CExc(CExc::File::crypt, __LINE__);
		if (PKCS5_PBKDF2_HMAC(options.password.c_str(), options.password.size(), ptSalt, options.key.salt_bytes, options.key.option2, hash_md, (int)tKey.size(), &tKey[0]) != 1)
			throw CExc(CExc::File::crypt, __LINE__);
	} break;

	case crypt::KeyDerivation::bcrypt:
	{
		char output[64];
		char settings[32];

		if (_crypt_gensalt_blowfish_rn("$2a$", (unsigned long)options.key.option1, (const char*)ptSalt, 16, settings, 32) == NULL)
			throw CExc(CExc::File::crypt, __LINE__);
		memset(output, 0, sizeof(output));
		if (_crypt_blowfish_rn(options.password.c_str(), settings, output, 64) == NULL)
			throw CExc(CExc::File::crypt, __LINE__);

		shake128((unsigned char*)output, 24, &tKey[0], tKey.size());
	} break;

	case crypt::KeyDerivation::scrypt:
	{
		if (crypto_scrypt((unsigned char*)options.password.c_str(), options.password.size(), ptSalt, options.key.salt_bytes, std::pow(2, options.key.option1), options.key.option2, options.key.option3, &tKey[0], tKey.size()) != 0)
			throw CExc(CExc::File::crypt, __LINE__);
	} break;
	}

	// --------------------------- return encoded IV and Salt
	init.encoding = Encoding::base64;
	if (options.iv == crypt::IV::random && tVec.size() > 0) 
	{
		init.iv.resize(Encode::bin_to_base64(&tVec[0], tVec.size(), NULL, true));
		if (init.iv.size())
			Encode::bin_to_base64(&tVec[0], tVec.size(), &init.iv[0], true);
	}
	if (options.key.salt_bytes > 0) {
		init.salt.resize(Encode::bin_to_base64(&tSalt[0], tSalt.size(), NULL, true));
		if (init.salt.size())
			Encode::bin_to_base64(&tSalt[0], tSalt.size(), &init.salt[0], true);
	}

	try
	{
		EVP_CIPHER_CTX_init(&ctx);

		if (!EVP_EncryptInit_ex(&ctx, tCipher, NULL, NULL, NULL))
			throw CExc(CExc::File::crypt, __LINE__);

		// ------ gcm/ccm init ------
		if (options.mode == crypt::Mode::gcm)
		{
			if (1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, Constants::gcm_iv_length, NULL))
				throw CExc(CExc::File::crypt, __LINE__);
		}
		else if (options.mode == crypt::Mode::ccm) {
			if (1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_L, 15 - Constants::ccm_iv_length, NULL))
				throw CExc(CExc::File::crypt, __LINE__);
			if (1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, Constants::ccm_iv_length, NULL))
				throw CExc(CExc::File::crypt, __LINE__);
			if (1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, 16, NULL))
				throw CExc(CExc::File::crypt, __LINE__);
		}
		// ----------------------------
		if (1 != EVP_EncryptInit_ex(&ctx, NULL, NULL, &tKey[0], ptVec))
			throw CExc(CExc::File::crypt, __LINE__);

		// -------------------------------------------------------------------------------------

		int							clen = 0;
		size_t						olen = 0;
		std::vector<unsigned char>	tBuf;
		unsigned char*				pBuf;

		// -------------- ASCII: write directly to buffer --------------------------------------
		if (options.encoding == crypt::Encoding::ascii) 
		{
			buffer.resize(in_len + EVP_MAX_BLOCK_LENGTH);
			pBuf = &buffer[0];

		// -------------- BASE16/BASE64: temp Buffer needed ------------------------------------
		}
		else {
			tBuf.resize(in_len + EVP_MAX_BLOCK_LENGTH);
			pBuf = &tBuf[0];
		}

		// -------------- ccm-mode has to know input length in advance -------------------------
		if (options.mode == crypt::Mode::ccm) {
			if (in_len > (unsigned)std::numeric_limits<int>::max())
				throw CExc(CExc::Code::input_too_long);
			if (1 != EVP_EncryptUpdate(&ctx, NULL, &clen, NULL, in_len))
				throw CExc(CExc::File::crypt, __LINE__);
		}
		// -------------- add salt and iv strings as AAD data for gcm and ccm ------------------
		if (options.mode == crypt::Mode::gcm || options.mode == crypt::Mode::ccm) {
			if (1 != EVP_EncryptUpdate(&ctx, NULL, &clen, (const unsigned char*)init.salt.c_str(), init.salt.size()))
				throw CExc(CExc::File::crypt, __LINE__);
			if (1 != EVP_EncryptUpdate(&ctx, NULL, &clen, (const unsigned char*)init.iv.c_str(), init.iv.size()))
				throw CExc(CExc::File::crypt, __LINE__);
		}

		// -------------- encrypt data ---------------------------------------------------------
		if (1 != EVP_EncryptUpdate(&ctx, pBuf, &clen, in, in_len))
			throw CExc(CExc::File::crypt, __LINE__);
		olen += (size_t)clen;
		if (1 != EVP_EncryptFinal_ex(&ctx, pBuf + olen, &clen))
			throw CExc(CExc::File::crypt, __LINE__, CExc::Code::encrypt);
		olen += (size_t)clen;

		switch (options.encoding) 
		{
		// -------------- ASCII Output -----------------------------------------------------------
		case crypt::Encoding::ascii:
			buffer.resize(olen);
			break;
		// -------------- HEX Output -----------------------------------------------------------
		case crypt::Encoding::base16:
			buffer.resize(Encode::bin_to_hex(NULL, olen));
			Encode::bin_to_hex(pBuf, olen, (char*)&buffer[0]);
			break;
		// -------------- BASE64 Output --------------------------------------------------------
		case crypt::Encoding::base64:
			buffer.resize(Encode::bin_to_base64(NULL, olen));
			Encode::bin_to_base64(pBuf, olen, (char*)&buffer[0]);
			break;
		}

		// -------------- GCM/CCM-Mode: get tag-data -------------------------------------------
		if (options.mode == crypt::Mode::gcm || options.mode == crypt::Mode::ccm)
		{
			unsigned char tag[16];
			int type = (options.mode == crypt::Mode::gcm) ? EVP_CTRL_GCM_GET_TAG : EVP_CTRL_CCM_GET_TAG;
			if (1 != EVP_CIPHER_CTX_ctrl(&ctx, type, 16, tag))
				throw CExc(CExc::File::crypt, __LINE__);
			init.tag.resize(24);
			Encode::bin_to_base64(tag, 16, &init.tag[0], true);
		}

		// -------------- cleanup
		EVP_CIPHER_CTX_cleanup(&ctx);
	}
	catch (CExc& exc) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		throw(exc);
	}
	catch (...) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		throw CExc(CExc::File::crypt, __LINE__);
	}
}

// ===========================================================================================================================================================================================

void crypt::decrypt(const unsigned char* in, size_t in_len, std::vector<unsigned char>& buffer, const Options::Crypt& options, const InitStrings& init)
{
	if (!in || !in_len)
		throw CExc(CExc::File::crypt, __LINE__);
	if (!options.password.size())
		throw CExc(CExc::File::crypt, __LINE__);

	const EVP_CIPHER* tCipher = getEVPCipher(options.cipher, options.mode);
	if (!tCipher)
		throw CExc(CExc::File::crypt, __LINE__);

	EVP_CIPHER_CTX				ctx;
	std::vector<unsigned char>	tKey;
	std::vector<unsigned char>	tVec;
	std::vector<unsigned char>	tSalt;
	const unsigned char*		ptVec = NULL;
	const unsigned char*		ptSalt = NULL;
	unsigned int				iv_len = 0;

	// --------------------------- prepare salt vector:
	if (options.key.salt_bytes > 0)
	{
		if (options.key.algorithm == crypt::KeyDerivation::bcrypt && options.key.salt_bytes != 16)
			throw CExc(CExc::Code::bcrypt_salt);
		tSalt.resize(options.key.salt_bytes);
		if (!init.salt.size())
			throw CExc(CExc::Code::decrypt_nosalt);
		if (Encode::base64_to_bin(init.salt.c_str(), init.salt.size()) != (size_t)options.key.salt_bytes)
			throw CExc(CExc::Code::decrypt_badsalt);
		Encode::base64_to_bin(init.salt.c_str(), init.salt.size(), &tSalt[0]);
		ptSalt = &tSalt[0];
	}

	// --------------------------- prepare iv & key vector
	switch (options.mode)
	{
	case crypt::Mode::gcm: iv_len = Constants::gcm_iv_length; break;
	case crypt::Mode::ccm: iv_len = Constants::ccm_iv_length; break;
	default: iv_len = iv_len = tCipher->iv_len; break;
	}

	if (options.iv == crypt::IV::keyderivation)
	{
		tKey.resize(tCipher->key_len + iv_len);
		if (iv_len > 0)
			ptVec = &tKey[tCipher->key_len];

	}
	else if (options.iv == crypt::IV::random)
	{
		tKey.resize(tCipher->key_len);
		if (iv_len > 0)
		{
			tVec.resize(iv_len);
			if (!init.iv.size())
				throw CExc(CExc::Code::decrypt_noiv);
			if (Encode::base64_to_bin(init.iv.c_str(), init.iv.size()) != tVec.size())
				throw CExc(CExc::Code::decrypt_badiv);
			Encode::base64_to_bin(init.iv.c_str(), init.iv.size(), &tVec[0]);
			ptVec = &tVec[0];
		}
	}
	else if (options.iv == crypt::IV::zero)
	{
		tKey.resize(tCipher->key_len);
		ptVec = NULL;
	}

	// --------------------------- key derivation:
	switch (options.key.algorithm)
	{
	case crypt::KeyDerivation::pbkdf2:
	{
		const EVP_MD* hash_md = getEVPHash((Hash)options.key.option1);
		if (!hash_md)
			throw CExc(CExc::File::crypt, __LINE__);
		if (PKCS5_PBKDF2_HMAC(options.password.c_str(), options.password.size(), ptSalt, options.key.salt_bytes, options.key.option2, hash_md, (int)tKey.size(), &tKey[0]) != 1)
			throw CExc(CExc::File::crypt, __LINE__);
	} break;

	case crypt::KeyDerivation::bcrypt:
	{
		char output[64];
		char settings[32];

		if (_crypt_gensalt_blowfish_rn("$2a$", (unsigned long)options.key.option1, (const char*)ptSalt, 16, settings, 32) == NULL)
			throw CExc(CExc::File::crypt, __LINE__);
		memset(output, 0, sizeof(output));
		if (_crypt_blowfish_rn(options.password.c_str(), settings, output, 64) == NULL)
			throw CExc(CExc::File::crypt, __LINE__);

		shake128((unsigned char*)output, 24, &tKey[0], tKey.size());
	} break;

	case crypt::KeyDerivation::scrypt:
	{
		if (crypto_scrypt((unsigned char*)options.password.c_str(), options.password.size(), ptSalt, options.key.salt_bytes, std::pow(2, options.key.option1), options.key.option2, options.key.option3, &tKey[0], tKey.size()) != 0)
			throw CExc(CExc::File::crypt, __LINE__);
	} break;
	}

	try
	{
		EVP_CIPHER_CTX_init(&ctx);

		if (!EVP_DecryptInit_ex(&ctx, tCipher, NULL, NULL, NULL))
			throw CExc(CExc::File::crypt, __LINE__);

		// ------------ gcm/ccm init:
		if (options.mode == crypt::Mode::gcm || options.mode == crypt::Mode::ccm) 
		{
			unsigned char tag[16];
			if (!init.tag.size())
				throw CExc(CExc::Code::decrypt_notag);
			if (Encode::base64_to_bin(init.tag.c_str(), init.tag.size()) != 16)
				throw CExc(CExc::Code::decrypt_badtag);
			Encode::base64_to_bin(init.tag.c_str(), init.tag.size(), tag);

			if (options.mode == crypt::Mode::gcm) {
				if (1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, Constants::gcm_iv_length, NULL))
					throw CExc(CExc::File::crypt, __LINE__);
				if (1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
					throw CExc(CExc::File::crypt, __LINE__);
			}
			else {
				if (1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_L, 15 - Constants::ccm_iv_length, NULL))
					throw CExc(CExc::File::crypt, __LINE__);
				if (1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, Constants::ccm_iv_length, NULL))
					throw CExc(CExc::File::crypt, __LINE__);
				if (1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, 16, tag))
					throw CExc(CExc::File::crypt, __LINE__);
			}
		}
		// ----------------------------------------------------------------------------------------------------------------------------

		if (!EVP_DecryptInit_ex(&ctx, NULL, NULL, &tKey[0], ptVec))
			throw CExc(CExc::File::crypt, __LINE__);

		int							clen;
		size_t						ilen, olen;
		std::vector<unsigned char>	tBuf;
		const unsigned char*		pIn;

		switch (options.encoding)
		{
		// ------------- ASCII Input ----------------------------------------------------
		case crypt::Encoding::ascii:
			buffer.resize(in_len);
			pIn = in;
			ilen = in_len;
			break;
		// ------------- Hex Input ------------------------------------------------------
		case crypt::Encoding::base16:
			tBuf.resize(in_len / 2 + EVP_MAX_BLOCK_LENGTH);
			ilen = Encode::hex_to_bin((const char*)in, in_len, &tBuf[0]);
			buffer.resize(tBuf.size());
			pIn = &tBuf[0];
			break;
		// ------------- Base64 Input ---------------------------------------------------
		case crypt::Encoding::base64:
			tBuf.resize(static_cast<size_t>(in_len*0.8));
			ilen = Encode::base64_to_bin((const char*)in, in_len, &tBuf[0]);
			buffer.resize(tBuf.size());
			pIn = &tBuf[0];
			break;
		}

		// -------------- ccm-mode has to know input length in advance -------------------------
		if (options.mode == crypt::Mode::ccm)
		{
			if (1 != EVP_DecryptUpdate(&ctx, NULL, &clen, NULL, ilen))
				throw CExc(CExc::File::crypt, __LINE__, CExc::Code::decrypt);
		}

		// -------------- add salt and iv strings as AAD data for gcm and ccm ------------------
		if (options.mode == crypt::Mode::ccm || options.mode == crypt::Mode::gcm) {
			if (1 != EVP_DecryptUpdate(&ctx, NULL, &clen, (const unsigned char*)init.salt.c_str(), init.salt.size()))
				throw CExc(CExc::File::crypt, __LINE__);
			if (1 != EVP_DecryptUpdate(&ctx, NULL, &clen, (const unsigned char*)init.iv.c_str(), init.iv.size()))
				throw CExc(CExc::File::crypt, __LINE__);
		}

		if (1 != EVP_DecryptUpdate(&ctx, &buffer[0], &clen, pIn, ilen))
			throw CExc(CExc::File::crypt, __LINE__);
		olen = (size_t)clen;

		// ------------- ccm mode for some reason doesn't like EVP_DecryptFinal_ex...
		if (options.mode != crypt::Mode::ccm)
		{
			if (1 != EVP_DecryptFinal_ex(&ctx, &buffer[0] + clen, &clen))
				throw CExc(CExc::File::crypt, __LINE__, CExc::Code::decrypt);
			olen += (size_t)clen;
		}
		buffer.resize(olen);

		// -------------- cleanup
		EVP_CIPHER_CTX_cleanup(&ctx);
	}
	catch (CExc& exc) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		throw(exc);
	}
	catch (...) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		throw CExc(CExc::File::crypt, __LINE__);
	}
}

// ===========================================================================================================================================================================================

void crypt::hash(const unsigned char* in, size_t in_len, std::vector<unsigned char>& buffer, const Options::Hash& options)
{
	if(!in && in_len>0)
		throw CExc(CExc::File::crypt,__LINE__);
	
	unsigned char	hash[64];
	int				hash_len;

	if(options.algorithm == Hash::sha3_256 || options.algorithm == Hash::sha3_384 || options.algorithm == Hash::sha3_512)
	{
		Keccak_HashInstance keccak_inst;
		switch(options.algorithm) {
		case Hash::sha3_256:
			if(Keccak_HashInitialize_SHA3_256(&keccak_inst)!=0) throw CExc(CExc::File::crypt,__LINE__);
			hash_len = 32;
			break;
		case Hash::sha3_384:
			if(Keccak_HashInitialize_SHA3_384(&keccak_inst)!=0) throw CExc(CExc::File::crypt,__LINE__);
			hash_len = 48;
			break;
		case Hash::sha3_512:
			if(Keccak_HashInitialize_SHA3_512(&keccak_inst)!=0) throw CExc(CExc::File::crypt,__LINE__);
			hash_len = 64;
			break;
		}
		if(Keccak_HashUpdate(&keccak_inst, in, in_len * 8)!=0)
			throw CExc(CExc::File::crypt,__LINE__);
		if(Keccak_HashFinal(&keccak_inst, hash)!=0)
			throw CExc(CExc::File::crypt,__LINE__);
	} 
	else 
	{
		EVP_MD_CTX		mdctx;
		size_t			md_len;
		const EVP_MD*	md = getEVPHash(options.algorithm);
		if(!md)
			throw CExc(CExc::File::crypt,__LINE__);

		EVP_MD_CTX_init(&mdctx);
		if(!EVP_DigestInit_ex(&mdctx, md, NULL))
			throw CExc(CExc::File::crypt,__LINE__);
		if(!EVP_DigestUpdate(&mdctx, in, in_len))
			throw CExc(CExc::File::crypt,__LINE__);
		if(!EVP_DigestFinal_ex(&mdctx, hash, &md_len))
			throw CExc(CExc::File::crypt,__LINE__);
		if(!EVP_MD_CTX_cleanup(&mdctx))
			throw CExc(CExc::File::crypt,__LINE__);

		hash_len = md->md_size;
	}

	buffer.clear();
	if(options.encoding == Encoding::ascii)
	{
		buffer.resize(hash_len);
		memcpy(&buffer[0], hash, hash_len);
	} else if(options.encoding == Encoding::base16)
	{
		buffer.resize(Encode::bin_to_hex(NULL, hash_len));
		Encode::bin_to_hex(hash,hash_len,(char*)&buffer[0]);
	} else 
	{
		buffer.resize(Encode::bin_to_base64(NULL, hash_len));
		Encode::bin_to_base64(hash,hash_len,(char*)&buffer[0]);
	}
}

// ===========================================================================================================================================================================================

void crypt::hmac(const unsigned char* data, unsigned int data_len, const crypt::Options::Hash& options, std::vector<unsigned char>& out)
{
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	const EVP_MD* md = getEVPHash(options.algorithm);

	if(!data || !data_len)
		throw CExc(CExc::File::crypt,__LINE__);
	if(!md)
		throw CExc(CExc::File::crypt,__LINE__);

	try {
		if(1 != HMAC_Init_ex(&ctx, &options.key[0], options.key.size(), md, NULL))
			throw CExc(CExc::File::crypt,__LINE__);
		if(1 != HMAC_Update(&ctx, (const unsigned char*)data, data_len))
			throw CExc(CExc::File::crypt,__LINE__);
		size_t len;
		unsigned char buf[EVP_MAX_MD_SIZE];
		if(1 != HMAC_Final(&ctx, buf, &len))
			throw CExc(CExc::File::crypt,__LINE__);
		if(!len)
			throw CExc(CExc::File::crypt,__LINE__);

		switch(options.encoding) {
		case crypt::Encoding::ascii:
			out.resize(len);
			memcpy(&out[0], buf, len);
			break;
		case crypt::Encoding::base16:
			out.resize(Encode::bin_to_hex(NULL, len));
			Encode::bin_to_hex(buf,len,(char*)&out[0]);
			break;
		case crypt::Encoding::base64:
			out.resize(Encode::bin_to_base64(NULL, len, NULL, true));
			Encode::bin_to_base64(buf, len, (char*)&out[0], true);
			break;
		}

		HMAC_CTX_cleanup(&ctx);
	} catch(CExc& exc) {
		HMAC_CTX_cleanup(&ctx);
		throw exc;
	}
}

// ===========================================================================================================================================================================================

void crypt::hmac_header(const char* a, size_t a_len, const unsigned char* b, size_t b_len, Hash algo, const unsigned char* key, size_t key_len, std::string& out)
{
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	const EVP_MD* md = getEVPHash(algo);

	if (!a || !a_len || !b || !b_len)
		throw CExc(CExc::File::crypt, __LINE__);
	if (!md)
		throw CExc(CExc::File::crypt, __LINE__);

	try {
		if (1 != HMAC_Init_ex(&ctx, key, key_len, md, NULL))
			throw CExc(CExc::File::crypt, __LINE__);
		if (1 != HMAC_Update(&ctx, (const unsigned char*)a, a_len))
			throw CExc(CExc::File::crypt, __LINE__);
		if (1 != HMAC_Update(&ctx, (const unsigned char*)b, b_len))
			throw CExc(CExc::File::crypt, __LINE__);
		size_t len;
		unsigned char buf[EVP_MAX_MD_SIZE];
		if (1 != HMAC_Final(&ctx, buf, &len))
			throw CExc(CExc::File::crypt, __LINE__);
		if (!len)
			throw CExc(CExc::File::crypt, __LINE__);

		out.resize(Encode::bin_to_base64(NULL, len, NULL, true));
		Encode::bin_to_base64(buf, len, &out[0], true);

		HMAC_CTX_cleanup(&ctx);

	}
	catch (CExc& exc) {
		HMAC_CTX_cleanup(&ctx);
		throw exc;
	}
}

// ===========================================================================================================================================================================================

void crypt::shake128(const unsigned char* in, size_t in_len, unsigned char* out, size_t out_len)
{
	Keccak_HashInstance keccak_inst;
	if (Keccak_HashInitialize_SHAKE128(&keccak_inst) != 0)
		throw CExc(CExc::File::crypt, __LINE__);
	if (Keccak_HashUpdate(&keccak_inst, in, in_len * 8) != 0)
		throw CExc(CExc::File::crypt, __LINE__);
	if (Keccak_HashFinal(&keccak_inst, out) != 0)
		throw CExc(CExc::File::crypt, __LINE__);
	if (Keccak_HashSqueeze(&keccak_inst, out, out_len * 8) != 0)
		throw CExc(CExc::File::crypt, __LINE__);
}

// ===========================================================================================================================================================================================

void crypt::random(const Options::Random& options, std::vector<unsigned char>& buffer)
{
	if(options.length == 0)
		throw CExc(CExc::File::crypt,__LINE__);

	buffer.clear();

	switch(options.mode)
	{
	case Random::ascii:
	{
		buffer.resize(options.length);
		if (RAND_bytes(&buffer[0], (int)options.length) != 1)
			throw CExc(CExc::File::crypt, __LINE__);
	} break;

	case Random::base16:
	{
		std::vector<unsigned char> tbuf;
		tbuf.resize(options.length);
		if(RAND_bytes(&tbuf[0], (int)options.length) != 1)
			throw CExc(CExc::File::crypt,__LINE__);
		buffer.resize(Encode::bin_to_hex(NULL,tbuf.size()));
		Encode::bin_to_hex(&tbuf[0], tbuf.size(), (char*)&buffer[0]);
		
	} break;

	case Random::base64:
	{
		std::vector<unsigned char> tbuf;
		tbuf.resize(options.length);
		if(RAND_bytes(&tbuf[0], (int)options.length) != 1)
			throw CExc(CExc::File::crypt,__LINE__);
		buffer.resize(Encode::bin_to_base64(NULL,tbuf.size()));
		Encode::bin_to_base64(&tbuf[0], tbuf.size(), (char*)&buffer[0]);
		
	} break;

	case Random::charnum:
	{
		buffer.resize(options.length);
		unsigned char temp[Constants::rand_char_bufsize];
		size_t i = 0;
		while (i < options.length) {
			if (RAND_bytes(temp, Constants::rand_char_bufsize) != 1)
				throw CExc(CExc::File::crypt, __LINE__);
			for (int x = 0; x < Constants::rand_char_bufsize && i < options.length; x++) {
				if (temp[x] < 62) {
					if (temp[x] < 10) {
						buffer[i] = 48 + temp[x];
					}
					else if (temp[x] < 36) {
						buffer[i] = 55 + temp[x];
					}
					else {
						buffer[i] = 61 + temp[x];
					}
					i++;
				}
			}
		}
	} break;
	
	case Random::specials:
	{
		buffer.resize(options.length);
		unsigned char temp[Constants::rand_char_bufsize];
		size_t i = 0;
		while(i < options.length)
		{
			if(RAND_bytes(temp, Constants::rand_char_bufsize) != 1)
				throw CExc(CExc::File::crypt,__LINE__);
			for(int x = 0; x < Constants::rand_char_bufsize && i < options.length; x++) {
				if(temp[x] > 32 && temp[x] < 127) {
					buffer[i] = temp[x];
					i++;
				}
			}
		}		
	} break;
	}
}

// ===========================================================================================================================================================================================

size_t crypt::getHashLength(Hash h)
{
	switch(h)
	{
	case crypt::Hash::md4: return 16;
	case crypt::Hash::md5: return 16;
	case crypt::Hash::mdc2: return 16;
	case crypt::Hash::ripemd160: return 20;
	case crypt::Hash::sha1: return 20;
	case crypt::Hash::sha256: return 32;
	case crypt::Hash::sha512: return 64;
	case crypt::Hash::whirlpool: return 64;
	case crypt::Hash::sha3_256: return 32;
	case crypt::Hash::sha3_384: return 48;
	case crypt::Hash::sha3_512: return 64;
	}
	return 0;
}

// ===========================================================================================================================================================================================
// ===========================================================================================================================================================================================

int crypt::help::Iterator::w = 0;
int crypt::help::Iterator::i = -1;
int crypt::help::Iterator::v = -1;

void crypt::help::Iterator::setup(int what, crypt::Cipher cipher)
{
	w = what;
	if (w < 0 || w > 2)
		w = 0;
	switch (w)
	{
	case Cipher:
		i = static_cast<int>(cipher);
		break;
	case Mode:
		v = static_cast<int>(cipher);
		i = -1;
		break;
	case Hash:
		i = -1;
		break;
	}
}

void crypt::help::Iterator::setup(int what, bool only_openssl)
{
	w = what;
	if (w < 0 || w > 2)
		w = 0;
	switch (w)
	{
	case Cipher:
		i = -1;
		break;
	case Mode:
		v = 0;
		i = -1;
		break;
	case Hash:
		i = -1;
		v = (only_openssl) ? 1 : 0;
		break;
	}
}

bool crypt::help::Iterator::next()
{
	i++;

	switch (w)
	{
	case Cipher:
		if (i < static_cast<int>(Cipher::COUNT))
		{
			return true;
		}
		else {
			i = -1;
			return false;
		}
	case Mode:
		while (i < static_cast<int>(Mode::COUNT))
		{
			unsigned int x = static_cast<unsigned int>(pow(2, i));
			if ((cipher_modes[v] & x) == x)
				return true;
			i++;
		}
		i = -1;
		return false;
	case Hash:
		if (v)
		{
			if (i < static_cast<int>(Hash::sha3_256))
				return true;
		}
		else {
			if (i < static_cast<int>(Hash::COUNT))
				return true;
		}
		i = -1;
		return false;
	}
	return false;
}

const TCHAR* crypt::help::Iterator::getString()
{
	if (i < 0)
		return NULL;

	switch (w)
	{
	case Cipher:
		return cipher_str[i];
	case Mode:
		return mode_str[i];
	case Hash:
		return hash_str[i];
	}
	return NULL;
}


const char* crypt::help::getString(crypt::Cipher cipher)
{
	return cipher_str_c[static_cast<int>(cipher)];
}

const char* crypt::help::getString(crypt::Mode mode)
{
	return mode_str_c[static_cast<int>(mode)];
}

const char*  crypt::help::getString(crypt::Encoding enc)
{
	return encoding_str_c[static_cast<int>(enc)];
}

const char* crypt::help::getString(crypt::KeyDerivation k)
{
	return key_algo_str_c[static_cast<int>(k)];
}

const char* crypt::help::getString(crypt::IV iv)
{
	return iv_str_c[static_cast<int>(iv)];
}

const char* crypt::help::getString(crypt::Hash h)
{
	return hash_str_c[static_cast<int>(h)];
}

const char* crypt::help::getString(crypt::Random mode)
{
	return random_mode_str_c[static_cast<int>(mode)];
}

bool crypt::help::getCipher(const char* s, crypt::Cipher& c)
{
	if (!s)
		return false;
	for (size_t i = 0; i< static_cast<int>(Cipher::COUNT); i++)
	{
		size_t sl = strlen(s), x = 0;
		if (sl != lstrlen(cipher_str[i]))
			continue;
		for (x = 0; x< sl; x++) {
			if (s[x] != (char)cipher_str[i][x])
				break;
		}
		if (x == sl) {
			c = (crypt::Cipher)i;
			return true;
		}
	}
	return false;
}

bool crypt::help::getCipherMode(const char* s, crypt::Mode& m)
{
	if (!s)
		return false;
	for (size_t i = 0; i< static_cast<int>(Mode::COUNT); i++)
	{
		size_t sl = strlen(s), x = 0;
		if (sl != lstrlen(mode_str[i]))
			continue;
		for (x = 0; x< sl; x++) {
			if (s[x] != (char)mode_str[i][x])
				break;
		}
		if (x == sl) {
			m = (crypt::Mode)i;
			return true;
		}
	}
	return false;
}

bool crypt::help::getKeyDerivation(const char*s, KeyDerivation& v)
{
	if (!s)
		return false;
	for (int i = 0; i<static_cast<int>(KeyDerivation::COUNT); i++)
	{
		if (strcmp(s, key_algo_str_c[i]) == 0) {
			v = (crypt::KeyDerivation)i;
			return true;
		}
	}
	return false;
}

bool crypt::help::getIVMode(const char* s, crypt::IV& iv)
{
	if (!s)
		return false;
	for (int i = 0; i<static_cast<int>(IV::COUNT); i++)
	{
		if (strcmp(s, iv_str_c[i]) == 0) {
			iv = (crypt::IV)i;
			return true;
		}
	}
	return false;
}

bool crypt::help::getEncoding(const char* s, crypt::Encoding& e)
{
	if (!s)
		return false;
	for (int i = 0; i<static_cast<int>(Encoding::COUNT); i++)
	{
		if (strcmp(s, encoding_str_c[i]) == 0) {
			e = (crypt::Encoding)i;
			return true;
		}
	}
	return false;
}

bool crypt::help::getRandomMode(const char* s, crypt::Random& m)
{
	if (!s)
		return false;
	for (int i = 0; i<static_cast<int>(crypt::Random::COUNT); i++)
	{
		if (strcmp(s, random_mode_str_c[i]) == 0) {
			m = (crypt::Random)i;
			return true;
		}
	}
	return false;
}

bool crypt::help::getHash(const char* s, Hash& h, bool only_openssl)
{
	if (!s)
		return false;
	size_t m = (only_openssl) ? static_cast<size_t>(Hash::sha3_256) : static_cast<size_t>(Hash::COUNT);
	for (size_t i = 0; i< m; i++)
	{
		size_t sl = strlen(s), x = 0;
		if (sl != lstrlen(hash_str[i]))
			continue;
		for (x = 0; x< sl; x++) {
			if (s[x] != (char)hash_str[i][x])
				break;
		}
		if (x == sl) {
			h = (Hash)i;
			return true;
		}
	}
	return false;
}

crypt::Mode crypt::help::getModeByIndex(crypt::Cipher cipher, int index)
{
	int i = 0;
	int modes = 0;
	while (i < static_cast<int>(Mode::COUNT))
	{
		unsigned int x = static_cast<unsigned int>(pow(2, i));
		if ((cipher_modes[static_cast<int>(cipher)] & x) == x) {
			if (index == modes)
				return (crypt::Mode)i;
			modes++;
		}
		i++;
	}
	return Mode::cbc;
}

int crypt::help::getIndexByMode(crypt::Cipher cipher, crypt::Mode mode)
{
	int i = 0;
	int modes = 0;
	while (i < static_cast<int>(Mode::COUNT))
	{
		unsigned int x = static_cast<unsigned int>(pow(2, i));
		if ((cipher_modes[static_cast<int>(cipher)] & x) == x) {
			if ((crypt::Mode)i == mode)
				return modes;
			modes++;
		}
		i++;
	}
	return -1;
}

bool crypt::help::validCipherMode(crypt::Cipher cipher, crypt::Mode mode)
{
	unsigned int x = static_cast<unsigned int>(std::pow(2, static_cast<int>(mode)));
	if ((cipher_modes[static_cast<int>(cipher)] & x) == x)
		return true;
	else
		return false;
}

bool crypt::help::IsOpenSSLHash(crypt::Hash h)
{
	return (h < Hash::sha3_256);
}

const TCHAR* crypt::help::getHelpURL(crypt::Encoding enc)
{
	lstrcpy(help_url_wikipedia + help_url_wikipedia_len, help_url_encoding[unsigned(enc)]);
	return help_url_wikipedia;
}

const TCHAR* crypt::help::getHelpURL(crypt::Cipher cipher)
{
	lstrcpy(help_url_wikipedia + help_url_wikipedia_len, help_url_cipher[unsigned(cipher)]);
	return help_url_wikipedia;
}

const TCHAR* crypt::help::getHelpURL(crypt::Hash h)
{
	lstrcpy(help_url_wikipedia + help_url_wikipedia_len, help_url_hash[unsigned(h)]);
	return help_url_wikipedia;
}

const TCHAR* crypt::help::getHelpURL(crypt::KeyDerivation k)
{
	lstrcpy(help_url_wikipedia + help_url_wikipedia_len, help_url_keyderiv[unsigned(k)]);
	return help_url_wikipedia;
}

const TCHAR* crypt::help::getHelpURL(crypt::Mode m)
{
	lstrcpy(help_url_wikipedia + help_url_wikipedia_len, help_url_mode[unsigned(m)]);
	return help_url_wikipedia;
}