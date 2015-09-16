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
static const unsigned int cipher_modes[Crypt::Cipher::COUNT] = { cbc|ecb|cfb|ofb, 
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
																cbc|ecb|cfb|ofb|ctr|xts|ccm|gcm, };

// ----------------------------- STRINGS ---------------------------------------------------------------------------------------------------------------------------------------------------------

static const TCHAR* cipher_str[] = {TEXT("des"), TEXT("des_ede"), TEXT("des_ede3"), TEXT("desx"), TEXT("rc2"), TEXT("rc4"), TEXT("rc5"), TEXT("idea"), TEXT("blowfish"), TEXT("cast5"), TEXT("aes128"), TEXT("aes192"), TEXT("aes256") };
static const TCHAR* mode_str[] = {TEXT("ecb"), TEXT("cbc"), TEXT("cfb"), TEXT("ofb"), TEXT("ctr"), TEXT("xts"), TEXT("ccm"), TEXT("gcm")};
static const char* encoding_str_c[] = {"ascii", "base16", "base64"};
static const char* key_algo_str_c[] = { "pbkdf2", "bcrypt", "scrypt" };
static const TCHAR* hash_str[] = {TEXT("md4"), TEXT("md5"), TEXT("sha1"), TEXT("sha256"), TEXT("sha512"), TEXT("ripemd160"), TEXT("whirlpool"), TEXT("sha3_256"), TEXT("sha3_384"), TEXT("sha3_512")};

// ----------------------------- MAIN FUNCTIONS ---------------------------------------------------------------------------------------------------------------------------------------------------

const EVP_CIPHER* getEVPCipher(Crypt::Cipher c, Crypt::Mode m)
{
	switch(c) {
	case Crypt::Cipher::blowfish: 
		switch(m) {
		case Crypt::Mode::cbc: return EVP_bf_cbc();
		case Crypt::Mode::ecb: return EVP_bf_ecb();
		case Crypt::Mode::cfb: return EVP_bf_cfb();
		case Crypt::Mode::ofb: return EVP_bf_ofb();
		}
		break;
	case Crypt::Cipher::des:
		switch(m) {
		case Crypt::Mode::cbc: return EVP_des_cbc();
		case Crypt::Mode::ecb: return EVP_des_ecb();
		case Crypt::Mode::cfb: return EVP_des_cfb();
		case Crypt::Mode::ofb: return EVP_des_ofb();
		}
		break;
	case Crypt::Cipher::des_ede:
		switch(m) {
		case Crypt::Mode::cbc: return EVP_des_ede_cbc();
		case Crypt::Mode::ecb: return EVP_des_ede_ecb();
		case Crypt::Mode::cfb: return EVP_des_ede_cfb();
		case Crypt::Mode::ofb: return EVP_des_ede_ofb();
		}
		break;
	case Crypt::Cipher::des_ede3:
		switch(m) {
		case Crypt::Mode::cbc: return EVP_des_ede3_cbc();
		case Crypt::Mode::ecb: return EVP_des_ede3_ecb();
		case Crypt::Mode::cfb: return EVP_des_ede3_cfb();
		case Crypt::Mode::ofb: return EVP_des_ede3_ofb();
		}
		break;
	case Crypt::Cipher::rc2:
		switch(m) {
		case Crypt::Mode::cbc: return EVP_rc2_cbc();
		case Crypt::Mode::ecb: return EVP_rc2_ecb();
		case Crypt::Mode::cfb: return EVP_rc2_cfb();
		case Crypt::Mode::ofb: return EVP_rc2_ofb();
		}
		break;
	case Crypt::Cipher::idea:
		switch(m) {
		case Crypt::Mode::cbc: return EVP_idea_cbc();
		case Crypt::Mode::ecb: return EVP_idea_ecb();
		case Crypt::Mode::cfb: return EVP_idea_cfb();
		case Crypt::Mode::ofb: return EVP_idea_ofb();
		}
		break;
	case Crypt::Cipher::cast5:
		switch(m) {
		case Crypt::Mode::cbc: return EVP_cast5_cbc();
		case Crypt::Mode::ecb: return EVP_cast5_ecb();
		case Crypt::Mode::cfb: return EVP_cast5_cfb();
		case Crypt::Mode::ofb: return EVP_cast5_ofb();
		}
		break;
	case Crypt::Cipher::aes128:
		switch(m) {
		case Crypt::Mode::cbc: return EVP_aes_128_cbc();
		case Crypt::Mode::ecb: return EVP_aes_128_ecb();
		case Crypt::Mode::cfb: return EVP_aes_128_cfb();
		case Crypt::Mode::ofb: return EVP_aes_128_ofb();
		case Crypt::Mode::ctr: return EVP_aes_128_ctr();
		case Crypt::Mode::xts: return EVP_aes_128_xts();
		case Crypt::Mode::ccm: return EVP_aes_128_ccm();
		case Crypt::Mode::gcm: return EVP_aes_128_gcm();
		}
		break;
	case Crypt::Cipher::aes192:
		switch(m) {
		case Crypt::Mode::cbc: return EVP_aes_192_cbc();
		case Crypt::Mode::ecb: return EVP_aes_192_ecb();
		case Crypt::Mode::cfb: return EVP_aes_192_cfb();
		case Crypt::Mode::ofb: return EVP_aes_192_ofb();
		case Crypt::Mode::ctr: return EVP_aes_192_ctr();
		case Crypt::Mode::ccm: return EVP_aes_192_ccm();
		case Crypt::Mode::gcm: return EVP_aes_192_gcm();
		}
		break;
	case Crypt::Cipher::aes256:
		switch(m) {
		case Crypt::Mode::cbc: return EVP_aes_256_cbc();
		case Crypt::Mode::ecb: return EVP_aes_256_ecb();
		case Crypt::Mode::cfb: return EVP_aes_256_cfb();
		case Crypt::Mode::ofb: return EVP_aes_256_ofb();
		case Crypt::Mode::ctr: return EVP_aes_256_ctr();
		case Crypt::Mode::xts: return EVP_aes_256_xts();
		case Crypt::Mode::ccm: return EVP_aes_256_ccm();
		case Crypt::Mode::gcm: return EVP_aes_256_gcm();
		}
		break;
	case Crypt::Cipher::desx:
		switch(m) {
			case Crypt::Mode::cbc: return EVP_desx_cbc();
		}
		break;
	case Crypt::Cipher::rc4:
		return EVP_rc4();
	case Crypt::Cipher::rc5:
		switch(m) {
		case Crypt::Mode::cbc: return EVP_rc5_32_12_16_cbc();
		case Crypt::Mode::ecb: return EVP_rc5_32_12_16_ecb();
		case Crypt::Mode::cfb: return EVP_rc5_32_12_16_cfb();
		case Crypt::Mode::ofb: return EVP_rc5_32_12_16_ofb();
		}
		break;
	}
	return NULL;
}

const EVP_MD* getEVPHash(Crypt::Hash algo)
{
	switch(algo) {
	case Crypt::Hash::md4: return EVP_md4();
	case Crypt::Hash::md5: return EVP_md5();
	case Crypt::Hash::sha1: return EVP_sha1();
	case Crypt::Hash::sha256: return EVP_sha256();
	case Crypt::Hash::sha512: return EVP_sha512();
	case Crypt::Hash::ripemd160: return EVP_ripemd160();
	case Crypt::Hash::whirlpool: return EVP_whirlpool();
	}
	return NULL;
}

void Crypt::doCrypt(Operation op, const unsigned char* in, size_t in_len, std::vector<unsigned char>& buffer, Crypt::Options* options, std::string& s_iv, std::string& s_salt, std::string& s_tag)
{
	if(!in || !in_len || !options)
		throw CExc(CExc::crypt,__LINE__);

	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER* tCipher = getEVPCipher(options->cipher, options->mode);
	if(!tCipher)
		throw CExc(CExc::crypt,__LINE__);

	std::vector<unsigned char>	tKey;
	std::vector<unsigned char>	tVec;
	std::vector<unsigned char>	tSalt;
	const unsigned char*		ptVec=NULL;
	const unsigned char*		ptSalt=NULL;
	unsigned int				iv_len=0;

	// ------------- Prepare Key and IV -----------------------------------------------------------------------------------------
	if(!options->password.size())
		throw CExc(CExc::crypt,__LINE__);

	// ------- Salt:
	if(options->key.salt_bytes) {
		tSalt.resize(options->key.salt_bytes);
		// ---- Encryption: get random bytes:
		if(op == Crypt::Operation::Encryption) {
			RAND_bytes(&tSalt[0], options->key.salt_bytes);
		} else {
		// ---- Decryption: decode header information
			if(!s_salt.size())
				throw CExc(TEXT("Decryption: salt missing."));
			if(Encode::base64_to_bin(s_salt.c_str(),s_salt.size()) != (size_t)options->key.salt_bytes)
				throw CExc(TEXT("Decryption: salt corrupted."));
			Encode::base64_to_bin(s_salt.c_str(),s_salt.size(),&tSalt[0]);
		}
		ptSalt = &tSalt[0];
	}

	// --------- prepare IV and Key Vector:
	if(options->mode == Crypt::Mode::gcm)
		iv_len = Constants::gcm_iv_length;
	else if(options->mode == Crypt::Mode::ccm)
		iv_len = Constants::ccm_iv_length;
	else
		iv_len = tCipher->iv_len;

	if(options->iv == Crypt::InitVector::keyderivation) {
		tKey.resize(tCipher->key_len+iv_len);
		if(iv_len > 0)
			ptVec = &tKey[tCipher->key_len];

	} else if(options->iv == Crypt::InitVector::random) {
		tKey.resize(tCipher->key_len);
		if(iv_len > 0) {
			tVec.resize(iv_len);
			if(op == Crypt::Operation::Encryption) {
				RAND_bytes(&tVec[0], iv_len);
			} else {
				if(!s_iv.size())
					throw CExc(TEXT("Decryption: iv missing."));
				if(Encode::base64_to_bin(s_iv.c_str(),s_iv.size()) != tVec.size())
					throw CExc(TEXT("Decryption: iv corrupted."));
				Encode::base64_to_bin(s_iv.c_str(),s_iv.size(),&tVec[0]);
			}
			ptVec=&tVec[0];
		}

	} else if(options->iv == Crypt::InitVector::zero) {
		tKey.resize(tCipher->key_len);
		ptVec=NULL;
	}

	switch(options->key.algorithm) {
	case Crypt::KeyDerivation::pbkdf2:
		{
		const EVP_MD* hash_md = getEVPHash((Hash)options->key.option1);
		if(!hash_md)
			throw CExc(CExc::crypt,__LINE__);
		if(PKCS5_PBKDF2_HMAC(options->password.c_str(), options->password.size(), ptSalt, options->key.salt_bytes, options->key.option2, hash_md, (int)tKey.size(), &tKey[0]) != 1)
			throw CExc(CExc::crypt,__LINE__);
		break;
		}
	case Crypt::KeyDerivation::bcrypt:
		{
		char output[64];
			char settings[32];
			unsigned char nullSalt[16];
			
		if(options->key.salt_bytes != 16) {
			memset(nullSalt, 0 , 16);
			ptSalt = nullSalt;
		}
		if(_crypt_gensalt_blowfish_rn("$2a$", (unsigned long)options->key.option1, (const char*)ptSalt, 16, settings, 32)==NULL)
			throw CExc(CExc::crypt,__LINE__);
		memset(output, 0, sizeof(output));
		if(_crypt_blowfish_rn(options->password.c_str(), settings, output, 64, true)==NULL)
			throw CExc(CExc::crypt,__LINE__);

		Keccak_HashInstance keccak_inst;
		if(Keccak_HashInitialize_SHAKE128(&keccak_inst)!=0)
			throw CExc(CExc::crypt,__LINE__);
		if(Keccak_HashUpdate(&keccak_inst, (unsigned char*)output, 24 * 8)!=0)
			throw CExc(CExc::crypt,__LINE__);
		if(Keccak_HashFinal(&keccak_inst, &tKey[0])!=0)
			throw CExc(CExc::crypt,__LINE__);
		if(Keccak_HashSqueeze(&keccak_inst, &tKey[0], tKey.size()*8)!=0)
			throw CExc(CExc::crypt,__LINE__);

		break;
		}
	case Crypt::KeyDerivation::scrypt:
		if(crypto_scrypt((unsigned char*)options->password.c_str(), options->password.size(), ptSalt, options->key.salt_bytes, std::pow(2,options->key.option1), options->key.option2, options->key.option3, &tKey[0], tKey.size()) != 0)
			throw CExc(CExc::crypt,__LINE__);
		break;
	}
	
	// ------------ return encoded IV and Salt for header ---------------------------------------------------------------------------------------------------------------
	if(op == Crypt::Operation::Encryption) {
		if(options->iv == Crypt::InitVector::random && tVec.size() > 0) {
			s_iv.resize(Encode::bin_to_base64(&tVec[0], tVec.size(), NULL, true));
			if(s_iv.size())
				Encode::bin_to_base64(&tVec[0], tVec.size(), &s_iv[0], true);
		}
		if(options->key.salt_bytes > 0) {
			s_salt.resize(Encode::bin_to_base64(&tSalt[0], tSalt.size(), NULL, true));
			if(s_salt.size())
				Encode::bin_to_base64(&tSalt[0], tSalt.size(), &s_salt[0], true);
		}
	}

	// ----------------------------------------------------------------------------------------------------------------------------------------------
	try {
		EVP_CIPHER_CTX_init(&ctx);

		// ----------------------------------------------------------------------------------------------------------------------------------------------
		// ============= ENCRYPTION =====================================================================================================================
		if(op == Operation::Encryption) {

			// ------------- Init Encryption --------------------------------------------------------------------------------------
			if(!EVP_EncryptInit_ex(&ctx, tCipher, NULL, NULL, NULL))
				throw CExc(CExc::crypt,__LINE__);

			// ------ gcm/ccm init -----------------------
			if(options->mode == Crypt::Mode::gcm) {
				if(1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, Constants::gcm_iv_length, NULL))
					throw CExc(CExc::crypt,__LINE__);
			} else if(options->mode == Crypt::Mode::ccm) {
				if(1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_L, 15 - Constants::ccm_iv_length, NULL))
					throw CExc(CExc::crypt,__LINE__);
				if(1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, Constants::ccm_iv_length, NULL))
					throw CExc(CExc::crypt,__LINE__);
				if(1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, 16, NULL))
					throw CExc(CExc::crypt,__LINE__);
			}
			// -------------------------------------------
			if(1 != EVP_EncryptInit_ex(&ctx, NULL, NULL, &tKey[0], ptVec))
				throw CExc(CExc::crypt,__LINE__);

			// -------------------------------------------------------------------------------------------------------------------------------------------

			int							clen=0;
			size_t						olen=0;			
			std::vector<unsigned char>	tBuf;
			unsigned char*				pBuf;

			// -------------- ASCII: write directly to buffer --------------------------------------
			if(options->encoding == Crypt::Encoding::ascii) {
				buffer.resize(in_len + EVP_MAX_BLOCK_LENGTH);
				pBuf = &buffer[0];

			// -------------- HEX/BASE64: temp Buffer needed ---------------------------------------
			} else {
				tBuf.resize(in_len + EVP_MAX_BLOCK_LENGTH);
				pBuf = &tBuf[0];
			}

			// -------------- ccm-mode has to know input length in advance -------------------------
			if(options->mode == Crypt::Mode::ccm) {				
				if(in_len > (unsigned)std::numeric_limits<int>::max())
					throw CExc(CExc::crypt,__LINE__, TEXT("input too long."));
				if(1 != EVP_EncryptUpdate(&ctx, NULL, &clen, NULL, in_len))
					throw CExc(CExc::crypt,__LINE__);
			}
			// -------------- add salt and iv strings as AAD data for gcm and ccm ------------------
			if(options->mode == Crypt::Mode::gcm || options->mode == Crypt::Mode::ccm) {
				if(1 != EVP_EncryptUpdate(&ctx, NULL, &clen, (const unsigned char*)s_salt.c_str(), s_salt.size()))
					throw CExc(CExc::crypt,__LINE__);
				if(1 != EVP_EncryptUpdate(&ctx, NULL, &clen, (const unsigned char*)s_iv.c_str(), s_iv.size()))
					throw CExc(CExc::crypt,__LINE__);
			}

			// -------------- encrypt data ---------------------------------------------------------
			if (1 != EVP_EncryptUpdate(&ctx, pBuf, &clen, in, in_len))
				throw CExc(CExc::crypt,__LINE__);
			olen += (size_t)clen;
			if (1 != EVP_EncryptFinal_ex(&ctx, pBuf+olen, &clen))
				throw CExc(CExc::crypt,__LINE__, CExc::encrypt);
			olen += (size_t)clen;

			switch(options->encoding) {
			// -------------- ASCII Output -----------------------------------------------------------
			case Crypt::Encoding::ascii:
				buffer.resize(olen);
				break;
			// -------------- HEX Output -----------------------------------------------------------
			case Crypt::Encoding::hex:
				buffer.resize(Encode::bin_to_hex(NULL, olen));
				Encode::bin_to_hex(pBuf, olen, (char*)&buffer[0]);
				break;
			// -------------- BASE64 Output --------------------------------------------------------
			case Crypt::Encoding::base64:
				buffer.resize(Encode::bin_to_base64(NULL, olen));
				Encode::bin_to_base64(pBuf, olen, (char*)&buffer[0]);
				break;
			}

			// -------------- GCM/CCM-Mode: get tag-data -------------------------------------------
			if(options->mode == Crypt::Mode::gcm || options->mode == Crypt::Mode::ccm) {
				unsigned char tag[16];
				int type= (options->mode == Crypt::Mode::gcm) ? EVP_CTRL_GCM_GET_TAG : EVP_CTRL_CCM_GET_TAG;
				if(1 != EVP_CIPHER_CTX_ctrl(&ctx, type, 16, tag))
					throw CExc(CExc::crypt,__LINE__);
				s_tag.resize(24);
				Encode::bin_to_base64(tag, 16, &s_tag[0], true);
			}


		// ========================= DECRYPTION ===========================================================================================================
		} else {

			// ------------- Init Decryption -------------------------------------------------------------------------------------
			if(!EVP_DecryptInit_ex(&ctx, tCipher, NULL, NULL, NULL))
				throw CExc(CExc::crypt,__LINE__);

			// ------------ gcm/ccm init:
			if(options->mode == Crypt::Mode::gcm || options->mode == Crypt::Mode::ccm) {
				unsigned char tag[16];
				if(!s_tag.size())
					throw CExc(TEXT("Decryption: tag missing."));
				if(Encode::base64_to_bin(s_tag.c_str(),s_tag.size()) != 16)
					throw CExc(TEXT("Decryption: tag corrupted."));
				Encode::base64_to_bin(s_tag.c_str(),s_tag.size(),tag);

				if(options->mode == Crypt::Mode::gcm) {
					if(1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, Constants::gcm_iv_length, NULL))
						throw CExc(CExc::crypt,__LINE__);
					if(1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
						throw CExc(CExc::crypt,__LINE__);
				} else {
					if(1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_L, 15 - Constants::ccm_iv_length, NULL))
						throw CExc(CExc::crypt,__LINE__);
					if(1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, Constants::ccm_iv_length, NULL))
						throw CExc(CExc::crypt,__LINE__);
					if(1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, 16, tag))
						throw CExc(CExc::crypt,__LINE__);
				}
			}
			// ------------------------
			if(!EVP_DecryptInit_ex(&ctx, NULL, NULL, &tKey[0], ptVec))
				throw CExc(CExc::crypt,__LINE__);

			// ----------------------------------------------------------------------------------------------------------------------------

			int							clen;
			size_t						ilen, olen;
			std::vector<unsigned char>	tBuf;
			const unsigned char*		pIn;

			switch(options->encoding) {
			// ------------- ASCII Input ----------------------------------------------------
			case Crypt::Encoding::ascii:
				buffer.resize(in_len);
				pIn = in;
				ilen = in_len;
				break;
			// ------------- Hex Input ------------------------------------------------------
			case Crypt::Encoding::hex:
				tBuf.resize(in_len/2 + EVP_MAX_BLOCK_LENGTH);
				ilen = Encode::hex_to_bin((const char*)in, in_len, &tBuf[0]);
				buffer.resize(tBuf.size());
				pIn = &tBuf[0];
				break;
			// ------------- Base64 Input ---------------------------------------------------
			case Crypt::Encoding::base64:
				tBuf.resize(static_cast<size_t>(in_len*0.8));
				ilen = Encode::base64_to_bin((const char*)in, in_len, &tBuf[0]);
				buffer.resize(tBuf.size());
				pIn = &tBuf[0];
				break;
			}

			// -------------- ccm-mode has to know input length in advance -------------------------
			if(options->mode == Crypt::Mode::ccm) {
				if(1 != EVP_DecryptUpdate(&ctx, NULL, &clen, NULL, ilen))
					throw CExc(CExc::crypt,__LINE__, CExc::decrypt);
			}

			// -------------- add salt and iv strings as AAD data for gcm and ccm ------------------
			if(options->mode == Crypt::Mode::ccm || options->mode == Crypt::Mode::gcm) {
				if(1 != EVP_DecryptUpdate(&ctx, NULL, &clen, (const unsigned char*)s_salt.c_str(), s_salt.size()))
					throw CExc(CExc::crypt,__LINE__);
				if(1 != EVP_DecryptUpdate(&ctx, NULL, &clen, (const unsigned char*)s_iv.c_str(), s_iv.size()))
					throw CExc(CExc::crypt,__LINE__);
			}

			if(1 != EVP_DecryptUpdate(&ctx, &buffer[0], &clen, pIn, ilen))
				throw CExc(CExc::crypt,__LINE__);
			olen = (size_t)clen;

			// ------------- ccm mode doesn't like EVP_DecryptFinal_ex
			if(options->mode != Crypt::Mode::ccm) {
				if (1 != EVP_DecryptFinal_ex(&ctx, &buffer[0]+clen, &clen))
					throw CExc(CExc::crypt,__LINE__, CExc::decrypt);
				olen += (size_t)clen;
			}

			buffer.resize(olen);
		}

		// --------------------------- Cleanup ---------------------------------------------------------------------------------
		EVP_CIPHER_CTX_cleanup(&ctx);

	} catch(CExc& exc) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		throw(exc);
	} catch(...) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		throw CExc(CExc::crypt,__LINE__);
	}
}

void Crypt::doHash(const unsigned char* in, size_t in_len, std::vector<unsigned char>& buffer, const HashOptions* options)
{
	if((!in && in_len>0) || !options)
		throw CExc(CExc::crypt,__LINE__);
	int hash_len;
	unsigned char hash[64];

	if(options->algorithm == Hash::sha3_256 || options->algorithm == Hash::sha3_384 || options->algorithm == Hash::sha3_512) {

		Keccak_HashInstance keccak_inst;
		switch(options->algorithm) {
		case Hash::sha3_256:
			if(Keccak_HashInitialize_SHA3_256(&keccak_inst)!=0) throw CExc(CExc::crypt,__LINE__);
			hash_len = 32;
			break;
		case Hash::sha3_384:
			if(Keccak_HashInitialize_SHA3_384(&keccak_inst)!=0) throw CExc(CExc::crypt,__LINE__);
			hash_len = 48;
			break;
		case Hash::sha3_512:
			if(Keccak_HashInitialize_SHA3_512(&keccak_inst)!=0) throw CExc(CExc::crypt,__LINE__);
			hash_len = 64;
			break;
		}
		if(Keccak_HashUpdate(&keccak_inst, in, in_len * 8)!=0)
			throw CExc(CExc::crypt,__LINE__);
		if(Keccak_HashFinal(&keccak_inst, hash)!=0)
			throw CExc(CExc::crypt,__LINE__);

	} else {
		EVP_MD_CTX mdctx;
		size_t md_len;
		const EVP_MD* md = getEVPHash(options->algorithm);
		if(!md)
			throw CExc(CExc::crypt,__LINE__);

		EVP_MD_CTX_init(&mdctx);
		if(!EVP_DigestInit_ex(&mdctx, md, NULL))
			throw CExc(CExc::crypt,__LINE__);
		if(!EVP_DigestUpdate(&mdctx, in, in_len))
			throw CExc(CExc::crypt,__LINE__);
		if(!EVP_DigestFinal_ex(&mdctx, hash, &md_len))
			throw CExc(CExc::crypt,__LINE__);
		if(!EVP_MD_CTX_cleanup(&mdctx))
			throw CExc(CExc::crypt,__LINE__);

		hash_len = md->md_size;
	}

	buffer.clear();
	if(options->encoding == Encoding::ascii) {
		buffer.resize(hash_len);
		memcpy(&buffer[0], hash, hash_len);

	} else if(options->encoding == Encoding::hex) {
		buffer.resize(Encode::bin_to_hex(NULL, hash_len));
		Encode::bin_to_hex(hash,hash_len,(char*)&buffer[0]);

	} else {
		buffer.resize(Encode::bin_to_base64(NULL, hash_len));
		Encode::bin_to_base64(hash,hash_len,(char*)&buffer[0]);
	}
}

void Crypt::hmac(const char* header, unsigned int header_len, const unsigned char* data, unsigned int data_len, Hash algo, const unsigned char* key, size_t key_len, std::string& out)
{
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	const EVP_MD* md = getEVPHash(algo);

	if(!header || !header_len || !data || !data_len)
		throw CExc(CExc::crypt,__LINE__);
	if(!md)
		throw CExc(CExc::crypt,__LINE__);

	try {
		if(1 != HMAC_Init_ex(&ctx, key, key_len, md, NULL))
			throw CExc(CExc::crypt,__LINE__);
		if(1 != HMAC_Update(&ctx, (const unsigned char*)header, header_len))
			throw CExc(CExc::crypt,__LINE__);
		if(1 != HMAC_Update(&ctx, (const unsigned char*)data, data_len))
			throw CExc(CExc::crypt,__LINE__);
		size_t len;
		unsigned char buf[EVP_MAX_MD_SIZE];
		if(1 != HMAC_Final(&ctx, buf, &len))
			throw CExc(CExc::crypt,__LINE__);
		if(!len)
			throw CExc(CExc::crypt,__LINE__);

		out.resize(Encode::bin_to_base64(NULL, len, NULL, true));
		Encode::bin_to_base64(buf, len, &out[0], true);

		HMAC_CTX_cleanup(&ctx);

	} catch(CExc& exc) {
		HMAC_CTX_cleanup(&ctx);
		throw exc;
	}
}

void Crypt::hmac(const unsigned char* data, unsigned int data_len, const Crypt::HashOptions& options, std::vector<unsigned char>& out)
{
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	const EVP_MD* md = getEVPHash(options.algorithm);

	if(!data || !data_len)
		throw CExc(CExc::crypt,__LINE__);
	if(!md)
		throw CExc(CExc::crypt,__LINE__);

	try {
		if(1 != HMAC_Init_ex(&ctx, options.key.c_str(), options.key.size(), md, NULL))
			throw CExc(CExc::crypt,__LINE__);
		if(1 != HMAC_Update(&ctx, (const unsigned char*)data, data_len))
			throw CExc(CExc::crypt,__LINE__);
		size_t len;
		unsigned char buf[EVP_MAX_MD_SIZE];
		if(1 != HMAC_Final(&ctx, buf, &len))
			throw CExc(CExc::crypt,__LINE__);
		if(!len)
			throw CExc(CExc::crypt,__LINE__);

		switch(options.encoding) {
		case Crypt::Encoding::ascii:
			out.resize(len);
			memcpy(&out[0], buf, len);
			break;
		case Crypt::Encoding::hex:
			out.resize(Encode::bin_to_hex(NULL, len));
			Encode::bin_to_hex(buf,len,(char*)&out[0]);
			break;
		case Crypt::Encoding::base64:
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

void Crypt::getRandom(const RandOptions* options, std::vector<unsigned char>& buffer)
{
	if(!options || !options->length)
		throw CExc(CExc::crypt,__LINE__);

	buffer.clear();

	switch(options->mode) {
	case RandomMode::ascii:
		buffer.resize(options->length);
		if(RAND_bytes(&buffer[0], (int)options->length) != 1)
			throw CExc(CExc::crypt,__LINE__);
		break;
	case RandomMode::hex:
		{
		std::vector<unsigned char> tbuf;
		tbuf.resize(options->length);
		if(RAND_bytes(&tbuf[0], (int)options->length) != 1)
			throw CExc(CExc::crypt,__LINE__);
		buffer.resize(Encode::bin_to_hex(NULL,tbuf.size()));
		Encode::bin_to_hex(&tbuf[0], tbuf.size(), (char*)&buffer[0]);
		break;
		}
	case RandomMode::base64:
		{
		std::vector<unsigned char> tbuf;
		tbuf.resize(options->length);
		if(RAND_bytes(&tbuf[0], (int)options->length) != 1)
			throw CExc(CExc::crypt,__LINE__);
		buffer.resize(Encode::bin_to_base64(NULL,tbuf.size()));
		Encode::bin_to_base64(&tbuf[0], tbuf.size(), (char*)&buffer[0]);
		break;
		}
	case RandomMode::charnum:
		{
		buffer.resize(options->length);
		unsigned char temp[Constants::rand_char_bufsize];
		size_t i = 0;
		while(i<options->length) {
			if(RAND_bytes(temp,Constants::rand_char_bufsize) != 1)
				throw CExc(CExc::crypt,__LINE__);
			for(int x=0; x<Constants::rand_char_bufsize && i<options->length; x++) {
				if(temp[x] < 62) {
					if(temp[x] < 10) {
						buffer[i] = 48+temp[x];
					} else if(temp[x] < 36) {
						buffer[i] = 55+temp[x];
					} else {
						buffer[i] = 61+temp[x];
					}
					i++;
				}
			}
		}
		break;
		}
	case RandomMode::specials:
		{
		buffer.resize(options->length);
		unsigned char temp[Constants::rand_char_bufsize];
		size_t i = 0;
		while(i<options->length) {
			if(RAND_bytes(temp, Constants::rand_char_bufsize) != 1)
				throw CExc(CExc::crypt,__LINE__);
			for(int x=0; x<Constants::rand_char_bufsize && i<options->length; x++) {
				if(temp[x] > 32 && temp[x] < 127) {
					buffer[i] = temp[x];
					i++;
				}
			}
		}
		break;
		}
	}
}

size_t Crypt::getMDLength(Hash h)
{
	switch(h) {
	case Crypt::Hash::md4: return 16;
	case Crypt::Hash::md5: return 16;
	case Crypt::Hash::ripemd160: return 20;
	case Crypt::Hash::sha1: return 20;
	case Crypt::Hash::sha256: return 32;
	case Crypt::Hash::sha512: return 64;
	case Crypt::Hash::whirlpool: return 64;
	case Crypt::Hash::sha3_256: return 32;
	case Crypt::Hash::sha3_384: return 48;
	case Crypt::Hash::sha3_512: return 64;
	}
	return 0;
}

void Crypt::shake128(const unsigned char* in, size_t in_len, unsigned char* out, size_t out_len)
{
	Keccak_HashInstance keccak_inst;
	if(Keccak_HashInitialize_SHAKE128(&keccak_inst)!=0)
		throw CExc(CExc::crypt,__LINE__);
	if(Keccak_HashUpdate(&keccak_inst, in, in_len * 8)!=0)
		throw CExc(CExc::crypt,__LINE__);
	if(Keccak_HashFinal(&keccak_inst, out)!=0)
		throw CExc(CExc::crypt,__LINE__);
	if(Keccak_HashSqueeze(&keccak_inst, out, out_len * 8)!=0)
		throw CExc(CExc::crypt,__LINE__);
}

/// ==========================================================================================================================================================================
/// ========== STRING FUNCTIONS ==============================================================================================================================================
/// ==========================================================================================================================================================================

// ============================== CRYPT ======================================================================================================================================

int Crypt::Strings::cipher_id = -1;
int Crypt::Strings::mode_id = -1;
int Crypt::Strings::hash_id = -1;

void Crypt::Strings::setup()
{
	cipher_id = -1;
	mode_id = -1;
};

bool Crypt::Strings::nextCipher()
{
	cipher_id++;
	if(cipher_id < static_cast<int>(Cipher::COUNT))
	{
		return true;
	} else {
		cipher_id=-1;
		return false;
	}
};

void Crypt::Strings::setCipher(Crypt::Cipher cipher) {
	cipher_id = static_cast<int>(cipher);
	mode_id = -1;
}

bool Crypt::Strings::nextMode()
{
	mode_id++;
	while(mode_id < static_cast<int>(Mode::COUNT)) {
		unsigned int x = static_cast<unsigned int>(pow(2, mode_id));
		if((cipher_modes[cipher_id] & x) == x)
			return true;
		mode_id++;
	}
	return false;
};

std::string Crypt::Strings::Mode(Crypt::Mode mode)
{
	std::string ret;
	ret.resize(lstrlen(mode_str[static_cast<int>(mode)]));
	for(size_t i=0; i<ret.size(); i++)
		ret[i] = static_cast<char>(mode_str[static_cast<int>(mode)][i]);
	return ret;
}

std::string Crypt::Strings::Cipher(Crypt::Cipher cipher)
{
	std::string ret;
	ret.resize(lstrlen(cipher_str[static_cast<int>(cipher)]));
	for(size_t i=0; i<ret.size(); i++)
		ret[i] = static_cast<char>(cipher_str[static_cast<int>(cipher)][i]);
	return ret;
}

const char*  Crypt::Strings::Encoding(Crypt::Encoding enc)
{
	return encoding_str_c[static_cast<int>(enc)];
}

const char* Crypt::Strings::KeyAlgorithm(Crypt::KeyDerivation k)
{
	return key_algo_str_c[static_cast<int>(k)];
}

const TCHAR* Crypt::Strings::Cipher()
{
	if(cipher_id >= 0 )
		return cipher_str[cipher_id];
	else
		return NULL;
};

const TCHAR* Crypt::Strings::Mode() {
	if(mode_id >= 0)
		return mode_str[mode_id];
	else
		return NULL;
};

Crypt::Mode Crypt::Strings::getModeByIndex(Crypt::Cipher cipher, int index)
{
	int i = 0;
	int modes=0;
	while(i < static_cast<int>(Mode::COUNT)) {
		unsigned int x = static_cast<unsigned int>(pow(2, i));
		if((cipher_modes[static_cast<int>(cipher)] & x) == x) {
			if(index==modes)
				return (Crypt::Mode)i;
			modes++;
		}
		i++;
	}
	return Mode::cbc;
}

int Crypt::Strings::getIndexByMode(Crypt::Cipher cipher, Crypt::Mode mode)
{
	int i = 0;
	int modes=0;
	while(i < static_cast<int>(Mode::COUNT)) {
		unsigned int x = static_cast<unsigned int>(pow(2, i));
		if((cipher_modes[static_cast<int>(cipher)] & x) == x) {
			if((Crypt::Mode)i == mode)
				return modes;
			modes++;
		}
		i++;
	}
	return -1;
}

bool Crypt::Strings::getCipherByString(const char* s, Crypt::Cipher& c)
{
	if(!s)
		return false;
	for(size_t i=0; i< static_cast<int>(Cipher::COUNT); i++) {
		size_t sl = strlen(s), x=0;
		if(sl != lstrlen(cipher_str[i]))
			continue;
		for(x=0; x< sl; x++) {
			if(s[x] != (char)cipher_str[i][x])
				break;
		}
		if(x == sl) {
			c = (Crypt::Cipher)i;
			return true;
		}
	}
	return false;
}

bool Crypt::Strings::getModeByString(const char* s, Crypt::Mode& m)
{
	if(!s)
		return false;
	for(size_t i=0; i< static_cast<int>(Mode::COUNT); i++) {
		size_t sl = strlen(s), x=0;
		if(sl != lstrlen(mode_str[i]))
			continue;
		for(x=0; x< sl; x++) {
			if(s[x] != (char)mode_str[i][x])
				break;
		}
		if(x == sl) {
			m = (Crypt::Mode)i;
			return true;
		}
	}
	return false;
}

bool Crypt::Strings::getKeyDerivationByString(const char*s, KeyDerivation& v )
{
	if(!s)
		return false;
	for(int i=0; i<static_cast<int>(KeyDerivation::COUNT); i++) {
		if(strcmp(s, key_algo_str_c[i])==0) {
			v = (Crypt::KeyDerivation)i;
			return true;
		}
	}
	return false;
}

bool Crypt::Strings::getEncodingByString(const char* s, Crypt::Encoding& e)
{
	if(!s)
		return false;
	for(int i=0; i<static_cast<int>(Encoding::COUNT); i++) {
		if(strcmp(s, encoding_str_c[i])==0) {
			e = (Crypt::Encoding)i;
			return true;
		}
	}
	return false;
}

bool Crypt::Strings::nextHash(bool only_openssl)
{
	hash_id++;
	if(only_openssl) {
		if(hash_id < static_cast<int>(Hash::sha3_256))
			return true;
	} else {
		if(hash_id < static_cast<int>(Hash::COUNT))
			return true;
	}
	hash_id=-1;
	return false;
};

const TCHAR* Crypt::Strings::getHash() {
	if(hash_id >= 0)
		return hash_str[hash_id];
	else
		return NULL;
};

std::string Crypt::Strings::getHash(Hash h)
{
	std::string ret;
	ret.resize(lstrlen(hash_str[static_cast<int>(h)]));
	for(size_t i=0; i<ret.size(); i++)
		ret[i] = static_cast<char>(hash_str[static_cast<int>(h)][i]);
	return ret;
}

bool Crypt::Strings::getHashByString(const char* s, Hash& h)
{
	if(!s)
		return false;
	for(size_t i=0; i< static_cast<int>(Hash::COUNT); i++) {
		size_t sl = strlen(s), x=0;
		if(sl != lstrlen(hash_str[i]))
			continue;
		for(x=0; x< sl; x++) {
			if(s[x] != (char)hash_str[i][x])
				break;
		}
		if(x == sl) {
			h= (Hash)i;
			return true;
		}
	}
	return false;
}