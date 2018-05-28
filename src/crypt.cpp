/*
This file is part of the nppcrypt
(http://www.github.com/jeanpaulrichter/nppcrypt)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
*/

#include <iostream>
#include <chrono>
#include <cmath>
#include "crypt.h"
#include "exception.h"

#include "bcrypt/crypt_blowfish.h"
#include "keccak/KeccakHash.h"

extern "C" {
#include "scrypt/crypto_scrypt.h"
}

#ifdef max
#undef max
#endif

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptopp/md5.h"
#include "cryptopp/md4.h"
#include "cryptopp/sha.h"
#include "cryptopp/sha3.h"
#include "cryptopp/hex.h"
#include "cryptopp/base32.h"
#include "cryptopp/base64.h"
#include "cryptopp/ripemd.h"
#include "cryptopp/whrlpool.h"
#include "cryptopp/tiger.h"
#include "cryptopp/keccak.h"
#include "cryptopp/blake2.h"
#include "cryptopp/hmac.h"
#include "cryptopp/aes.h"
#include "cryptopp/gcm.h"
#include "cryptopp/ccm.h"
#include "cryptopp/pwdbased.h"
#include "cryptopp/osrng.h"
#include "cryptopp/des.h"
#include "cryptopp/gost.h"
#include "cryptopp/blowfish.h"
#include "cryptopp/rc2.h"
#include "cryptopp/rc5.h"
#include "cryptopp/rc6.h"
#include "cryptopp/idea.h"
#include "cryptopp/cast.h"
#include "cryptopp/camellia.h"
#include "cryptopp/seed.h"
#include "cryptopp/tea.h"
#include "cryptopp/skipjack.h"
#include "cryptopp/shacal2.h"
#include "cryptopp/mars.h"
#include "cryptopp/twofish.h"
#include "cryptopp/serpent.h"
#include "cryptopp/sosemanuk.h"
#include "cryptopp/arc4.h"
#include "cryptopp/salsa.h"
#include "cryptopp/chacha.h"
#include "cryptopp/panama.h"
#include "cryptopp/eax.h"
#include "cryptopp/files.h"
#include "cryptopp/scrypt.h"

template<typename T>
T ipow(T base, T exp)
{
	T result = 1;
	while (exp) {
		if (exp & 1) {
			result *= base;
		}
		exp >>= 1;
		base *= base;
	}
	return result;
}

using namespace crypt;

// ----------------------------- PROPERTIES -------------------------------------------------------------------------------------------------------------------------------------------------------

static const unsigned int cipher_properties[unsigned(Cipher::COUNT)] = 
{	
	/* des			*/	CipherProperties::block | CipherProperties::c_weak,
	/* des_ede		*/	CipherProperties::block | CipherProperties::c_other,
	/* des_ede3		*/	CipherProperties::block | CipherProperties::c_other,
	/* desx			*/	CipherProperties::block | CipherProperties::c_weak,
	/* gost			*/	CipherProperties::block | CipherProperties::c_weak,
	/* cast128		*/	CipherProperties::block | CipherProperties::c_weak,
	/* cast256		*/	CipherProperties::block | CipherProperties::c_aes | CipherProperties::eax | CipherProperties::ccm | CipherProperties::gcm,
	/* rc2			*/	CipherProperties::block | CipherProperties::c_weak,
	/* rc4			*/	CipherProperties::stream | CipherProperties::c_weak | CipherProperties::eax | CipherProperties::ccm | CipherProperties::gcm,
	/* rc5			*/	CipherProperties::block | CipherProperties::c_other,
	/* rc6			*/	CipherProperties::block | CipherProperties::c_aes | CipherProperties::eax | CipherProperties::ccm | CipherProperties::gcm,
	/* idea			*/	CipherProperties::block | CipherProperties::c_other,
	/* blowfish		*/	CipherProperties::block | CipherProperties::c_other,
	/* camellia		*/	CipherProperties::block | CipherProperties::c_other | CipherProperties::eax | CipherProperties::ccm | CipherProperties::gcm,
	/* seed			*/	CipherProperties::block | CipherProperties::c_other | CipherProperties::eax | CipherProperties::ccm | CipherProperties::gcm,
	/* tea			*/	CipherProperties::block | CipherProperties::c_other,
	/* xtea			*/	CipherProperties::block | CipherProperties::c_other,
	/* shacal2		*/	CipherProperties::block | CipherProperties::c_other | CipherProperties::eax,
	/* mars			*/	CipherProperties::block | CipherProperties::c_aes | CipherProperties::eax | CipherProperties::ccm | CipherProperties::gcm,
	/* twofish		*/	CipherProperties::block | CipherProperties::c_aes | CipherProperties::eax | CipherProperties::ccm | CipherProperties::gcm,
	/* serpent		*/	CipherProperties::block | CipherProperties::c_aes | CipherProperties::eax | CipherProperties::ccm | CipherProperties::gcm,
	/* rijndael128	*/	CipherProperties::block | CipherProperties::c_aes | CipherProperties::eax | CipherProperties::ccm | CipherProperties::gcm,
	/* rijndael192	*/	CipherProperties::block | CipherProperties::c_aes | CipherProperties::eax | CipherProperties::ccm | CipherProperties::gcm,
	/* rijndael256	*/	CipherProperties::block | CipherProperties::c_aes | CipherProperties::eax | CipherProperties::ccm | CipherProperties::gcm,
	/* sosemanuk	*/	CipherProperties::stream | CipherProperties::c_stream,
	/* salsa20		*/	CipherProperties::stream | CipherProperties::c_stream,
	/* xsalsa20		*/	CipherProperties::stream | CipherProperties::c_stream,
	/* chacha20		*/	CipherProperties::stream | CipherProperties::c_stream,
	/* panama		*/	CipherProperties::stream | CipherProperties::c_stream,
};

static const unsigned int hash_properties[unsigned(crypt::Hash::COUNT)] =
{
	/* md4			*/	HashProperties::weak | HashProperties::hmac_possible,
	/* md5			*/	HashProperties::weak | HashProperties::hmac_possible,
	/* sha1			*/	HashProperties::weak | HashProperties::hmac_possible,
	/* sha256		*/	HashProperties::hmac_possible,
	/* sha512		*/	HashProperties::hmac_possible,
	/* ripemd128	*/	HashProperties::hmac_possible,
	/* ripemd160	*/	HashProperties::hmac_possible,
	/* ripemd256	*/	HashProperties::hmac_possible,
	/* whirlpool	*/	HashProperties::hmac_possible,
	/* tiger		*/	HashProperties::hmac_possible,
	/* sha3_224		*/	HashProperties::hmac_possible,
	/* sha3_256		*/	HashProperties::hmac_possible,
	/* sha3_384		*/	HashProperties::hmac_possible,
	/* sha3_512		*/	HashProperties::hmac_possible,
	/* keccac256	*/  HashProperties::hmac_possible,
	/* keccac512	*/  HashProperties::hmac_possible,
	/* blake2s		*/	0,
	/* blake2b		*/	HashProperties::key
};

// ----------------------------- STRINGS ---------------------------------------------------------------------------------------------------------------------------------------------------------
namespace Strings {
	static const char*	cipher[] = { "des", "des_ede", "des_ede3", "desx", "gost", "cast128", "cast256", "rc2", "rc4", "rc5", "rc6", "idea", "blowfish", "camellia", "seed", "tea", "xtea", "shacal-2", "mars", "twofish", "serpent", "rijndael128", "rijndael192", "rijndael256", "sosemanuk", "salsa20", "xsalsa20", "chacha20", "panama" };
	static const char*	cipher_help_url[] = { "Data_Encryption_Standard", "Data_Encryption_Standard", "Data_Encryption_Standard", "DES-X", "GOST_(block_cipher)", "CAST-128", "CAST-256", "RC2", "RC4", "RC5", "RC6", "International_Data_Encryption_Algorithm", "Blowfish_(cipher)", "Camellia_(cipher)", "SEED", "Tiny_Encryption_Algorithm", "XTEA", "SHACAL", "MARS_(cryptography)", "Twofish", "Serpent_(cipher)", "Advanced_Encryption_Standard", "Advanced_Encryption_Standard", "Advanced_Encryption_Standard", "SOSEMANUK", "Salsa20", "Salsa20", "Salsa20#ChaCha_variant", "Panama_(cryptography)" };

	static const char*	mode[] = { "ecb", "cbc", "cfb", "ofb", "ctr", "eax", "ccm", "gcm" };
	static const char*	mode_help_url[] = { "Block_cipher_mode_of_operation", "Block_cipher_mode_of_operation", "Block_cipher_mode_of_operation", "Block_cipher_mode_of_operation", "Block_cipher_mode_of_operation", "EAX_mode", "CCM_mode", "Galois/Counter_Mode" };

	static const char*	iv[] = { "random", "keyderivation", "zero" };

	static const char*	hash[] = { "md4", "md5", "sha1", "sha256", "sha512", "ripemd128", "ripemd160", "ripemd256", "whirlpool", "tiger128", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "keccac256", "keccac512", "blake2s", "blake2b" };
	static const char*	hash_help_url[] = { "MD4","MD5", "SHA-1", "SHA-2", "SHA-2", "RIPEMD", "RIPEMD", "RIPEMD", "Whirlpool_(cryptography)", "Tiger_(cryptography)", "SHA-3", "SHA-3", "SHA-3", "SHA-3", "SHA-3#Capacity_change_proposal", "SHA-3#Capacity_change_proposal", "BLAKE_(hash_function)#BLAKE2", "BLAKE_(hash_function)#BLAKE2" };

	static const char*	encoding[] = { "ascii", "base16", "base32", "base64" };
	static const char*	encoding_help_url[] = { "ASCII", "Hexadecimal", "Base32", "Base64" };

	static const char*	key_algo[] = { "pbkdf2", "bcrypt", "scrypt" };
	static const char*	key_algo_help_url[] = { "PBKDF2", "Bcrypt", "Scrypt" };

	static const char*	random_mode[] = { "charnum", "specials", "ascii", "base16" , "base64" };

	static const char*	eol[] = { "windows", "unix" };

	static char			help_url_wikipedia[100] = "https://en.wikipedia.org/wiki/";
	static const int	help_url_wikipedia_len = 30;

	static const std::string	eol_windows = "\r\n";
	static const std::string	eol_unix = "\n";
};

// ===========================================================================================================================================================================================

crypt::UserData::UserData()
{
}

crypt::UserData::UserData(const char* s, Encoding enc)
{
	set(s, strlen(s), enc);
}
const byte* crypt::UserData::BytePtr() const
{
	return data.BytePtr();
}

size_t crypt::UserData::size() const
{
	return data.size();
}

size_t crypt::UserData::set(std::string& s, Encoding enc)
{
	if(enc == Encoding::ascii) {
		data.Assign((const byte*)s.c_str(), s.size());
	} else {
		std::unique_ptr<CryptoPP::BaseN_Decoder> decoder;
		if (enc == Encoding::base16) {
			decoder.reset(new CryptoPP::HexDecoder);
		} else if (enc == Encoding::base16) {
			decoder.reset(new CryptoPP::Base32Decoder);
		} else {
			decoder.reset(new CryptoPP::Base64Decoder);
		}
		decoder->Put((const byte*)s.data(), s.size());
		decoder->MessageEnd();
		CryptoPP::word64 size = decoder->MaxRetrievable();
		if (size && size <= SIZE_MAX) {
			data.resize(size);
			decoder->Get(&data[0], data.size());
		}
	}
	return data.size();
}

size_t crypt::UserData::set(const char* s, size_t length, Encoding enc)
{
	if (enc == Encoding::ascii) {
		data.Assign((const byte*)s, length);
	} else {
		std::unique_ptr<CryptoPP::BaseN_Decoder> decoder;
		if (enc == Encoding::base16) {
			decoder.reset(new CryptoPP::HexDecoder);
		} else if (enc == Encoding::base16) {
			decoder.reset(new CryptoPP::Base32Decoder);
		} else {
			decoder.reset(new CryptoPP::Base64Decoder);
		}
		decoder->Put((const byte*)s, length);
		decoder->MessageEnd();
		CryptoPP::word64 size = decoder->MaxRetrievable();
		if (size && size <= SIZE_MAX) {
			data.resize(size);
			decoder->Get(&data[0], data.size());
		}
	}
	return data.size();
}

size_t crypt::UserData::set(const byte* s, size_t length)
{
	if (s && length) {
		data.Assign(s, length);
	}
	return data.size();
}

void crypt::UserData::get(std::string& s, Encoding enc) const
{
	if (data.size()) {
		if (enc == Encoding::ascii) {
			s.assign((const char*)data.BytePtr(), data.size());
		} else {
			std::unique_ptr<CryptoPP::SimpleProxyFilter> encoder;
			if (enc == Encoding::base16) {
				encoder.reset(new CryptoPP::HexEncoder);
			} else if (enc == Encoding::base16) {
				encoder.reset(new CryptoPP::Base32Encoder);
			} else {
				encoder.reset(new CryptoPP::Base64Encoder(0,false));
			}
			encoder->Put(data.BytePtr(), data.size());
			encoder->MessageEnd();
			CryptoPP::word64 size = encoder->MaxRetrievable();
			if (size && size <= SIZE_MAX) {
				s.resize(size);
				encoder->Get((byte*)&s[0], s.size());
			} else {
				s.clear();
			}
		}
	} else {
		s.clear();
	}
}

void crypt::UserData::get(secure_string& s, Encoding enc) const
{
	if (data.size()) {
		if (enc == Encoding::ascii) {
			s.assign((const char*)data.BytePtr(), data.size());
		} else {
			std::unique_ptr<CryptoPP::SimpleProxyFilter> encoder;
			if (enc == Encoding::base16) {
				encoder.reset(new CryptoPP::HexEncoder);
			} else if (enc == Encoding::base16) {
				encoder.reset(new CryptoPP::Base32Encoder);
			} else {
				encoder.reset(new CryptoPP::Base64Encoder(0, false));
			}
			encoder->Put(data.BytePtr(), data.size());
			encoder->MessageEnd();
			CryptoPP::word64 size = encoder->MaxRetrievable();
			if (size && size <= SIZE_MAX) {
				s.resize(size);
				encoder->Get((byte*)&s[0], s.size());
			} else {
				s.clear();
			}
		}
	} else {
		s.clear();
	}
}

void crypt::UserData::clear()
{
	data.New(0);
}

// ===========================================================================================================================================================================================

bool crypt::getCipherInfo(crypt::Cipher cipher, crypt::Mode mode, int& key_length, int& iv_length, int& block_size)
{
	using namespace CryptoPP;
	switch (cipher)
	{
	case crypt::Cipher::des:
		key_length = DES::DEFAULT_KEYLENGTH; iv_length = DES::BLOCKSIZE; block_size = DES::BLOCKSIZE; break;
	case crypt::Cipher::des_ede:
		key_length = DES_EDE2::DEFAULT_KEYLENGTH; iv_length = DES_EDE2::BLOCKSIZE; block_size = DES_EDE2::BLOCKSIZE; break;
	case crypt::Cipher::des_ede3:
		key_length = DES_EDE3::DEFAULT_KEYLENGTH; iv_length = DES_EDE3::BLOCKSIZE; block_size = DES_EDE3::BLOCKSIZE; break;
	case crypt::Cipher::desx:
		key_length = DES_XEX3::DEFAULT_KEYLENGTH; iv_length = DES_XEX3::BLOCKSIZE; block_size = DES_XEX3::BLOCKSIZE; break;
	case crypt::Cipher::gost:
		key_length = GOST::DEFAULT_KEYLENGTH; iv_length = GOST::BLOCKSIZE; block_size = GOST::BLOCKSIZE; break;
	case crypt::Cipher::cast128:
		key_length = CAST128::DEFAULT_KEYLENGTH; iv_length = CAST128::BLOCKSIZE; block_size = CAST128::BLOCKSIZE; break;
	case crypt::Cipher::cast256:
		key_length = CAST256::DEFAULT_KEYLENGTH; iv_length = (mode == crypt::Mode::ccm) ? 13 : CAST256::BLOCKSIZE; block_size = CAST256::BLOCKSIZE; break;
	case crypt::Cipher::rc2:
		key_length = RC2::DEFAULT_KEYLENGTH; iv_length = RC2::BLOCKSIZE; block_size = RC2::BLOCKSIZE; break;
	case crypt::Cipher::rc4:
		key_length = Weak::ARC4::DEFAULT_KEYLENGTH; iv_length = Weak::ARC4::IV_LENGTH; block_size = 0; break;
	case crypt::Cipher::rc5:
		key_length = RC5::DEFAULT_KEYLENGTH; iv_length = RC5::BLOCKSIZE; block_size = RC5::BLOCKSIZE; break;
	case crypt::Cipher::rc6:
		key_length = RC6::DEFAULT_KEYLENGTH; iv_length = (mode == crypt::Mode::ccm) ? 13 : RC6::BLOCKSIZE; block_size = RC6::BLOCKSIZE; break;
	case crypt::Cipher::idea:
		key_length = IDEA::DEFAULT_KEYLENGTH; iv_length = IDEA::BLOCKSIZE; block_size = IDEA::BLOCKSIZE; break;
	case crypt::Cipher::blowfish:
		key_length = Blowfish::DEFAULT_KEYLENGTH; iv_length = Blowfish::BLOCKSIZE; block_size = Blowfish::BLOCKSIZE; break;
	case crypt::Cipher::camellia:
		key_length = Camellia::DEFAULT_KEYLENGTH; iv_length = (mode == crypt::Mode::ccm) ? 13 : Camellia::BLOCKSIZE; block_size = Camellia::BLOCKSIZE; break;
	case crypt::Cipher::seed:
		key_length = SEED::DEFAULT_KEYLENGTH; iv_length = (mode == crypt::Mode::ccm) ? 13 : SEED::BLOCKSIZE; block_size = SEED::BLOCKSIZE; break;
	case crypt::Cipher::tea:
		key_length = TEA::DEFAULT_KEYLENGTH; iv_length = TEA::BLOCKSIZE; block_size = TEA::BLOCKSIZE; break;
	case crypt::Cipher::xtea:
		key_length = XTEA::DEFAULT_KEYLENGTH; iv_length = XTEA::BLOCKSIZE; block_size = XTEA::BLOCKSIZE; break;
	case crypt::Cipher::shacal2:
		key_length = SHACAL2::DEFAULT_KEYLENGTH; iv_length = (mode == crypt::Mode::ccm) ? 13 : SHACAL2::BLOCKSIZE; block_size = SHACAL2::BLOCKSIZE; break;
	case crypt::Cipher::mars:
		key_length = MARS::DEFAULT_KEYLENGTH; iv_length = (mode == crypt::Mode::ccm) ? 13 : MARS::BLOCKSIZE; block_size = MARS::BLOCKSIZE; break;
	case crypt::Cipher::twofish:
		key_length = Twofish::DEFAULT_KEYLENGTH; iv_length = (mode == crypt::Mode::ccm) ? 13 : Twofish::BLOCKSIZE; block_size = Twofish::BLOCKSIZE; break;
	case crypt::Cipher::serpent:
		key_length = Serpent::DEFAULT_KEYLENGTH; iv_length = (mode == crypt::Mode::ccm) ? 13 : Serpent::BLOCKSIZE; block_size = Serpent::BLOCKSIZE; break;
	case crypt::Cipher::rijndael128:
		key_length = 16; block_size = AES::BLOCKSIZE;
		iv_length = (mode == crypt::Mode::ccm) ? 13 : AES::BLOCKSIZE;		
		break;
	case crypt::Cipher::rijndael192:
		key_length = 24; block_size = AES::BLOCKSIZE;
		iv_length = (mode == crypt::Mode::ccm) ? 13 : AES::BLOCKSIZE;
		break;
	case crypt::Cipher::rijndael256:
		key_length = 32; block_size = AES::BLOCKSIZE;
		iv_length = (mode == crypt::Mode::ccm) ? 13 : AES::BLOCKSIZE;
		break;
	case crypt::Cipher::sosemanuk:
		block_size = 0;
		key_length = Sosemanuk::DEFAULT_KEYLENGTH;
		iv_length = Sosemanuk::IV_LENGTH;
		break;
	case crypt::Cipher::salsa20:
		block_size = 0;
		key_length = Salsa20::DEFAULT_KEYLENGTH;
		iv_length = Salsa20::IV_LENGTH;
		break;
	case crypt::Cipher::xsalsa20:
		block_size = 0;
		key_length = XSalsa20::DEFAULT_KEYLENGTH;
		iv_length = XSalsa20::IV_LENGTH;
		break;
	case crypt::Cipher::chacha20:
		block_size = 0;
		key_length = ChaCha20::DEFAULT_KEYLENGTH;
		iv_length = ChaCha20::IV_LENGTH;
		break;
	case crypt::Cipher::panama:
		block_size = 0;
		key_length = PanamaCipher<LittleEndian>::DEFAULT_KEYLENGTH;
		iv_length = PanamaCipher<LittleEndian>::IV_LENGTH;
		break;
	default: return false;
	}
	return true;
}

bool crypt::getHashInfo(Hash h, int& length)
{
	using namespace CryptoPP;
	switch (h)
	{
	case crypt::Hash::md4: length = Weak::MD4::DIGESTSIZE; break;
	case crypt::Hash::md5: length = Weak::MD5::DIGESTSIZE; break;
	case crypt::Hash::sha1: length = SHA1::DIGESTSIZE; break;
	case crypt::Hash::sha256: length = SHA256::DIGESTSIZE; break;
	case crypt::Hash::sha512: length = SHA512::DIGESTSIZE; break;
	case crypt::Hash::ripemd128: length = RIPEMD128::DIGESTSIZE; break;
	case crypt::Hash::ripemd160: length = RIPEMD160::DIGESTSIZE; break;
	case crypt::Hash::ripemd256: length = RIPEMD256::DIGESTSIZE; break;
	case crypt::Hash::whirlpool: length = Whirlpool::DIGESTSIZE; break;
	case crypt::Hash::tiger128: length = Tiger::DIGESTSIZE; break;
	case crypt::Hash::sha3_224: length = SHA3_224::DIGESTSIZE; break;
	case crypt::Hash::sha3_256: length = SHA3_256::DIGESTSIZE; break;
	case crypt::Hash::sha3_384: length = SHA3_384::DIGESTSIZE; break;
	case crypt::Hash::sha3_512: length = SHA3_512::DIGESTSIZE; break;
	case crypt::Hash::keccak256: length = Keccak_256::DIGESTSIZE; break;
	case crypt::Hash::keccak512: length = Keccak_512::DIGESTSIZE; break;
	case crypt::Hash::blake2s: length = BLAKE2s::DIGESTSIZE; break;
	case crypt::Hash::blake2b: length = BLAKE2b::DIGESTSIZE; break;
	default: return false;
	}
	return true;
}

void crypt::encrypt(const byte* in, size_t in_len, std::basic_string<byte>& buffer, const Options::Crypt& options, InitData& init)
{
	using namespace CryptoPP;

	if (!in || !in_len) {
		throw CExc(CExc::Code::input_null);
	}
	
	SecByteBlock		tKey;
	SecByteBlock		tVec;
	SecByteBlock		tSalt;
	const byte*			ptVec = NULL;
	const byte*			ptSalt = NULL;
	int					key_len, iv_len;
	int					block_size;

	getCipherInfo(options.cipher, options.mode, key_len, iv_len, block_size);

	// --------------------------- prepare salt vector:
	if (options.key.salt_bytes > 0)	{
		if (options.key.algorithm == KeyDerivation::bcrypt && options.key.salt_bytes != 16) {
			throw CExc(CExc::Code::invalid_bcrypt_saltlength);
		}
		tSalt.resize(options.key.salt_bytes);
		OS_GenerateRandomBlock(true, &tSalt[0], options.key.salt_bytes);
		ptSalt = &tSalt[0];
	}
	// --------------------------- prepare iv & key vector
	if (options.iv == crypt::IV::keyderivation)	{
		tKey.resize(key_len + iv_len);
		if (iv_len > 0) {
			ptVec = &tKey[key_len];
		}
	} else if (options.iv == crypt::IV::random)	{
		tKey.resize(key_len);
		if (iv_len > 0)	{
			tVec.resize(iv_len);
			OS_GenerateRandomBlock(false, &tVec[0], iv_len);
			ptVec = &tVec[0];
		}
	} else if (options.iv == crypt::IV::zero) {
		tKey.resize(key_len);
		if (iv_len)	{
			tVec.Assign(iv_len, 0);
			ptVec = &tVec[0];
		}
	}
	// --------------------------- key derivation:
	switch (options.key.algorithm)
	{
	case KeyDerivation::pbkdf2:
	{
		std::unique_ptr<PasswordBasedKeyDerivationFunction> pbkdf2;
		switch (Hash(options.key.options[0]))
		{
		case Hash::md4:
			pbkdf2.reset( new PKCS5_PBKDF2_HMAC< Weak::MD4 > ); break;
		case Hash::md5:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< Weak::MD5 >); break;
		case Hash::sha1:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA1 >); break;
		case Hash::sha256:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA256 >); break;
		case Hash::sha512:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA512 >); break;
		case Hash::ripemd128:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< RIPEMD128 >); break;
		case Hash::ripemd160:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< RIPEMD160 >); break;
		case Hash::ripemd256:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< RIPEMD256 >); break;
		case Hash::whirlpool:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< Whirlpool >); break;
		case Hash::tiger128:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< Tiger >); break;
		case Hash::sha3_224:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA3_224 >); break;
		case Hash::sha3_256:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA3_256 >); break;
		case Hash::sha3_384:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA3_384 >); break;
		case Hash::sha3_512:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA3_512 >); break;
		case Hash::keccak256:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< Keccak_256 >); break;
		case Hash::keccak512:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< Keccak_512 >); break;
		default: throw CExc(CExc::Code::invalid_pbkdf2_hash);
		}
		pbkdf2->DeriveKey(&tKey[0], tKey.size(), 
						options.password.BytePtr(), options.password.size(), 
						MakeParameters(Name::Salt(), ConstByteArrayParameter(ptSalt, options.key.salt_bytes))
						("Iterations", options.key.options[1]));
		break;
	}
	case KeyDerivation::bcrypt:
	{
		char output[64];
		char settings[32];

		if (_crypt_gensalt_blowfish_rn("$2a$", (unsigned long)options.key.options[0], (const char*)ptSalt, 16, settings, 32) == NULL) {
			throw CExc(CExc::Code::bcrypt_failed);
		}
		memset(output, 0, sizeof(output));
		if (_crypt_blowfish_rn((const char*)options.password.BytePtr(), settings, output, 64) == NULL) {
			throw CExc(CExc::Code::bcrypt_failed);
		}
		byte hashdata[23];
		ArraySource ss((const byte*)output + 29, 31, true, new Base64Decoder(new ArraySink(hashdata, 23)));
		shake128(hashdata, 23, &tKey[0], tKey.size());
		break;
	}
	case KeyDerivation::scrypt:
	{
		if (crypto_scrypt(options.password.BytePtr(), options.password.size(), ptSalt, options.key.salt_bytes, ipow(2, options.key.options[0]), options.key.options[1], options.key.options[2], &tKey[0], tKey.size()) != 0) {
			throw CExc(CExc::Code::scrypt_failed);
		}
		break;
	}
	}
	// --------------------------- return encoded IV and Salt
	if (options.iv == crypt::IV::random && tVec.size() > 0) {
		init.iv.set(tVec.BytePtr(), tVec.size());
	}
	if (options.key.salt_bytes > 0) {
		init.salt.set(tSalt.BytePtr(), tSalt.size());
	}

	try	{
		if ((cipher_properties[int(options.cipher)] & CipherProperties::stream) == CipherProperties::stream)	{
			std::unique_ptr<SymmetricCipherDocumentation::Encryption> pEnc;
			switch (options.cipher) {
			case Cipher::sosemanuk: pEnc.reset(new Sosemanuk::Encryption(tKey.data(), key_len, ptVec)); break;
			case Cipher::rc4: pEnc.reset(new Weak::ARC4::Encryption(tKey.data(), key_len)); break;
			case Cipher::salsa20: pEnc.reset(new Salsa20::Encryption(tKey.data(), key_len, ptVec)); break;
			case Cipher::xsalsa20: pEnc.reset(new XSalsa20::Encryption(tKey.data(), key_len, ptVec)); break;
			case Cipher::chacha20: pEnc.reset(new ChaCha20::Encryption(tKey.data(), key_len, ptVec)); break;
			case Cipher::panama: pEnc.reset(new PanamaCipher<LittleEndian>::Encryption(tKey.data(), key_len, ptVec)); break;
			}

			switch (options.encoding.enc)
			{
			case Encoding::ascii:
			{
				buffer.resize(in_len);
				pEnc->ProcessData(&buffer[0], in, in_len);
				break;
			}
			case Encoding::base16: case Encoding::base32:
			{
				int linelength = options.encoding.linebreaks ? (int)options.encoding.linelength : 0;
				const std::string& seperator = (options.encoding.eol == crypt::EOL::windows) ? Strings::eol_windows : Strings::eol_unix;
				std::vector<byte> temp(in_len);
				pEnc->ProcessData(temp.data(), in, in_len);
				if (options.encoding.enc == Encoding::base16) {
					ArraySource(temp.data(), temp.size(), true,
						new HexEncoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.encoding.uppercase, linelength, seperator)
						);
				} else {
					ArraySource(temp.data(), temp.size(), true,
						new Base32Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.encoding.uppercase, linelength, seperator)
						);
				}
				break;
			}
			case Encoding::base64:
			{
				std::vector<byte> temp(in_len);
				pEnc->ProcessData(temp.data(), in, in_len);
				ArraySource(temp.data(), temp.size(), true,
					new Base64Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.encoding.linebreaks, (int)options.encoding.linelength, CryptoPP::EOL(options.encoding.eol))
				);
				if (options.encoding.linebreaks) {
					buffer.pop_back();
					if (options.encoding.eol == crypt::EOL::windows) {
						buffer.pop_back();
					}
				}
				break;
			}
			}			
		} else {
			if (options.mode == Mode::gcm || options.mode == Mode::ccm || options.mode == Mode::eax) {
				std::unique_ptr<AuthenticatedSymmetricCipherDocumentation::Encryption> penc;
				int tag_size;
				switch (options.cipher)
				{
				case Cipher::cast256:
				{
					switch (options.mode)
					{
					case Mode::gcm: penc.reset(new GCM< CAST256 >::Encryption); tag_size = Constants::gcm_tag_size; break;
					case Mode::ccm: penc.reset(new CCM< CAST256 >::Encryption); tag_size = Constants::ccm_tag_size;  break;
					case Mode::eax: penc.reset(new EAX< CAST256 >::Encryption); tag_size = Constants::eax_tag_size;  break;
					}
					break;
				}
				case Cipher::rc6:
				{
					switch (options.mode)
					{
					case Mode::gcm: penc.reset(new GCM< RC6 >::Encryption); tag_size = Constants::gcm_tag_size; break;
					case Mode::ccm: penc.reset(new CCM< RC6 >::Encryption); tag_size = Constants::ccm_tag_size;  break;
					case Mode::eax: penc.reset(new EAX< RC6 >::Encryption); tag_size = Constants::eax_tag_size;  break;
					}
					break;
				}
				case Cipher::camellia:
				{
					switch (options.mode)
					{
					case Mode::gcm: penc.reset(new GCM< Camellia >::Encryption); tag_size = Constants::gcm_tag_size; break;
					case Mode::ccm: penc.reset(new CCM< Camellia >::Encryption); tag_size = Constants::ccm_tag_size;  break;
					case Mode::eax: penc.reset(new EAX< Camellia >::Encryption); tag_size = Constants::eax_tag_size;  break;
					}
					break;
				}
				case Cipher::seed:
				{
					switch (options.mode)
					{
					case Mode::gcm: penc.reset(new GCM< SEED >::Encryption); tag_size = Constants::gcm_tag_size; break;
					case Mode::ccm: penc.reset(new CCM< SEED >::Encryption); tag_size = Constants::ccm_tag_size;  break;
					case Mode::eax: penc.reset(new EAX< SEED >::Encryption); tag_size = Constants::eax_tag_size;  break;
					}
					break;
				}
				case Cipher::shacal2:
				{
					switch (options.mode)
					{
					case Mode::eax: penc.reset(new EAX< SHACAL2 >::Encryption); tag_size = Constants::eax_tag_size;  break;
					default: throw CExc(CExc::Code::invalid_mode);
					}
					break;
				}
				case Cipher::mars:
				{
					switch (options.mode)
					{
					case Mode::gcm: penc.reset(new GCM< MARS >::Encryption); tag_size = Constants::gcm_tag_size; break;
					case Mode::ccm: penc.reset(new CCM< MARS >::Encryption); tag_size = Constants::ccm_tag_size;  break;
					case Mode::eax: penc.reset(new EAX< MARS >::Encryption); tag_size = Constants::eax_tag_size;  break;
					}
					break;
				}
				case Cipher::twofish:
				{
					switch (options.mode)
					{
					case Mode::gcm: penc.reset(new GCM< Twofish >::Encryption); tag_size = Constants::gcm_tag_size; break;
					case Mode::ccm: penc.reset(new CCM< Twofish >::Encryption); tag_size = Constants::ccm_tag_size;  break;
					case Mode::eax: penc.reset(new EAX< Twofish >::Encryption); tag_size = Constants::eax_tag_size;  break;
					}
					break;
				}
				case Cipher::serpent:
				{
					switch (options.mode)
					{
					case Mode::gcm: penc.reset(new GCM< Serpent >::Encryption); tag_size = Constants::gcm_tag_size; break;
					case Mode::ccm: penc.reset(new CCM< Serpent >::Encryption); tag_size = Constants::ccm_tag_size;  break;
					case Mode::eax: penc.reset(new EAX< Serpent >::Encryption); tag_size = Constants::eax_tag_size;  break;
					}
					break;
				}
				case Cipher::rijndael128: case Cipher::rijndael256: case Cipher::rijndael192:
				{
					switch (options.mode)
					{
					case Mode::gcm: penc.reset(new GCM< AES >::Encryption); tag_size = Constants::gcm_tag_size; break;
					case Mode::ccm: penc.reset(new CCM< AES >::Encryption); tag_size = Constants::ccm_tag_size;  break;
					case Mode::eax: penc.reset(new EAX< AES >::Encryption); tag_size = Constants::eax_tag_size;  break;
					}
					break;
				} 
				}
				std::basic_string<byte> temp;
				penc->SetKeyWithIV(tKey.data(), key_len, ptVec, iv_len);
				if (options.mode == Mode::ccm) {
					penc->SpecifyDataLengths(init.salt.size() + init.iv.size(), in_len, 0);
				}

				AuthenticatedEncryptionFilter ef(*penc, NULL, false, tag_size);
				if (options.encoding.enc == Encoding::ascii) {
					ef.Attach(new StringSinkTemplate<std::basic_string<byte>>(buffer));
				} else {
					ef.Attach(new StringSinkTemplate<std::basic_string<byte>>(temp));
				}

				// in order to not break backwards-comp.: add salt + iv as base64:
				secure_string temp2;
				init.salt.get(temp2, Encoding::base64);
				ef.ChannelPut( AAD_CHANNEL, (const byte*)temp2.c_str(), temp2.size());
				init.iv.get(temp2, Encoding::base64);
				ef.ChannelPut( AAD_CHANNEL, (const byte*)temp2.c_str(), temp2.size());
				ef.ChannelMessageEnd( AAD_CHANNEL );
				ef.ChannelPut(DEFAULT_CHANNEL, in, in_len);
				ef.ChannelMessageEnd( DEFAULT_CHANNEL );

				switch (options.encoding.enc)
				{
				case Encoding::ascii:
				{
					init.tag.set(buffer.data() + buffer.size() - tag_size, tag_size);
					buffer.resize(buffer.size() - tag_size);
					break;
				}
				case Encoding::base16: case Encoding::base32:
				{
					int linelength = options.encoding.linebreaks ? (int)options.encoding.linelength : 0;
					const std::string& seperator = (options.encoding.eol == crypt::EOL::windows) ? Strings::eol_windows : Strings::eol_unix;
					if (options.encoding.enc == Encoding::base16) {
						StringSource(temp.data(), temp.size() - tag_size, true, new HexEncoder(new StringSinkTemplate<std::basic_string<byte>>(buffer),
							options.encoding.uppercase, linelength, seperator));
					} else {
						StringSource(temp.data(), temp.size() - tag_size, true, new Base32Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer),
							options.encoding.uppercase, linelength, seperator));
					}
					init.tag.set(temp.data() + temp.size() - tag_size, tag_size);
					break;
				}
				case Encoding::base64:
				{
					StringSource(temp.data(), temp.size() - tag_size, true, new Base64Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer),
						options.encoding.linebreaks, (int)options.encoding.linelength, CryptoPP::EOL(options.encoding.eol)));
					if (options.encoding.linebreaks) {
						buffer.pop_back();
						if (options.encoding.eol == crypt::EOL::windows) {
							buffer.pop_back();
						}
					}
					init.tag.set(temp.data() + temp.size() - tag_size, tag_size);
					break;
				}
				}
			} else {
				std::unique_ptr<CipherModeBase> pEnc;
				switch (options.cipher)
				{
				case Cipher::des:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<DES>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<DES>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<DES>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<DES>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<DES>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::des_ede:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<DES_EDE2>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<DES_EDE2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<DES_EDE2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<DES_EDE2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<DES_EDE2>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::des_ede3:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<DES_EDE3>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<DES_EDE3>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<DES_EDE3>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<DES_EDE3>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<DES_EDE3>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::desx:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<DES_XEX3>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<DES_XEX3>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<DES_XEX3>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<DES_XEX3>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<DES_XEX3>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::gost:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<GOST>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<GOST>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<GOST>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<GOST>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<GOST>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::cast128:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<CAST128>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<CAST128>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<CAST128>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<CAST128>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<CAST128>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::cast256:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<CAST256>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<CAST256>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<CAST256>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<CAST256>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<CAST256>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::rc2:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<RC2>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<RC2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<RC2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<RC2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<RC2>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::rc5:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<RC5>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<RC5>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<RC5>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<RC5>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<RC5>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::rc6:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<RC6>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<RC6>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<RC6>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<RC6>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<RC6>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::idea:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<IDEA>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<IDEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<IDEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<IDEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<IDEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::blowfish:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<Blowfish>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<Blowfish>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<Blowfish>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<Blowfish>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<Blowfish>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::camellia:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<Camellia>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<Camellia>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<Camellia>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<Camellia>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<Camellia>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::seed:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<SEED>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<SEED>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<SEED>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<SEED>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<SEED>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::tea:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<TEA>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<TEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<TEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<TEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<TEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::xtea:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<XTEA>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<XTEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<XTEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<XTEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<XTEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::shacal2:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<SHACAL2>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<SHACAL2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<SHACAL2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<SHACAL2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<SHACAL2>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::mars:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<MARS>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<MARS>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<MARS>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<MARS>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<MARS>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::twofish:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<Twofish>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<Twofish>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<Twofish>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<Twofish>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<Twofish>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::serpent:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<Serpent>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<Serpent>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<Serpent>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<Serpent>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<Serpent>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::rijndael128: case Cipher::rijndael256: case Cipher::rijndael192:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<AES>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<AES>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<AES>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<AES>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<AES>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				default: throw CExc(CExc::Code::invalid_cipher);
				}
				switch (options.encoding.enc)
				{
				case Encoding::ascii:
				{
					StringSource(in, in_len, true, new StreamTransformationFilter(*pEnc, new StringSinkTemplate<std::basic_string<byte>>(buffer)));
					break;
				}
				case Encoding::base16: case Encoding::base32:
				{
					int linelength = options.encoding.linebreaks ? (int)options.encoding.linelength : 0;
					const std::string& seperator = (options.encoding.eol == crypt::EOL::windows) ? Strings::eol_windows : Strings::eol_unix;
					if (options.encoding.enc == Encoding::base16) {
						StringSource(in, in_len, true, new StreamTransformationFilter(*pEnc,
							new HexEncoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.encoding.uppercase, linelength, seperator)));
					} else {
						StringSource(in, in_len, true, new StreamTransformationFilter(*pEnc,
								new Base32Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.encoding.uppercase, linelength, seperator)));
					}
					break;
				}
				case crypt::Encoding::base64:
				{
					StringSource(in, in_len, true, new StreamTransformationFilter(*pEnc,
							new Base64Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.encoding.linebreaks, (int)options.encoding.linelength, CryptoPP::EOL(options.encoding.eol))
							));
					if (options.encoding.linebreaks) {
						buffer.pop_back();
						if (options.encoding.eol == crypt::EOL::windows) {
							buffer.pop_back();
						}
					}
					break;
				}
				}
			}
		}
	} catch (CryptoPP::Exception& exc) {
		switch (exc.GetErrorType()) {
		case CryptoPP::Exception::NOT_IMPLEMENTED: throw CExc(CExc::Code::cryptopp_not_implemented); break;
		case CryptoPP::Exception::INVALID_ARGUMENT: throw CExc(CExc::Code::cryptopp_invalid_argument); break;
		case CryptoPP::Exception::CANNOT_FLUSH: throw CExc(CExc::Code::cryptopp_cannot_flush); break;
		case CryptoPP::Exception::DATA_INTEGRITY_CHECK_FAILED: throw CExc(CExc::Code::cryptopp_bad_integrity); break;
		case CryptoPP::Exception::INVALID_DATA_FORMAT: throw CExc(CExc::Code::cryptopp_invalid_data); break;
		case CryptoPP::Exception::IO_ERROR: throw CExc(CExc::Code::cryptopp_io_error); break;
		default: throw CExc(CExc::Code::cryptopp_other); break;
		}
	} catch(CExc& exc) {
		throw exc;
	} catch (...) {
		throw CExc(CExc::Code::unexpected);
	}
}

void crypt::decrypt(const byte* in, size_t in_len, std::basic_string<byte>& buffer, const Options::Crypt& options, const InitData& init)
{
	if (!in || !in_len) {
		throw CExc(CExc::Code::input_null);
	}

	using namespace crypt;
	using namespace	CryptoPP;

	SecByteBlock		tVec;
	SecByteBlock		tKey;
	const byte*			ptVec = NULL;
	const byte*			ptSalt = NULL;
	int					iv_len, key_len;
	int					block_size;

	getCipherInfo(options.cipher, options.mode, key_len, iv_len, block_size);

	// --------------------------- prepare salt vector:
	if (options.key.salt_bytes > 0)	{
		if (options.key.algorithm == crypt::KeyDerivation::bcrypt && options.key.salt_bytes != 16) {
			throw CExc(CExc::Code::invalid_bcrypt_saltlength);
		}
		if (!init.salt.size()) {
			throw CExc(CExc::Code::salt_missing);
		}
		if (init.salt.size() != (size_t)options.key.salt_bytes) {
			throw CExc(CExc::Code::invalid_salt);
		}
		ptSalt = init.salt.BytePtr();
	}
	// --------------------------- prepare iv vector:
	if (options.iv == crypt::IV::keyderivation)	{
		tKey.resize(key_len + iv_len);
		if (iv_len > 0) {
			ptVec = &tKey[key_len];
		}
	} else if (options.iv == crypt::IV::random) {
		tKey.resize(key_len);
		if (iv_len > 0)	{
			if (!init.iv.size()) {
				throw CExc(CExc::Code::iv_missing);
			}			
			if (init.iv.size() != iv_len) {
				throw CExc(CExc::Code::invalid_iv);
			}
			ptVec = init.iv.BytePtr();
		}
	} else if (options.iv == crypt::IV::zero) {
		tKey.resize(key_len);
		if (iv_len) {
			tVec.resize(iv_len);
			memset(&tVec[0], 0, tVec.size());
			ptVec = &tVec[0];
		}
	}
	// --------------------------- key derivation:
	switch (options.key.algorithm)
	{
	case KeyDerivation::pbkdf2:
	{
		std::unique_ptr<PasswordBasedKeyDerivationFunction> pbkdf2;
		switch (crypt::Hash(options.key.options[0]))
		{
		case Hash::md4:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< Weak::MD4 >); break;
		case Hash::md5:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< Weak::MD5 >); break;
		case Hash::sha1:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA1 >); break;
		case Hash::sha256:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA256 >); break;
		case Hash::sha512:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA512 >); break;
		case Hash::ripemd128:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< RIPEMD128 >); break;
		case Hash::ripemd160:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< RIPEMD160 >); break;
		case Hash::ripemd256:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< RIPEMD256 >); break;
		case Hash::whirlpool:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< Whirlpool >); break;
		case Hash::tiger128:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< Tiger >); break;
		case Hash::sha3_224:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA3_224 >); break;
		case Hash::sha3_256:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA3_256 >); break;
		case Hash::sha3_384:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA3_384 >); break;
		case Hash::sha3_512:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA3_512 >); break;
		case Hash::keccak256:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< Keccak_256 >); break;
		case Hash::keccak512:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< Keccak_512 >); break;
		default: throw CExc(CExc::Code::invalid_pbkdf2_hash);
		}
		pbkdf2->DeriveKey(&tKey[0], tKey.size(),
			options.password.BytePtr(), options.password.size(),
			MakeParameters(Name::Salt(), ConstByteArrayParameter(ptSalt, options.key.salt_bytes))
			("Iterations", options.key.options[1]));
		break;
	}
	case crypt::KeyDerivation::bcrypt:
	{
		char output[64];
		char settings[32];

		if (_crypt_gensalt_blowfish_rn("$2a$", (unsigned long)options.key.options[0], (const char*)ptSalt, 16, settings, 32) == NULL) {
			throw CExc(CExc::Code::bcrypt_failed);
		}
		memset(output, 0, sizeof(output));
		if (_crypt_blowfish_rn((const char*)options.password.BytePtr(), settings, output, 64) == NULL) {
			throw CExc(CExc::Code::bcrypt_failed);
		}
		byte hashdata[23];
		ArraySource ss((const byte*)output + 29, 31, true, new Base64Decoder(new ArraySink(hashdata, 23)));
		shake128(hashdata, 23, &tKey[0], tKey.size());
		break;
	}
	case crypt::KeyDerivation::scrypt:
	{
		if (crypto_scrypt(options.password.BytePtr(), options.password.size(), ptSalt, options.key.salt_bytes, ipow<uint64_t>(2, options.key.options[0]), options.key.options[1], options.key.options[2], &tKey[0], tKey.size()) != 0) {
			throw CExc(CExc::Code::scrypt_failed);
		}
		//CryptoPP::Scrypt scrypt;
		//if (!scrypt.DeriveKey(&tKey[0], tKey.size(), password.BytePtr(), password.size(), ptSalt, options.key.salt_bytes, ipow<uint64_t>(2, options.key.options[0]), options.key.options[1], options.key.options[2])) {
		//	throw CExc(CExc::Code::scrypt_failed);
		//}
		break;
	}
	}
	try	{
		if ((cipher_properties[int(options.cipher)] & CipherProperties::stream) == CipherProperties::stream)	{
			std::unique_ptr<SymmetricCipherDocumentation::Decryption> pEnc;
			switch (options.cipher) {
			case Cipher::sosemanuk: pEnc.reset(new Sosemanuk::Decryption(tKey.data(), key_len, ptVec)); break;
			case Cipher::rc4: pEnc.reset(new Weak::ARC4::Decryption(tKey.data(), key_len)); break;
			case Cipher::salsa20: pEnc.reset(new Salsa20::Decryption(tKey.data(), key_len, ptVec)); break;
			case Cipher::xsalsa20: pEnc.reset(new XSalsa20::Encryption(tKey.data(), key_len, ptVec)); break;
			case Cipher::chacha20: pEnc.reset(new ChaCha20::Encryption(tKey.data(), key_len, ptVec)); break;
			case Cipher::panama: pEnc.reset(new PanamaCipher<LittleEndian>::Encryption(tKey.data(), key_len, ptVec)); break;
			default: throw CExc(CExc::Code::invalid_cipher);
			}
			switch (options.encoding.enc)
			{
			case Encoding::ascii:
			{
				buffer.resize(in_len);
				pEnc->ProcessData(&buffer[0], in, in_len);
				break;
			}
			case Encoding::base16: case Encoding::base32: case Encoding::base64:
			{
				std::basic_string<byte> temp;
				if (options.encoding.enc == Encoding::base16) {
					StringSource(in, in_len, true, new HexDecoder(new StringSinkTemplate<std::basic_string<byte>>(temp)));
				} else if (options.encoding.enc == Encoding::base32) {
					StringSource(in, in_len, true, new Base32Decoder(new StringSinkTemplate<std::basic_string<byte>>(temp)));
				} else {
					StringSource(in, in_len, true, new Base64Decoder(new StringSinkTemplate<std::basic_string<byte>>(temp)));
				}
				buffer.resize(temp.size());
				pEnc->ProcessData(&buffer[0], &temp[0], temp.size());
				break;
			}
			}
		} else {
			if (options.mode == Mode::gcm || options.mode == Mode::ccm || options.mode == Mode::eax) {
				std::unique_ptr<AuthenticatedSymmetricCipherDocumentation::Encryption> penc;
				int tag_size;
				switch (options.cipher)
				{
				case Cipher::cast256:
				{
					switch (options.mode)
					{
					case Mode::gcm: penc.reset(new GCM< CAST256 >::Decryption); tag_size = Constants::gcm_tag_size; break;
					case Mode::ccm: penc.reset(new CCM< CAST256 >::Decryption); tag_size = Constants::ccm_tag_size; break;
					case Mode::eax: penc.reset(new EAX< CAST256 >::Decryption); tag_size = Constants::eax_tag_size; break;
					}
					break;
				}
				case Cipher::rc6:
				{
					switch (options.mode)
					{
					case Mode::gcm: penc.reset(new GCM< RC6 >::Decryption); tag_size = Constants::gcm_tag_size; break;
					case Mode::ccm: penc.reset(new CCM< RC6 >::Decryption); tag_size = Constants::ccm_tag_size; break;
					case Mode::eax: penc.reset(new EAX< RC6 >::Decryption); tag_size = Constants::eax_tag_size; break;
					}
					break;
				}
				case Cipher::camellia:
				{
					switch (options.mode)
					{
					case Mode::gcm: penc.reset(new GCM< Camellia >::Decryption); tag_size = Constants::gcm_tag_size; break;
					case Mode::ccm: penc.reset(new CCM< Camellia >::Decryption); tag_size = Constants::ccm_tag_size; break;
					case Mode::eax: penc.reset(new EAX< Camellia >::Decryption); tag_size = Constants::eax_tag_size; break;
					}
					break;
				}
				case Cipher::seed:
				{
					switch (options.mode)
					{
					case Mode::gcm: penc.reset(new GCM< SEED >::Decryption); tag_size = Constants::gcm_tag_size; break;
					case Mode::ccm: penc.reset(new CCM< SEED >::Decryption); tag_size = Constants::ccm_tag_size; break;
					case Mode::eax: penc.reset(new EAX< SEED >::Decryption); tag_size = Constants::eax_tag_size; break;
					}
					break;
				}
				case Cipher::shacal2:
				{
					switch (options.mode)
					{
					case Mode::eax: penc.reset(new EAX< SHACAL2 >::Decryption); tag_size = Constants::eax_tag_size; break;
					default: throw CExc(CExc::Code::invalid_mode);
					}
					break;
				}
				case Cipher::mars:
				{
					switch (options.mode)
					{
					case Mode::gcm: penc.reset(new GCM< MARS >::Decryption); tag_size = Constants::gcm_tag_size; break;
					case Mode::ccm: penc.reset(new CCM< MARS >::Decryption); tag_size = Constants::ccm_tag_size; break;
					case Mode::eax: penc.reset(new EAX< MARS >::Decryption); tag_size = Constants::eax_tag_size; break;
					}
					break;
				}
				case Cipher::twofish:
				{
					switch (options.mode)
					{
					case Mode::gcm: penc.reset(new GCM< Twofish >::Decryption); tag_size = Constants::gcm_tag_size; break;
					case Mode::ccm: penc.reset(new CCM< Twofish >::Decryption); tag_size = Constants::ccm_tag_size;  break;
					case Mode::eax: penc.reset(new EAX< Twofish >::Decryption); tag_size = Constants::eax_tag_size;  break;
					}
					break;
				}
				case Cipher::serpent:
				{
					switch (options.mode)
					{
					case Mode::gcm: penc.reset(new GCM< Serpent >::Decryption); tag_size = Constants::gcm_tag_size; break;
					case Mode::ccm: penc.reset(new CCM< Serpent >::Decryption); tag_size = Constants::ccm_tag_size;  break;
					case Mode::eax: penc.reset(new EAX< Serpent >::Decryption); tag_size = Constants::eax_tag_size;  break;
					}
					break;
				}
				case Cipher::rijndael128: case Cipher::rijndael192: case Cipher::rijndael256:
				{
					switch (options.mode)
					{
					case Mode::gcm: penc.reset(new GCM< AES >::Decryption); tag_size = Constants::gcm_tag_size; break;
					case Mode::ccm: penc.reset(new CCM< AES >::Decryption); tag_size = Constants::ccm_tag_size; break;
					case Mode::eax: penc.reset(new EAX< AES >::Decryption); tag_size = Constants::eax_tag_size; break;
					}
					break;
				}
				}
				penc->SetKeyWithIV(tKey.data(), key_len, ptVec, iv_len);

				std::basic_string<byte> temp;
				const byte*				pEncrypted;
				size_t					Encrypted_size;
				
				switch (options.encoding.enc)
				{
				case Encoding::ascii:
				{
					pEncrypted = in;
					Encrypted_size = in_len;
					break;
				}
				case Encoding::base16: case Encoding::base32: case Encoding::base64:
				{
					if (options.encoding.enc == Encoding::base16) {
						StringSource(in, in_len, true, new HexDecoder(new StringSinkTemplate<std::basic_string<byte>>(temp)));
					} else if (options.encoding.enc == Encoding::base32) {
						StringSource(in, in_len, true, new Base32Decoder(new StringSinkTemplate<std::basic_string<byte>>(temp)));
					} else {
						StringSource(in, in_len, true, new Base64Decoder(new StringSinkTemplate<std::basic_string<byte>>(temp)));
					}
					pEncrypted = temp.c_str();
					Encrypted_size = temp.size();
					break;
				}
				}				

				if (options.mode == Mode::ccm) {
					penc->SpecifyDataLengths(init.salt.size() + init.iv.size(), Encrypted_size, 0);
				}

				AuthenticatedDecryptionFilter df(*penc, NULL, AuthenticatedDecryptionFilter::MAC_AT_BEGIN | AuthenticatedDecryptionFilter::THROW_EXCEPTION, tag_size);

				secure_string temp2;
				df.ChannelPut( DEFAULT_CHANNEL, init.tag.BytePtr(), init.tag.size());
				init.salt.get(temp2, Encoding::base64);
				df.ChannelPut( AAD_CHANNEL, (const byte*)temp2.c_str(), temp2.size());
				init.iv.get(temp2, Encoding::base64);
				df.ChannelPut( AAD_CHANNEL, (const byte*)temp2.c_str(), temp2.size());
				df.ChannelPut( DEFAULT_CHANNEL, pEncrypted, Encrypted_size);
				df.ChannelMessageEnd( AAD_CHANNEL );
				df.ChannelMessageEnd( DEFAULT_CHANNEL );

				if (!df.GetLastResult()) {
					throw CExc(CExc::Code::authentication_failed);
				}

				df.SetRetrievalChannel("");
				size_t n = (size_t)df.MaxRetrievable();
				buffer.resize(n);

				if (n > 0) { 
					df.Get((byte*)buffer.data(), n);
				}
			} else {
				std::unique_ptr<CipherModeBase> pEnc;
				switch (options.cipher)
				{
				case Cipher::des:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<DES>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<DES>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<DES>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<DES>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<DES>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::des_ede:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<DES_EDE2>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<DES_EDE2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<DES_EDE2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<DES_EDE2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<DES_EDE2>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::des_ede3:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<DES_EDE3>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<DES_EDE3>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<DES_EDE3>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<DES_EDE3>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<DES_EDE3>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::desx:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<DES_XEX3>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<DES_XEX3>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<DES_XEX3>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<DES_XEX3>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<DES_XEX3>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::gost:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<GOST>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<GOST>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<GOST>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<GOST>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<GOST>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::cast128:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<CAST128>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<CAST128>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<CAST128>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<CAST128>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<CAST128>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::cast256:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<CAST256>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<CAST256>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<CAST256>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<CAST256>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<CAST256>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::rc2:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<RC2>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<RC2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<RC2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<RC2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<RC2>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::rc5:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<RC5>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<RC5>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<RC5>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<RC5>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<RC5>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::rc6:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<RC6>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<RC6>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<RC6>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<RC6>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<RC6>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::idea:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<IDEA>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<IDEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<IDEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<IDEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<IDEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::blowfish:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<Blowfish>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<Blowfish>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<Blowfish>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<Blowfish>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<Blowfish>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::camellia:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<Camellia>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<Camellia>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<Camellia>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<Camellia>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<Camellia>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::seed:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<SEED>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<SEED>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<SEED>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<SEED>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<SEED>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::tea:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<TEA>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<TEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<TEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<TEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<TEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::xtea:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<XTEA>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<XTEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<XTEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<XTEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<XTEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::shacal2:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<SHACAL2>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<SHACAL2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<SHACAL2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<SHACAL2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<SHACAL2>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::mars:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<MARS>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<MARS>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<MARS>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<MARS>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<MARS>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::twofish:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<Twofish>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<Twofish>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<Twofish>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<Twofish>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<Twofish>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::serpent:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<Serpent>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<Serpent>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<Serpent>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<Serpent>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<Serpent>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				case Cipher::rijndael128: case Cipher::rijndael192: case Cipher::rijndael256:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<AES>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<AES>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<AES>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<AES>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<AES>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::Code::invalid_mode);
					} break;
				}
				default: throw CExc(CExc::Code::invalid_cipher);
				}
				switch (options.encoding.enc)
				{
				case Encoding::ascii:
				{
					StringSource(in, in_len, true, 
						new StreamTransformationFilter(*pEnc, 
							new StringSinkTemplate<std::basic_string<byte>>(buffer)));
					break;
				}
				case Encoding::base16:
				{
					StringSource(in, in_len, true, 
						new HexDecoder(
							new StreamTransformationFilter(*pEnc, new StringSinkTemplate<std::basic_string<byte>>(buffer))));
					break;
				}
				case Encoding::base32:
				{
					StringSource(in, in_len, true,
						new Base32Decoder(
							new StreamTransformationFilter(*pEnc, new StringSinkTemplate<std::basic_string<byte>>(buffer))
						)
					);
					break;
				}
				case Encoding::base64:
				{
					StringSource(in, in_len, true,
						new Base64Decoder(
							new StreamTransformationFilter(*pEnc, new StringSinkTemplate<std::basic_string<byte>>(buffer))
						)
					);
					break;
				}
				}
			}
		}
	} catch (CryptoPP::Exception& exc) {
		switch (exc.GetErrorType()) {
		case CryptoPP::Exception::NOT_IMPLEMENTED: throw CExc(CExc::Code::cryptopp_not_implemented); break;
		case CryptoPP::Exception::INVALID_ARGUMENT: throw CExc(CExc::Code::cryptopp_invalid_argument); break;
		case CryptoPP::Exception::CANNOT_FLUSH: throw CExc(CExc::Code::cryptopp_cannot_flush); break;
		case CryptoPP::Exception::DATA_INTEGRITY_CHECK_FAILED: throw CExc(CExc::Code::cryptopp_bad_integrity); break;
		case CryptoPP::Exception::INVALID_DATA_FORMAT: throw CExc(CExc::Code::cryptopp_invalid_data); break;
		case CryptoPP::Exception::IO_ERROR: throw CExc(CExc::Code::cryptopp_io_error); break;
		default: throw CExc(CExc::Code::cryptopp_other); break;
		}
	} catch (CExc& exc) {
		throw exc;
	} catch (...) {
		throw CExc(CExc::Code::unexpected);
	}
}

void crypt::hash(const Options::Hash& options, std::basic_string<byte>& buffer, std::initializer_list<std::pair<const byte*, size_t>> in)
{
	try	{
		using namespace CryptoPP;
		using namespace std;

		SecByteBlock digest;
		std::unique_ptr<HashTransformation> hash;
		std::unique_ptr<MessageAuthenticationCode> hmac;
		HashTransformation* phash;

		if (options.use_key) {
			if ((hash_properties[(unsigned)options.algorithm] & HashProperties::hmac_possible) != HashProperties::hmac_possible && 
				(hash_properties[(unsigned)options.algorithm] & HashProperties::key) != HashProperties::key) {
				throw CExc(CExc::Code::invalid_hash);
			}
			switch (options.algorithm)
			{
			case crypt::Hash::md4:
				hmac.reset(new HMAC< Weak::MD4 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::md5:
				hmac.reset(new HMAC< Weak::MD5 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::sha1:
				hmac.reset(new HMAC< SHA1 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::sha256:
				hmac.reset(new HMAC< SHA256 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::sha512:
				hmac.reset(new HMAC< SHA512 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::ripemd128:
				hmac.reset(new HMAC< RIPEMD128 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::ripemd160:
				hmac.reset(new HMAC< RIPEMD160 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::ripemd256:
				hmac.reset(new HMAC< RIPEMD256 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::whirlpool:
				hmac.reset(new HMAC< Whirlpool >(options.key.data(), options.key.size())); break;
			case crypt::Hash::tiger128:
				hmac.reset(new HMAC< Tiger >(options.key.data(), options.key.size())); break;
			case crypt::Hash::sha3_224:
				hmac.reset(new HMAC< SHA3_224 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::sha3_256:
				hmac.reset(new HMAC< SHA3_256 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::sha3_384:
				hmac.reset(new HMAC< SHA3_384 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::sha3_512:
				hmac.reset(new HMAC< SHA3_512 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::keccak256:
				hmac.reset(new HMAC< Keccak_256 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::keccak512:
				hmac.reset(new HMAC< Keccak_512 >(options.key.data(), options.key.size())); break;
			case Hash::blake2b:
				hmac.reset(new BLAKE2b(options.key.data(), options.key.size())); break;
			default: throw CExc(CExc::Code::invalid_hash);
			}
			phash = hmac.get();
		} else {
			switch (options.algorithm)
			{
			case crypt::Hash::md4: hash.reset(new Weak::MD4()); break;
			case crypt::Hash::md5: hash.reset(new Weak::MD5()); break;
			case crypt::Hash::sha1: hash.reset(new SHA1()); break;
			case crypt::Hash::sha256: hash.reset(new SHA256()); break;
			case crypt::Hash::sha512: hash.reset(new SHA512()); break;
			case crypt::Hash::ripemd128: hash.reset(new RIPEMD128()); break;
			case crypt::Hash::ripemd160: hash.reset(new RIPEMD160()); break;
			case crypt::Hash::ripemd256: hash.reset(new RIPEMD256()); break;
			case crypt::Hash::whirlpool: hash.reset(new Whirlpool()); break;
			case crypt::Hash::tiger128: hash.reset(new Tiger()); break;
			case crypt::Hash::sha3_224: hash.reset(new SHA3_224()); break;
			case crypt::Hash::sha3_256: hash.reset(new SHA3_256()); break;
			case crypt::Hash::sha3_384: hash.reset(new SHA3_384()); break;
			case crypt::Hash::sha3_512: hash.reset(new SHA3_512()); break;
			case crypt::Hash::keccak256: hash.reset(new Keccak_256()); break;
			case crypt::Hash::keccak512: hash.reset(new Keccak_512()); break;
			case crypt::Hash::blake2s: hash.reset(new BLAKE2s()); break;
			case crypt::Hash::blake2b: hash.reset(new BLAKE2b()); break;
			default: throw CExc(CExc::Code::invalid_hash);
			}
			
			phash = hash.get();
		}
		digest.resize(phash->DigestSize());
		for (const std::pair<const byte*, size_t>& i : in) {
			phash->Update(i.first, i.second);
		}
		phash->Final(digest);

		switch (options.encoding)
		{
		case crypt::Encoding::ascii:
		{
			buffer.assign(digest.begin(), digest.end());
			break;
		}
		case crypt::Encoding::base16:
		{
			StringSource(&digest[0], digest.size(), true, new HexEncoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), true, 0));
			break;
		}
		case crypt::Encoding::base32:
		{
			StringSource(&digest[0], digest.size(), true, new Base32Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), true, 0));
			break;
		}
		case crypt::Encoding::base64:
		{
			StringSource(&digest[0], digest.size(), true, new Base64Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), false));
			break;
		}
		}
	} catch (CExc& exc) {
		throw exc;
	} catch (...) {
		throw CExc(CExc::Code::unexpected);
	}
}

void crypt::hash(const Options::Hash& options, std::basic_string<byte>& buffer, const std::string& path)
{
	try {
		using namespace CryptoPP;
		using namespace std;

		SecByteBlock digest;
		std::unique_ptr<HashTransformation> hash;
		std::unique_ptr<MessageAuthenticationCode> hmac;
		HashTransformation* phash;

		if (options.use_key) {
			if ((hash_properties[(unsigned)options.algorithm] & HashProperties::hmac_possible) != HashProperties::hmac_possible &&
				(hash_properties[(unsigned)options.algorithm] & HashProperties::key) != HashProperties::key) {
				throw CExc(CExc::Code::invalid_hash);
			}
			switch (options.algorithm)
			{
			case crypt::Hash::md4:
				hmac.reset(new HMAC< Weak::MD4 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::md5:
				hmac.reset(new HMAC< Weak::MD5 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::sha1:
				hmac.reset(new HMAC< SHA1 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::sha256:
				hmac.reset(new HMAC< SHA256 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::sha512:
				hmac.reset(new HMAC< SHA512 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::ripemd128:
				hmac.reset(new HMAC< RIPEMD128 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::ripemd160:
				hmac.reset(new HMAC< RIPEMD160 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::ripemd256:
				hmac.reset(new HMAC< RIPEMD256 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::whirlpool:
				hmac.reset(new HMAC< Whirlpool >(options.key.data(), options.key.size())); break;
			case crypt::Hash::tiger128:
				hmac.reset(new HMAC< Tiger >(options.key.data(), options.key.size())); break;
			case crypt::Hash::sha3_224:
				hmac.reset(new HMAC< SHA3_224 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::sha3_256:
				hmac.reset(new HMAC< SHA3_256 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::sha3_384:
				hmac.reset(new HMAC< SHA3_384 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::sha3_512:
				hmac.reset(new HMAC< SHA3_512 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::keccak256:
				hmac.reset(new HMAC< Keccak_256 >(options.key.data(), options.key.size())); break;
			case crypt::Hash::keccak512:
				hmac.reset(new HMAC< Keccak_512 >(options.key.data(), options.key.size())); break;
			case Hash::blake2b:
				hmac.reset(new BLAKE2b(options.key.data(), options.key.size())); break;
			default: throw CExc(CExc::Code::invalid_hash);
			}
			phash = hmac.get();
		}
		else {
			switch (options.algorithm)
			{
			case crypt::Hash::md4: hash.reset(new Weak::MD4()); break;
			case crypt::Hash::md5: hash.reset(new Weak::MD5()); break;
			case crypt::Hash::sha1: hash.reset(new SHA1()); break;
			case crypt::Hash::sha256: hash.reset(new SHA256()); break;
			case crypt::Hash::sha512: hash.reset(new SHA512()); break;
			case crypt::Hash::ripemd128: hash.reset(new RIPEMD128()); break;
			case crypt::Hash::ripemd160: hash.reset(new RIPEMD160()); break;
			case crypt::Hash::ripemd256: hash.reset(new RIPEMD256()); break;
			case crypt::Hash::whirlpool: hash.reset(new Whirlpool()); break;
			case crypt::Hash::tiger128: hash.reset(new Tiger()); break;
			case crypt::Hash::sha3_224: hash.reset(new SHA3_224()); break;
			case crypt::Hash::sha3_256: hash.reset(new SHA3_256()); break;
			case crypt::Hash::sha3_384: hash.reset(new SHA3_384()); break;
			case crypt::Hash::sha3_512: hash.reset(new SHA3_512()); break;
			case crypt::Hash::keccak256: hash.reset(new Keccak_256()); break;
			case crypt::Hash::keccak512: hash.reset(new Keccak_512()); break;
			case crypt::Hash::blake2s: hash.reset(new BLAKE2s()); break;
			case crypt::Hash::blake2b: hash.reset(new BLAKE2b()); break;
			default: throw CExc(CExc::Code::invalid_hash);
			}

			phash = hash.get();
		}
		digest.resize(phash->DigestSize());

		FileSource f(path.c_str(), true, new HashFilter(*phash, new ArraySink(digest, digest.size())));

		switch (options.encoding)
		{
		case crypt::Encoding::ascii:
		{
			buffer.assign(digest.begin(), digest.end());
			break;
		}
		case crypt::Encoding::base16:
		{
			StringSource(&digest[0], digest.size(), true, new HexEncoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), true, 0));
			break;
		}
		case crypt::Encoding::base32:
		{
			StringSource(&digest[0], digest.size(), true, new Base32Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), true, 0));
			break;
		}
		case crypt::Encoding::base64:
		{
			StringSource(&digest[0], digest.size(), true, new Base64Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), false));
			break;
		}
		}
	}
	catch (CExc& exc) {
		throw exc;
	}
	catch (...) {
		throw CExc(CExc::Code::unexpected);
	}
}

void crypt::shake128(const byte* in, size_t in_len, byte* out, size_t out_len)
{
	Keccak_HashInstance keccak_inst;
	if (Keccak_HashInitialize_SHAKE128(&keccak_inst) != 0) {
		throw CExc(CExc::Code::keccak_shake_failed);
	}
	if (Keccak_HashUpdate(&keccak_inst, in, in_len * 8) != 0) {
		throw CExc(CExc::Code::keccak_shake_failed);
	}
	if (Keccak_HashFinal(&keccak_inst, out) != 0) {
		throw CExc(CExc::Code::keccak_shake_failed);
	}
	if (Keccak_HashSqueeze(&keccak_inst, out, out_len * 8) != 0) {
		throw CExc(CExc::Code::keccak_shake_failed);
	}
}

void crypt::random(const Options::Random& options, std::basic_string<byte>& buffer)
{
	if (options.length == 0) {
		buffer.clear();
		return;
	}

	using namespace CryptoPP;
	using namespace crypt;

	buffer.clear();

	switch(options.mode)
	{
	case Random::ascii:
	{
		buffer.resize(options.length);
		OS_GenerateRandomBlock(true, &buffer[0], (int)options.length);
		break;
	}
	case Random::base16: case Random::base32: case Random::base64:
	{
		std::vector<unsigned char> tbuf;
		tbuf.resize(options.length);
		OS_GenerateRandomBlock(true, &tbuf[0], (int)options.length);
		if (options.mode == Random::base16) {
			StringSource(&tbuf[0], tbuf.size(), true, new HexEncoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), true));
		} else if (options.mode == Random::base32) {
			StringSource(&tbuf[0], tbuf.size(), true, new Base32Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), true));
		} else {
			StringSource(&tbuf[0], tbuf.size(), true, new Base64Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), false));
		}
		break;
	}
	case Random::charnum:
	{
		buffer.resize(options.length);
		unsigned char temp[Constants::rand_char_bufsize];
		size_t i = 0;
		while (i < options.length) {
			OS_GenerateRandomBlock(false, temp, Constants::rand_char_bufsize);
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
		break;
	}	
	case Random::specials:
	{
		buffer.resize(options.length);
		unsigned char temp[Constants::rand_char_bufsize];
		size_t i = 0;
		while(i < options.length) {
			OS_GenerateRandomBlock(false, temp, Constants::rand_char_bufsize);
			for(int x = 0; x < Constants::rand_char_bufsize && i < options.length; x++) {
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

void crypt::convert(const byte* in, size_t in_len, std::basic_string<byte>& buffer, const Options::Convert& options)
{
	using namespace CryptoPP;
	using namespace crypt;

	std::string s_seperator = (options.eol == crypt::EOL::windows) ? "\r\n" : "\n";
	int groupsize = options.linebreaks ? options.linelength : 0;

	switch (options.from)
	{
	case Encoding::ascii:
	{
		switch (options.to)
		{
		case Encoding::base16:
		{
			StringSource(in, in_len, true, new HexEncoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.uppercase, groupsize, s_seperator));
			break;
		}
		case Encoding::base32:
		{
			StringSource(in, in_len, true, new Base32Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.uppercase, groupsize, s_seperator));
			break;
		}
		case Encoding::base64:
		{
			StringSource(in, in_len, true, new Base64Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.linebreaks, options.linelength, CryptoPP::EOL(options.eol)));
			break;
		}
		}
		break;
	}
	case Encoding::base16:
	{
		switch (options.to)
		{
		case Encoding::ascii:
		{
			StringSource(in, in_len, true, new HexDecoder(new StringSinkTemplate<std::basic_string<byte>>(buffer)));
			break;
		}
		case Encoding::base32:
		{
			StringSource(in, in_len, true, new HexDecoder(new Base32Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.uppercase, groupsize, s_seperator)));
			break;
		}
		case Encoding::base64:
		{
			StringSource(in, in_len, true, new HexDecoder(new Base64Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.linebreaks, options.linelength, CryptoPP::EOL(options.eol))));
			break;
		}
		}
		break;
	}
	case Encoding::base32:
	{
		switch (options.to)
		{
		case Encoding::ascii:
		{
			StringSource(in, in_len, true, new Base32Decoder(new StringSinkTemplate<std::basic_string<byte>>(buffer)));
			break;
		}
		case Encoding::base16:
		{
			StringSource(in, in_len, true, new Base32Decoder(new HexEncoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.uppercase, groupsize, s_seperator)));
			break;
		}
		case Encoding::base64:
		{
			StringSource(in, in_len, true, new Base32Decoder(new Base64Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.linebreaks, options.linelength, CryptoPP::EOL(options.eol))));
			break;
		}
		}
		break;
	}
	case Encoding::base64:
	{
		switch (options.to)
		{
		case Encoding::ascii:
		{
			StringSource(in, in_len, true, new Base64Decoder(new StringSinkTemplate<std::basic_string<byte>>(buffer)));
			break;
		}
		case Encoding::base16:
		{
			StringSource(in, in_len, true, new Base64Decoder(new HexEncoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.uppercase, groupsize, s_seperator)));
			break;
		}
		case Encoding::base32:
		{
			StringSource(in, in_len, true, new Base64Decoder(new Base32Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.uppercase, groupsize, s_seperator)));
			break;
		}
		}
		break;
	}
	}
}

// ===========================================================================================================================================================================

int crypt::help::Iter::_what = 0;
int crypt::help::Iter::i = -1;
int crypt::help::Iter::_cipher = -1;
int crypt::help::Iter::_temp = 0;
unsigned int crypt::help::Iter::_filter = 0;

void crypt::help::Iter::setup_cipher(CipherCat category)
{
	_what = 0;
	i = -1;
	switch (category) {
	case CipherCat::aes: _temp = CipherProperties::c_aes; break;
	case CipherCat::other: _temp = CipherProperties::c_other; break;
	case CipherCat::stream: _temp = CipherProperties::c_stream; break;
	case CipherCat::weak: _temp = CipherProperties::c_weak; break;
	default: _temp = -1;
	}
}

void crypt::help::Iter::setup_mode(Cipher cipher)
{
	_what = 1;
	_cipher = int(cipher);
	i = -1;
}

void crypt::help::Iter::setup_hash(unsigned int filter)
{
	_what = 2;
	i = -1;
	_filter = filter;
}

bool crypt::help::Iter::next()
{
	i++;
	switch (_what)
	{
	case 0:
	{
		while (i < static_cast<int>(Cipher::COUNT)) {
			if (_temp == -1 || (cipher_properties[i] & _temp) == _temp) {
				return true;
			}
			i++;
		}
		return false;
	}
	case 1:
	{
		if ((cipher_properties[_cipher] & CipherProperties::stream) == CipherProperties::stream) {
			return false;
		}
		while (i < static_cast<int>(Mode::COUNT)) {
			if (((int(Mode::eax) == i && (cipher_properties[_cipher] & CipherProperties::eax) != CipherProperties::eax))
				|| ((int(Mode::ccm) == i && (cipher_properties[_cipher] & CipherProperties::ccm) != CipherProperties::ccm))
				|| ((int(Mode::gcm) == i && (cipher_properties[_cipher] & CipherProperties::gcm) != CipherProperties::gcm)))
			{
				i++;
				continue;
			}
			return true;
			i++;
		}
		return false;
	}
	case 2:
	{
		while (i < static_cast<int>(Hash::COUNT)) {
			if (((_filter & HashProperties::weak) == HashProperties::weak && (hash_properties[i] & HashProperties::weak) != HashProperties::weak) ||
				((_filter & HashProperties::hmac_possible) == HashProperties::hmac_possible && (hash_properties[i] & HashProperties::hmac_possible) != HashProperties::hmac_possible) ||
				((_filter & HashProperties::key) == HashProperties::key && (hash_properties[i] & HashProperties::key) != HashProperties::key)) {
				i++;
				continue;
			} else {
				return true;
			}
		}
		i = -1;
		return false;
	}
	}
	return false;
}

const char* crypt::help::Iter::getString()
{
	if (i < 0) {
		return NULL;
	}
	switch (_what)
	{
	case 0:	return Strings::cipher[i];
	case 1:	return Strings::mode[i];
	case 2:	return Strings::hash[i];
	}
	return NULL;
}


const char* crypt::help::getString(crypt::Cipher cipher)
{
	return Strings::cipher[static_cast<int>(cipher)];
}

const char* crypt::help::getString(crypt::Mode mode)
{
	return Strings::mode[static_cast<int>(mode)];
}

const char*  crypt::help::getString(crypt::Encoding enc)
{
	return Strings::encoding[static_cast<int>(enc)];
}

const char* crypt::help::getString(crypt::KeyDerivation k)
{
	return Strings::key_algo[static_cast<int>(k)];
}

const char* crypt::help::getString(crypt::IV iv)
{
	return Strings::iv[static_cast<int>(iv)];
}

const char* crypt::help::getString(crypt::Hash h)
{
	return Strings::hash[static_cast<int>(h)];
}

const char* crypt::help::getString(crypt::Random mode)
{
	return Strings::random_mode[static_cast<int>(mode)];
}

const char* crypt::help::getString(crypt::EOL eol)
{
	return Strings::eol[static_cast<int>(eol)];
}

bool crypt::help::getCipher(const char* s, crypt::Cipher& c)
{
	if (!s) {
		return false;
	}
	size_t sl = strlen(s);
	for (size_t i = 0; i< static_cast<int>(Cipher::COUNT); i++)	{
		if (sl != strlen(Strings::cipher[i])) {
			continue;
		}
		size_t x = 0;
		for (x = 0; x< sl; x++) {
			if (s[x] != Strings::cipher[i][x]) {
				break;
			}
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
	if (!s) {
		return false;
	}
	for (size_t i = 0; i< static_cast<int>(Mode::COUNT); i++) {
		size_t sl = strlen(s), x = 0;
		if (sl != strlen(Strings::mode[i])) {
			continue;
		}
		for (x = 0; x< sl; x++) {
			if (s[x] != Strings::mode[i][x]) {
				break;
			}
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
	if (!s) {
		return false;
	}
	for (int i = 0; i<static_cast<int>(KeyDerivation::COUNT); i++) {
		if (strcmp(s, Strings::key_algo[i]) == 0) {
			v = (crypt::KeyDerivation)i;
			return true;
		}
	}
	return false;
}

bool crypt::help::getIVMode(const char* s, crypt::IV& iv)
{
	if (!s) {
		return false;
	}
	for (int i = 0; i<static_cast<int>(IV::COUNT); i++)	{
		if (strcmp(s, Strings::iv[i]) == 0) {
			iv = (crypt::IV)i;
			return true;
		}
	}
	return false;
}

bool crypt::help::getEncoding(const char* s, crypt::Encoding& e)
{
	if (!s) {
		return false;
	}
	for (int i = 0; i<static_cast<int>(Encoding::COUNT); i++) {
		if (strcmp(s, Strings::encoding[i]) == 0) {
			e = (crypt::Encoding)i;
			return true;
		}
	}
	return false;
}

bool crypt::help::getRandomMode(const char* s, crypt::Random& m)
{
	if (!s) {
		return false;
	}
	for (int i = 0; i<static_cast<int>(crypt::Random::COUNT); i++) {
		if (strcmp(s, Strings::random_mode[i]) == 0) {
			m = (crypt::Random)i;
			return true;
		}
	}
	return false;
}

bool crypt::help::getEOL(const char* s, crypt::EOL& eol)
{
	if (!s) {
		return false;
	}
	for (int i = 0; i<static_cast<int>(crypt::EOL::COUNT); i++) {
		if (strcmp(s, Strings::eol[i]) == 0) {
			eol = (crypt::EOL)i;
			return true;
		}
	}
	return false;
}

bool crypt::help::getHash(const char* s, Hash& h, bool only_openssl)
{
	if (!s) {
		return false;
	}
	size_t m = (only_openssl) ? static_cast<size_t>(Hash::sha3_256) : static_cast<size_t>(Hash::COUNT);
	for (size_t i = 0; i< m; i++) {
		size_t sl = strlen(s), x = 0;
		if (sl != strlen(Strings::hash[i])) {
			continue;
		}
		for (x = 0; x< sl; x++) {
			if (s[x] != Strings::hash[i][x]) {
				break;
			}
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
	if (index < int(Mode::eax))	{
		return Mode(index);
	} else if (index == int(Mode::eax))	{
		if ((cipher_properties[int(cipher)] & CipherProperties::eax) == CipherProperties::eax) {
			return Mode::eax;
		}
	} else if (index == int(Mode::ccm))	{
		if ((cipher_properties[int(cipher)] & CipherProperties::ccm) == CipherProperties::ccm) {
			return Mode::ccm;
		}
	} else if (index == int(Mode::gcm))	{
		if ((cipher_properties[int(cipher)] & CipherProperties::gcm) == CipherProperties::gcm) {
			return Mode::gcm;
		}
	}
	return Mode::cbc;
}

int crypt::help::getIndexByMode(crypt::Cipher cipher, crypt::Mode mode)
{
	if (mode == Mode::eax) {
		if ((cipher_properties[int(cipher)] & CipherProperties::eax) == CipherProperties::eax) {
			return int(Mode::eax);
		}
	} else if (mode == Mode::ccm) {
		if ((cipher_properties[int(cipher)] & CipherProperties::ccm) == CipherProperties::ccm) {
			return int(Mode::ccm);
		}
	} else if (mode == Mode::gcm) {
		if ((cipher_properties[int(cipher)] & CipherProperties::gcm) == CipherProperties::gcm) {
			return int(Mode::gcm);
		}
	} else {
		return int(mode);
	}
	return -1;
}

bool crypt::help::validCipherMode(crypt::Cipher cipher, crypt::Mode mode)
{
	if (mode == Mode::eax) {
		if ((cipher_properties[int(cipher)] & CipherProperties::eax) == CipherProperties::eax) {
			return true;
		}
	} else if (mode == Mode::ccm) {
		if ((cipher_properties[int(cipher)] & CipherProperties::ccm) == CipherProperties::ccm) {
			return true;
		}
	} else if (mode == Mode::gcm) {
		if ((cipher_properties[int(cipher)] & CipherProperties::gcm) == CipherProperties::gcm) {
			return true;
		}
	} else {
		return true;
	}
	return false;
}

int crypt::help::getCipherCategory(Cipher cipher)
{
	if ((cipher_properties[int(cipher)] & CipherProperties::c_aes) == CipherProperties::c_aes) {
		return 0;
	} else if ((cipher_properties[int(cipher)] & CipherProperties::c_other) == CipherProperties::c_other) {
		return 1;
	} else if ((cipher_properties[int(cipher)] & CipherProperties::c_stream) == CipherProperties::c_stream) {
		return 2;
	} else if ((cipher_properties[int(cipher)] & CipherProperties::c_weak) == CipherProperties::c_weak) {
		return 3;
	}
	return -1;
}

crypt::Cipher crypt::help::getCipherByIndex(CipherCat category, int index)
{
	int i = 0;
	int ii = -1;
	int cat = 0;
	if (category == CipherCat::all) {
		return (index < int(Cipher::COUNT)) ? Cipher(index) : Cipher::rijndael256;
	}
	switch (category) {
	case CipherCat::aes: cat = CipherProperties::c_aes; break;
	case CipherCat::other: cat = CipherProperties::c_other; break;
	case CipherCat::stream: cat = CipherProperties::c_stream; break;
	case CipherCat::weak: cat = CipherProperties::c_weak; break;
	}
	for (i = 0; i < int(Cipher::COUNT); i++) {
		if ((cipher_properties[i] & cat) == cat) {
			ii++;
		}
		if (ii == index) {
			break;
		}
	}
	return Cipher(i);
}

int crypt::help::getCipherIndex(Cipher cipher)
{
	int cat;
	if ((cipher_properties[int(cipher)] & CipherProperties::c_aes) == CipherProperties::c_aes) {
		cat = CipherProperties::c_aes;
	} else if ((cipher_properties[int(cipher)] & CipherProperties::c_other) == CipherProperties::c_other) {
		cat = CipherProperties::c_other;
	} else if ((cipher_properties[int(cipher)] & CipherProperties::c_stream) == CipherProperties::c_stream) {
		cat = CipherProperties::c_stream;
	} else {
		cat = CipherProperties::c_weak;
	}
	int index = -1;
	for (int i = 0; i < int(Cipher::COUNT); i++) {
		if ((cipher_properties[i] & cat) == cat) {
			index++;
		}
		if (i == int(cipher)) {
			break;
		}
	}
	return index;
}

bool crypt::help::checkHashProperty(crypt::Hash h, int filter)
{
	if ((unsigned)h >= (unsigned)Hash::COUNT) {
		return false;
	}
	return ((hash_properties[(unsigned)h] & filter) == filter);
}

const char* crypt::help::getHelpURL(crypt::Encoding enc)
{
	strcpy(Strings::help_url_wikipedia + Strings::help_url_wikipedia_len, Strings::encoding_help_url[unsigned(enc)]);
	return Strings::help_url_wikipedia;
}

const char*	crypt::help::getHelpURL(crypt::Cipher cipher)
{
	strcpy(Strings::help_url_wikipedia + Strings::help_url_wikipedia_len, Strings::cipher_help_url[unsigned(cipher)]);
	return Strings::help_url_wikipedia;
}

const char*	crypt::help::getHelpURL(crypt::Hash h)
{
	strcpy(Strings::help_url_wikipedia + Strings::help_url_wikipedia_len, Strings::hash_help_url[unsigned(h)]);
	return Strings::help_url_wikipedia;
}

const char*	crypt::help::getHelpURL(crypt::KeyDerivation k)
{
	strcpy(Strings::help_url_wikipedia + Strings::help_url_wikipedia_len, Strings::key_algo_help_url[unsigned(k)]);
	return Strings::help_url_wikipedia;
}

const char*	crypt::help::getHelpURL(crypt::Mode m)
{
	strcpy(Strings::help_url_wikipedia + Strings::help_url_wikipedia_len, Strings::mode_help_url[unsigned(m)]);
	return Strings::help_url_wikipedia;
}