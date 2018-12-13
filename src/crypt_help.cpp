/*
This file is part of nppcrypt
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

#include "crypt_help.h"
#include "exception.h"
#include "mdef.h"

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

const enum { B4 = 1, B8 = 2, B12 = 4, B16 = 8, B20 = 16, B24 = 32, B28 = 64, B32 = 128, B36 = 256, B40 = 512, B44 = 1024, B48 = 2048, B52 = 4096, B56 = 8192, B60 = 16384, B64 = 32768 };

static const unsigned int cipher_properties[unsigned(crypt::Cipher::COUNT)] =
{
	/* threeway			*/	BLOCK | WEAK,
	/* aria				*/	BLOCK | EAX | CCM | GCM,
	/* blowfish			*/	BLOCK | WEAK,
	/* camellia			*/	BLOCK | EAX | CCM | GCM,
	/* cast128			*/	BLOCK,
	/* cast256			*/	BLOCK | EAX | CCM | GCM,
	/* chacha20			*/	STREAM,
	/* des				*/	BLOCK | WEAK,
	/* des_ede2			*/	BLOCK,
	/* des_ede3			*/	BLOCK ,
	/* desx				*/	BLOCK | WEAK,
	/* gost				*/	BLOCK | WEAK,
	/* idea				*/	BLOCK,
	/* kalyna128		*/	BLOCK | EAX | CCM | GCM,
	/* kalyna256		*/	BLOCK,
	/* kalyna512		*/	BLOCK,
	/* mars				*/	BLOCK | EAX | CCM | GCM,
	/* panama			*/	STREAM,
	/* rc2				*/	BLOCK | WEAK,
	/* rc4				*/	STREAM | WEAK,
	/* rc5				*/	BLOCK,
	/* rc6				*/	BLOCK | EAX | CCM | GCM,
	/* rijndael			*/	BLOCK | EAX | CCM | GCM,
	/* saferk			*/	BLOCK,
	/* safersk			*/	BLOCK,
	/* salsa20			*/	STREAM,
	/* seal				*/	STREAM | WEAK,
	/* seed				*/	BLOCK | EAX | CCM | GCM,
	/* serpent			*/	BLOCK | EAX | CCM | GCM,
	/* shacal2			*/	BLOCK,
	/* shark			*/	BLOCK | WEAK,
	/* simon128			*/	BLOCK | WEAK | EAX | CCM | GCM,
	/* skipjack			*/	BLOCK | WEAK,
	/* sm4				*/	BLOCK | EAX | CCM | GCM,
	/* sosemanuk		*/	STREAM,
	/* speck128			*/	BLOCK | WEAK | EAX | CCM | GCM,
	/* square			*/	BLOCK | WEAK | EAX | CCM | GCM,
	/* tea				*/	BLOCK | WEAK,
	/* threefish256		*/	BLOCK,
	/* threefish512		*/	BLOCK,
	/* threefish1024	*/	BLOCK,
	/* twofish			*/	BLOCK | EAX | CCM | GCM,
	/* wake				*/	STREAM | WEAK,
	/* xsalsa20			*/	STREAM,
	/* xtea				*/	BLOCK
};

/* { Start, Stepsize, Count } in Bytes */
static const unsigned int cipher_keys[unsigned(crypt::Cipher::COUNT)][3] =
{
	/* threeway			*/	{12, 0, 1},
	/* aria				*/	{16, 8, 3},
	/* blowfish			*/	{16, 16, 2},
	/* camellia			*/  {16, 8, 3},
	/* cast128			*/	{16, 0, 1},
	/* cast256			*/	{16, 4, 5},
	/* chacha20			*/	{16, 16, 2},
	/* des				*/	{8, 0, 1},
	/* des_ede2			*/	{16, 0, 1},
	/* des_ede3			*/  {24, 0, 1},
	/* desx				*/	{24, 0, 1},
	/* gost				*/	{32, 0, 1},
	/* idea				*/	{16, 0, 1},
	/* kalyna128		*/	{16, 16, 2},
	/* kalyna256		*/	{32, 32, 2},
	/* kalyna512		*/	{64, 0, 1},
	/* mars				*/	{16, 8, 3},
	/* panama			*/	{32, 0, 1},
	/* rc2				*/	{16, 16, 4},
	/* rc4				*/  {16, 16, 4},
	/* rc5				*/  {16, 16, 4},
	/* rc6				*/	{16, 8, 3},
	/* rijndael			*/	{16, 8, 3},
	/* saferk			*/	{8, 8, 2},
	/* safersk			*/	{8, 8, 2},
	/* salsa20			*/	{16, 16, 2},
	/* seal				*/	{20, 0, 1},
	/* seed				*/	{16, 0, 1},
	/* serpent			*/	{16, 8, 3},
	/* shacal2			*/	{16, 16, 4},
	/* shark			*/	{16, 0, 1},
	/* simon128			*/	{16, 16, 2},
	/* skipjack			*/	{10, 0, 1},
	/* sm4				*/	{16, 0, 1},
	/* sosemanuk		*/	{16, 16, 2},
	/* speck128			*/	{16, 16, 2},
	/* square			*/	{16, 0, 1},
	/* tea				*/	{16, 0, 1},
	/* threefish256		*/	{32, 0, 1},
	/* threefish512		*/	{64, 0, 1},
	/* threefish1024	*/	{128, 0, 1},
	/* twofish			*/	{16, 8, 3},
	/* wake				*/	{32, 0, 1},
	/* xsalsa20			*/	{32, 0, 1},
	/* xtea				*/	{16, 0, 1}
};

static const unsigned int hash_properties[unsigned(crypt::Hash::COUNT)] =
{
	/* adler32		*/	WEAK,
	/* blake2b		*/	KEY_SUPPORT,
	/* blake2s		*/	KEY_SUPPORT,
	/* cmac_aes		*/	KEY_SUPPORT | KEY_REQUIRED,
	/* crc32		*/	WEAK,
	/* keccak		*/	HMAC_SUPPORT,
	/* md2			*/	HMAC_SUPPORT | WEAK,
	/* md4			*/	HMAC_SUPPORT | WEAK,
	/* md5			*/	HMAC_SUPPORT | WEAK,
	/* ripemd		*/	HMAC_SUPPORT,
	/* sha1			*/	HMAC_SUPPORT | WEAK,
	/* sha2			*/	HMAC_SUPPORT,
	/* sha3			*/	HMAC_SUPPORT,
	/* siphash24	*/	KEY_SUPPORT | KEY_REQUIRED,
	/* siphash48	*/	KEY_SUPPORT | KEY_REQUIRED,
	/* sm3			*/  HMAC_SUPPORT,
	/* tiger		*/  HMAC_SUPPORT,
	/* whirlpool	*/	HMAC_SUPPORT
};

static const unsigned int hash_digests[unsigned(crypt::Hash::COUNT)] =
{
	/* adler32		*/	B4,
	/* blake2b		*/	B16 | B28 | B32 | B48 | B64,
	/* blake2s		*/	B16 | B32,
	/* cmac_aes		*/	B16,
	/* crc32		*/	B4,
	/* keccak		*/	B28 | B32 | B48 | B64,
	/* md2			*/	B16,
	/* md4			*/	B16,
	/* md5			*/	B16,
	/* ripemd		*/	B16 | B20 | B32 | B40,
	/* sha1			*/	B20,
	/* sha2			*/	B28 | B32 | B48 | B64,
	/* sha3			*/	B28 | B32 | B48 | B64,
	/* siphash24	*/	B8 | B16,
	/* siphash48	*/	B8 | B16,
	/* sm3			*/  B32,
	/* tiger		*/  B24,
	/* whirlpool	*/	B64,
};

/* { startindex , endindex } of crypt::Cipher */
#define CIPHER_CAT_COUNT 4
static const int cipher_categories[4][2] =
{
	/* A - D	*/ { 0, 10 },
	/* E - R	*/ { 11, 22 },
	/* S		*/ { 23, 36 },
	/* T - Z	*/ { 37, 44 }
};

// ----------------------------- STRINGS ---------------------------------------------------------------------------------------------------------------------------------------------------------
namespace Strings {
	static const char*	cipher[] = { "3way", "aria", "blowfish", "camellia", "cast128", "cast256", "chacha", "des", "des_ede2", "des_ede3", "desx", "gost", "idea", "kalyna128", "kalyna256", "kalyna512", "mars", "panama", "rc2", "rc4", "rc5", "rc6", "rijndael", "saferk", "safersk", "salsa20", "seal", "seed", "serpent", "shacal2", "shark", "simon128", "skipjack", "sm4", "sosemanuk", "speck128", "square", "tea", "threefish256", "threefish512", "threefish1024", "twofish", "wake", "xSalsa20", "xtea" };
	static const char*	cipher_label[] = { "3-way", "ARIA", "Blowfish", "Camellia", "CAST-128", "CAST-256", "ChaCha", "DES", "2TDEA", "3TDEA", "DES-X", "GOST", "IDEA", "Kalyna-128", "Kalyna-256", "Kalyna-512", "MARS", "Panama", "RC2", "RC4", "RC5", "RC6", "Rijndael", "SAFER-K", "SAFER-SK", "Salsa20", "SEAL", "SEED", "Serpent", "SHACAL-2", "SHARK", "Simon-128", "Skipjack", "SM4", "Sosemanuk", "Speck-128", "Square", "TEA", "Threefish-256", "Threefish-512", "Threefish-1024", "Twofish", "WAKE", "XSalsa20", "XTEA" };
	static const char*	cipher_info_url[] = { "3-Way", "ARIA_(cipher)", "Blowfish_(cipher)", "Camellia_(cipher)", "CAST-128", "CAST-256", "Salsa20#ChaCha_variant", "Data_Encryption_Standard", "Triple_DES", "Triple_DES", "DES-X", "GOST_(block_cipher)", "International_Data_Encryption_Algorithm", "Kalyna_(cipher)", "Kalyna_(cipher)", "Kalyna_(cipher)", "MARS_(cryptography)", "Panama_(cryptography)", "RC2", "RC4", "RC5", "RC6", "Advanced_Encryption_Standard", "SAFER", "SAFER", "Salsa20", "SEAL_(cipher)", "SEED", "Serpent_(cipher)", "SHACAL", "SHARK", "Simon_(cipher)", "Skipjack_(cipher)", "SM4_algorithm", "SOSEMANUK", "Speck_(cipher)", "Square_(cipher)", "Tiny_Encryption_Algorithm", "Threefish", "Threefish", "Threefish", "Twofish", "WAKE_(cipher)", "Salsa20", "XTEA" };
	static const char*	cipher_info[] = { "Joan Daemen, 1993", "South Korean standard, 2003", "Bruce Schneier, 1993", "Mitsubishi Electric, 2000", "Carlisle Adams and Stafford Tavares, 1996", "Carlisle Adams, Stafford Tavares et al., 1998", "Daniel J. Bernstein, 2008", "IBM, 1975", "2-key Triple DES", "3-key Triple DES", "Ron Rivest, 1994", "Soviet standard, 1970s", "Xuejia Lai and James Massey, 1991", "Ukrainian standard based on rijndael", "Ukrainian standard based on rijndael", "Ukrainian standard based on rijndael", "IBM, 1998", "Joan Daemen, Craig Clapp, 1998", "Ronald Rivest, 1987", "Ronald Rivest, 1987", "Ronald Rivest, 1994", "Ron Rivest et. al., 1998", "Vincent Rijmen, Joan Daemen, 1998", "James Massey, 1993", "James Massey, 1993", "Daniel J. Bernstein, 2007", "Phillip Rogaway, Don Coppersmith, 1997", "Korea Information Security Agency, 1998", "Ross Anderson, Eli Biham, Lars Knudsen, 1998", "Helena Handschuh, David Naccache", "Vincent Rijmen et al., 1996", "NSA, 2013", "NSA, 1998", "Lu Shu-wang, 2006", "C. Berbain, O. Billet, et al.", "NSA, 2013", "Joan Daemen, Vincent Rijmen, 1997", "Roger Needham, David Wheeler, 1994", "Bruce Schneier et al., 2008", "Bruce Schneier et al., 2008", "Bruce Schneier et al., 2008", "Bruce Schneier, 1998", "David Wheeler, 1993", "Daniel J. Bernstein, 2007", "Needham and Wheeler, 1997" };
	static const char*	cipher_categories[] = { "A - D", "E - R", "S", "T - Z" };

	static const char*	mode[] = { "ecb", "cbc", "cfb", "ofb", "ctr", "eax", "ccm", "gcm" };
	static const char*	mode_info_url[] = { "Block_cipher_mode_of_operation#Electronic_Codebook_(ECB)", "Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)", "Block_cipher_mode_of_operation#Cipher_Feedback_(CFB)", "Block_cipher_mode_of_operation#Output_Feedback_(OFB)", "Block_cipher_mode_of_operation#Counter_(CTR)", "EAX_mode", "CCM_mode", "Galois/Counter_Mode" };
	static const char*	mode_info[] = { "Electronic Codebook: each block is encrypted separately", "Cipher Block Chaining by Ehrsam, Meyer, Smith and Tuchman, 1976", "Cipher Feedback Mode", "Output Feedback Mode", "Counter Mode by Whitfield Diffie and Martin Hellman, 1979", "authenticated encryption algorithm by Bellare, Rogaway, Wagner, 2003", "authenticated encryption algorithm by Russ Housley, Doug Whiting and Niels Ferguson", "Galois/Counter Mode" };

	static const char*	iv[] = { "random", "keyderivation", "zero", "custom" };
	static const char*	iv_help[] = { "Win32:CryptGenRandom() is used", "use keyderivation to create Key + IV", "use zero vector", "user specified IV" };

	static const char*	hash[] = { "adler32", "blake2b", "blake2s", "cmac_aes", "crc32", "keccak", "md2", "md4", "md5", "ripemd", "sha1", "sha2", "sha3", "siphash24", "siphash48", "sm3", "tiger", "whirlpool" };
	static const char*	hash_label[] = { "Adler-32", "BLAKE2b", "BLAKE2s", "CMAC<AES>", "CRC-32", "Keccak", "MD2", "MD4", "MD5", "RIPEMD", "SHA-1", "SHA-2", "SHA-3", "SipHash-2-4", "SipHash-4-8", "SM3", "Tiger", "Whirlpool" };
	static const char*	hash_info_url[] = { "Adler-32","BLAKE_(hash_function)#BLAKE2", "BLAKE_(hash_function)#BLAKE2", "One-key_MAC", "Cyclic_redundancy_check", "SHA-3", "MD2_(cryptography)", "MD4", "MD5", "RIPEMD", "SHA-1", "SHA-2", "SHA-3", "SipHash", "SipHash", "SM3", "Tiger_(cryptography)", "Whirlpool_(cryptography)" };
	static const char*	hash_info[] = { "non-cryptographic checksum; Mark Adler, 1995", "Aumasson, Neves, O'Hearn, Winnerlein, 2012", "Aumasson, Neves, O'Hearn, Winnerlein, 2012", "fixed keylength of 16 bytes", "non-cryptographic checksum, polynomial: 0xEDB88320; Peterson, 1961", "f1600 with XOF d=0x01 (see SHA-3); Bertoni, Daemen, Peeters, Van Assche, 2015", "Ronald Rivest, 1989", "Ronald Rivest, 1990", "Ronald Rivest, 1992", "Dobbertin, Bosselaers, Preneel, 1996", "NSA, 1993", "NIST, 2001", "Keccak F1600 with XOF d=0x06 (FIPS 202); Bertoni, Daemen, Peeters, Van Assche, 2015", "fixed keylength of 16 bytes; Aumasson, Bernstein, 2012", "fixed keylength of 16 bytes; Aumasson, Bernstein, 2012", "Xiaoyun Wang et al., 2011", "Anderson, Biham, 1995", "Version 3.0; Rijmen, Barreto, 2000" };

	static const char*	encoding[] = { "ascii", "base16", "base32", "base64" };
	static const char*	encoding_info[] = { "notepad++ is not built for binary data", "standard hex-encoding", "DUDE base32 encoding", "RFC-4648 compatible base64 encoding" };
	static const char*	encoding_info_url[] = { "ASCII", "Hexadecimal", "Base32", "Base64" };

	static const char*	key_algo[] = { "pbkdf2", "bcrypt", "scrypt" };
	static const char*	key_algo_info[] = { "HMAC is used as pseudo-random function", "compulsory 16 byte salt, SHA-3 shake128 will be used to get required key-length from fixed 23 byte output", "N - CPU/memory cost, r - blocksize, p - parallelization" };
	static const char*	key_algo_info_url[] = { "PBKDF2", "Bcrypt", "Scrypt" };

	static const char*	random_restriction[] = { "digits", "letters", "alphanum", "password" , "specials" };

	static const char*	eol[] = { "windows", "unix" };

	static const char*  boolean[] = { "true", "false" };

	static char			help_url_wikipedia[100] = "https://en.wikipedia.org/wiki/";
	static const int	help_url_wikipedia_len = 30;
};

int searchStringArray(const char* s, const char** a, size_t a_length)
{
	if (!s || !a || !a_length) {
		return -1;
	}
	size_t s_length = std::strlen(s);
	for (size_t i = 0; i < a_length; i++) {
		if (s_length != std::strlen(a[i])) {
			continue;
		}
		size_t x = 0;
		for (x = 0; x < s_length; x++) {
			if (s[x] != a[i][x]) {
				break;
			}
		}
		if (x == s_length) {
			return (int)i;
		}
	}
	return -1;
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

const char* crypt::help::getString(UserData::Restriction r)
{
	return Strings::random_restriction[static_cast<int>(r)];
}

const char* crypt::help::getString(crypt::EOL eol)
{
	return Strings::eol[static_cast<int>(eol)];
}

const char* crypt::help::getString(bool v)
{
	return Strings::boolean[v ? 0 : 1];
}

bool crypt::help::getCipher(const char* s, crypt::Cipher& c)
{
	int index = searchStringArray(s, Strings::cipher, (size_t)Cipher::COUNT);
	if (index >= 0) {
		c = (Cipher)index;
		return true;
	} else {
		return false;
	}
}

bool crypt::help::getCipherMode(const char* s, crypt::Mode& m)
{
	int index = searchStringArray(s, Strings::mode, (size_t)Mode::COUNT);
	if (index >= 0) {
		m = (Mode)index;
		return true;
	} else {
		return false;
	}
}

bool crypt::help::getKeyDerivation(const char*s, KeyDerivation& v)
{
	int index = searchStringArray(s, Strings::key_algo, (size_t)KeyDerivation::COUNT);
	if (index >= 0) {
		v = (KeyDerivation)index;
		return true;
	} else {
		return false;
	}
}

bool crypt::help::getIVMode(const char* s, crypt::IV& iv)
{
	int index = searchStringArray(s, Strings::iv, (size_t)IV::COUNT);
	if (index >= 0) {
		iv = (IV)index;
		return true;
	} else {
		return false;
	}
}

bool crypt::help::getEncoding(const char* s, crypt::Encoding& e)
{
	int index = searchStringArray(s, Strings::encoding, (size_t)Encoding::COUNT);
	if (index >= 0) {
		e = (Encoding)index;
		return true;
	} else {
		return false;
	}
}

bool crypt::help::getRandomRestriction(const char* s, UserData::Restriction& r)
{
	int index = searchStringArray(s, Strings::random_restriction, (size_t)UserData::Restriction::COUNT);
	if (index >= 0) {
		r = (UserData::Restriction)index;
		return true;
	} else {
		return false;
	}
}

bool crypt::help::getEOL(const char* s, crypt::EOL& eol)
{
	int index = searchStringArray(s, Strings::eol, (size_t)EOL::COUNT);
	if (index >= 0) {
		eol = (EOL)index;
		return true;
	} else {
		return false;
	}
}

bool crypt::help::getHash(const char* s, Hash& h)
{
	int index = searchStringArray(s, Strings::hash, (size_t)Hash::COUNT);
	if (index >= 0) {
		h = (Hash)index;
		return true;
	} else {
		return false;
	}
}

bool crypt::help::getUnsigned(const char* s, size_t& i)
{
	if (s) {
		i = (size_t)std::atoi(s);
		return true;
	}
	return false;
}

bool crypt::help::getInteger(const char* s, int& i, bool log2)
{
	if (s) {
		if (log2) {
			int temp_int = std::atoi(s);
			if ((temp_int != 0) && !(temp_int & (temp_int - 1))) {
				i = static_cast<int>(std::log(temp_int) / std::log(2));
				return true;
			}
		} else {
			i = std::atoi(s);
			return true;
		}		
	}
	return false;
}

bool crypt::help::getBoolean(const char* s, bool& b)
{
	if (s) {
		size_t len = strlen(s);
		if (len == 4 && s[0] == 't' && s[1] == 'r' && s[2] == 'u' && s[3] == 'e') {
			b = true;
			return true;
		} else if(len == 5 && s[0] == 'f' && s[1] == 'a' && s[2] == 'l' && s[3] == 's' && s[4] == 'e') {
			b = false;
			return true;
		}
	}
	return false;
}

void crypt::help::validate(Options::Crypt options, bool exceptions)
{
	// ---------- cipher mode
	if (!checkProperty(options.cipher, STREAM) && !checkCipherMode(options.cipher, options.mode)) {
		if (exceptions) {
			throw CExc(CExc::Code::invalid_mode);
		} else {
			if (checkCipherMode(options.cipher, Mode::gcm)) {
				options.mode = Mode::gcm;
			} else {
				options.mode = Mode::cbc;
			}
		}
	}
	// ---------- key-length
	if (options.key.length > 0 && !checkCipherKeylength(options.cipher, options.key.length)) {
		if (exceptions) {
			throw CExc(CExc::Code::invalid_keylength);
		} else {
			options.key.length = 0; // default key-length will be chosen
		}
	}
	// ---------- keyderivation method
	switch (options.key.algorithm) {
	case KeyDerivation::pbkdf2:
	{
		if (options.key.options[0] < 0 || options.key.options[0] >= (int)crypt::Hash::COUNT || !checkProperty((crypt::Hash)options.key.options[0], HMAC_SUPPORT)) {
			if (exceptions) {
				throw CExc(CExc::Code::invalid_pbkdf2_hash);
			}
			options.key.options[0] = (int)Constants::pbkdf2_default_hash;
			options.key.options[1] = Constants::pbkdf2_default_hash_digest;
		}
		if (options.key.options[1] != 0 && !crypt::help::checkHashDigest((Hash)options.key.options[0], (unsigned int)options.key.options[1])) {
			options.key.options[1] = 0;
			if (exceptions) {
				throw CExc(CExc::Code::invalid_pbkdf2_hash);
			}
		}
		if (options.key.options[2] < crypt::Constants::pbkdf2_iter_min || options.key.options[2] > crypt::Constants::pbkdf2_iter_max) {
			options.key.options[2] = crypt::Constants::pbkdf2_iter_default;
			if (exceptions) {
				throw CExc(CExc::Code::invalid_pbkdf2);
			}
		}
		break;
	}
	case KeyDerivation::bcrypt:
	{
		if (options.key.options[0] < crypt::Constants::bcrypt_iter_min || options.key.options[0] > crypt::Constants::bcrypt_iter_max) {
			if (exceptions) {
				throw CExc(CExc::Code::invalid_bcrypt);
			} else {
				options.key.options[0] = crypt::Constants::bcrypt_iter_default;
			}
		}
		break;
	}
	case KeyDerivation::scrypt:
	{
		if (options.key.options[0] < crypt::Constants::scrypt_N_min || options.key.options[0] > crypt::Constants::scrypt_N_max) {
			if (exceptions) {
				throw CExc(CExc::Code::invalid_scrypt);
			} else {
				options.key.options[0] = crypt::Constants::scrypt_N_default;
			}
		}
		if (options.key.options[1] < crypt::Constants::scrypt_r_min || options.key.options[1] > crypt::Constants::scrypt_r_max) {
			if (exceptions) {
				throw CExc(CExc::Code::invalid_scrypt);
			} else {
				options.key.options[1] = crypt::Constants::scrypt_r_default;
			}
		}
		if (options.key.options[2] < crypt::Constants::scrypt_p_min || options.key.options[2] > crypt::Constants::scrypt_p_max) {
			if (exceptions) {
				throw CExc(CExc::Code::invalid_scrypt);
			} else {
				options.key.options[2] = crypt::Constants::scrypt_p_default;
			}
		}
		break;
	}
	}
	// ---------- salt
	if (options.key.salt_bytes > Constants::salt_max) {
		if (exceptions) {
			throw CExc(CExc::Code::invalid_salt);
		} else {
			options.key.salt_bytes = 16;
		}
	}
	if (options.key.algorithm == KeyDerivation::bcrypt && options.key.salt_bytes != 16) {
		if (exceptions) {
			throw CExc(CExc::Code::invalid_bcrypt_saltlength);
		} else {
			options.key.salt_bytes = 16;
		}
	}
	// ----------- encoding: line-length
	if (options.encoding.linelength > NPPC_MAX_LINE_LENGTH) {
		if (exceptions) {
			throw CExc(CExc::Code::invalid_linelength);
		} else {
			options.encoding.linelength = NPPC_MAX_LINE_LENGTH;
		}
	}
}

void crypt::help::validate(Options::Hash options, bool exceptions)
{
	if (!help::checkHashDigest(options.algorithm, (unsigned int)options.digest_length)) {
		if (exceptions) {
			throw CExc(CExc::Code::invalid_hash_digestlen);
		} else {
			options.digest_length = 0;
		}
	}
	if (options.use_key) {
		if (!help::checkProperty(options.algorithm, crypt::HMAC_SUPPORT) && !help::checkProperty(options.algorithm, crypt::KEY_SUPPORT)) {
			if (exceptions) {
				throw CExc(CExc::Code::hash_without_keysupport);
			} else {
				options.algorithm = Hash::sha3;
			}
		}
	} else if (help::checkProperty(options.algorithm, crypt::KEY_REQUIRED)) {
		if (exceptions) {
			throw CExc(CExc::Code::hash_requires_key);
		} else {
			options.algorithm = Hash::sha3;
		}
	}
}

void crypt::help::validate(Options::Convert options, bool exceptions)
{
	if (options.from == options.to) {
		if (exceptions) {
			throw CExc(CExc::Code::hash_requires_key);
		} else {
			if (options.to == Encoding::ascii) {
				options.to = Encoding::base16;
			} else if (options.to == Encoding::base16) {
				options.to = Encoding::base32;
			} else if (options.to == Encoding::base32) {
				options.to = Encoding::base64;
			} else {
				options.to = Encoding::ascii;
			}
		}
	}
	// ----------- line-length
	if (options.linelength > NPPC_MAX_LINE_LENGTH) {
		if (exceptions) {
			throw CExc(CExc::Code::invalid_linelength);
		} else {
			options.linelength = NPPC_MAX_LINE_LENGTH;
		}
	}
}

crypt::Mode crypt::help::getModeByIndex(crypt::Cipher cipher, int index)
{
	if (index >= 0 && index < int(Mode::eax)) {
		return Mode(index);
	} else if (index == int(Mode::eax)) {
		if ((cipher_properties[int(cipher)] & EAX) == EAX) {
			return Mode::eax;
		}
	} else if (index == int(Mode::ccm)) {
		if ((cipher_properties[int(cipher)] & CCM) == CCM) {
			return Mode::ccm;
		}
	} else if (index == int(Mode::gcm)) {
		if ((cipher_properties[int(cipher)] & GCM) == GCM) {
			return Mode::gcm;
		}
	}
	return Mode::cbc;
}

int crypt::help::getModeIndex(crypt::Cipher cipher, crypt::Mode mode)
{
	if (mode == Mode::eax) {
		if ((cipher_properties[int(cipher)] & EAX) == EAX) {
			return int(Mode::eax);
		}
	} else if (mode == Mode::ccm) {
		if ((cipher_properties[int(cipher)] & CCM) == CCM) {
			return int(Mode::ccm);
		}
	} else if (mode == Mode::gcm) {
		if ((cipher_properties[int(cipher)] & GCM) == GCM) {
			return int(Mode::gcm);
		}
	} else {
		return int(mode);
	}
	return -1;
}

int crypt::help::getCipherCategory(Cipher cipher)
{
	for (int i = CIPHER_CAT_COUNT - 1; i >= 0; i--) {
		if ((int)cipher >= cipher_categories[i][0]) {
			return i;
		}
	}
	return -1;
}

crypt::Cipher crypt::help::getCipherByIndex(size_t category, size_t index)
{
	if (category >= CIPHER_CAT_COUNT || cipher_categories[category][0] + index >= (size_t)crypt::Cipher::COUNT) {
		return Cipher::rijndael;
	} else {
		return (Cipher)(cipher_categories[category][0] + index);
	}
}

int crypt::help::getCipherIndex(Cipher cipher)
{
	for (int i = 0; i < CIPHER_CAT_COUNT; i++) {
		if ((int)cipher <= cipher_categories[i][1]) {
			return (int)cipher - cipher_categories[i][0];
		}
	}
	return -1;
}

size_t crypt::help::getCipherKeylengthByIndex(Cipher cipher, size_t index)
{
	return cipher_keys[(int)cipher][0] + index * cipher_keys[(int)cipher][1];
}

Hash crypt::help::getHashByIndex(size_t index, int filter)
{
	size_t h = 0;
	for (int i = 0; i < (int)Hash::COUNT; i++) {
		if (((filter & WEAK) == WEAK && (hash_properties[i] & WEAK) != WEAK) ||
			((filter & HMAC_SUPPORT) == HMAC_SUPPORT && (hash_properties[i] & HMAC_SUPPORT) != HMAC_SUPPORT) ||
			((filter & KEY_REQUIRED) == KEY_REQUIRED && (hash_properties[i] & KEY_REQUIRED) != KEY_REQUIRED) ||
			((filter & KEY_SUPPORT) == KEY_SUPPORT && (hash_properties[i] & KEY_SUPPORT) != KEY_SUPPORT)) {
			continue;
		}
		if (index == h) {
			return (Hash)i;
		}
		h++;
	}
	return Hash::sha3;
}

int crypt::help::getHashIndex(Hash h, int filter)
{
	int ret = 0;
	for (int i = 0; i < (int)Hash::COUNT; i++) {
		if (((filter & WEAK) == WEAK && (hash_properties[i] & WEAK) != WEAK) ||
			((filter & HMAC_SUPPORT) == HMAC_SUPPORT && (hash_properties[i] & HMAC_SUPPORT) != HMAC_SUPPORT) ||
			((filter & KEY_REQUIRED) == KEY_REQUIRED && (hash_properties[i] & KEY_REQUIRED) != KEY_REQUIRED) ||
			((filter & KEY_SUPPORT) == KEY_SUPPORT && (hash_properties[i] & KEY_SUPPORT) != KEY_SUPPORT)) {
			continue;
		}
		if ((Hash)i == h) {
			return ret;
		}
		ret++;
	}
	return -1;
}

size_t crypt::help::getHashDigestByIndex(Hash h, unsigned int index)
{
	unsigned int ind = 0;
	unsigned int i = 0;
	while (i < 16) {
		unsigned int x = ipow<unsigned int>(2, i);
		if ((hash_digests[(int)h] & x) == x) {
			if (ind == index) {
				return (i + 1) * 4;
			}
			ind++;
		}
		i++;
	}
	return 0;
}

int crypt::help::getHashDigestIndex(Hash h, unsigned int digest)
{
	unsigned int ind = 0;
	unsigned int i = 0;
	while (i < 16) {
		unsigned int x = ipow<unsigned int>(2, i);
		if ((hash_digests[(int)h] & x) == x) {
			if ((i + 1) * 4 == digest) {
				return ind;
			}
			ind++;
		}
		i++;
	}
	return 0;
}

bool crypt::help::checkCipherMode(crypt::Cipher cipher, crypt::Mode mode)
{
	if (mode == Mode::eax) {
		if ((cipher_properties[int(cipher)] & EAX) == EAX) {
			return true;
		}
	} else if (mode == Mode::ccm) {
		if ((cipher_properties[int(cipher)] & CCM) == CCM) {
			return true;
		}
	} else if (mode == Mode::gcm) {
		if ((cipher_properties[int(cipher)] & GCM) == GCM) {
			return true;
		}
	} else {
		return true;
	}
	return false;
}

bool crypt::help::checkProperty(crypt::Cipher cipher, int filter)
{
	if ((unsigned)cipher >= (unsigned)Cipher::COUNT) {
		return false;
	}
	return ((cipher_properties[(unsigned)cipher] & filter) == filter);
}

bool crypt::help::checkProperty(crypt::Hash h, int filter)
{
	if ((unsigned)h >= (unsigned)Hash::COUNT) {
		return false;
	}
	return ((hash_properties[(unsigned)h] & filter) == filter);
}

bool crypt::help::checkHashDigest(Hash h, unsigned int digest)
{
	if (digest < 4 || digest > 128) {
		return false;
	}
	unsigned int x = ipow<unsigned int>(2, ((digest / 4) - 1));
	return ((hash_digests[(unsigned)h] & x) == x);
}

bool crypt::help::checkCipherKeylength(Cipher cipher, size_t keylength)
{
	for (size_t i = 0; i < cipher_keys[(int)cipher][2]; i++) {
		if (keylength == cipher_keys[(int)cipher][0] + cipher_keys[(int)cipher][1] * i) {
			return true;
		}
	}
	return false;
}

const char* crypt::help::getHelpURL(crypt::Encoding enc)
{
	strcpy(Strings::help_url_wikipedia + Strings::help_url_wikipedia_len, Strings::encoding_info_url[unsigned(enc)]);
	return Strings::help_url_wikipedia;
}

const char*	crypt::help::getHelpURL(crypt::Cipher cipher)
{
	strcpy(Strings::help_url_wikipedia + Strings::help_url_wikipedia_len, Strings::cipher_info_url[unsigned(cipher)]);
	return Strings::help_url_wikipedia;
}

const char*	crypt::help::getHelpURL(crypt::Hash h)
{
	strcpy(Strings::help_url_wikipedia + Strings::help_url_wikipedia_len, Strings::hash_info_url[unsigned(h)]);
	return Strings::help_url_wikipedia;
}

const char*	crypt::help::getHelpURL(crypt::KeyDerivation k)
{
	strcpy(Strings::help_url_wikipedia + Strings::help_url_wikipedia_len, Strings::key_algo_info_url[unsigned(k)]);
	return Strings::help_url_wikipedia;
}

const char*	crypt::help::getHelpURL(crypt::Mode m)
{
	strcpy(Strings::help_url_wikipedia + Strings::help_url_wikipedia_len, Strings::mode_info_url[unsigned(m)]);
	return Strings::help_url_wikipedia;
}

const char*	crypt::help::getInfo(crypt::Cipher c)
{
	return Strings::cipher_info[unsigned(c)];
}

const char*	crypt::help::getInfo(crypt::Mode m)
{
	return Strings::mode_info[unsigned(m)];
}

const char*	crypt::help::getInfo(crypt::Hash h)
{
	return Strings::hash_info[unsigned(h)];
}

const char*	crypt::help::getInfo(crypt::IV iv)
{
	return Strings::iv_help[unsigned(iv)];
}

const char*	crypt::help::getInfo(crypt::KeyDerivation k)
{
	return Strings::key_algo_info[unsigned(k)];
}

const char*	crypt::help::getInfo(crypt::Encoding e)
{
	return Strings::encoding_info[unsigned(e)];
}

crypt::help::CipherCategories::CipherCategories() : i(0)
{
}

const char* crypt::help::CipherCategories::operator*() const
{
	if (i >= 0) {
		return Strings::cipher_categories[i];
	} else {
		return NULL;
	}
}

crypt::help::CipherCategories& crypt::help::CipherCategories::operator++()
{
	if (i != -1) {
		++i;
		if (i >= CIPHER_CAT_COUNT) {
			i = -1;
		}
	}
	return *this;
}

crypt::help::CipherNames::CipherNames(int category) : c(category), i(0)
{
	if (c < 0 || c >= CIPHER_CAT_COUNT) {
		i = -1;
	} else {
		i = cipher_categories[c][0];
	}
}

const char* crypt::help::CipherNames::operator*() const
{
	if (i >= 0) {
		return Strings::cipher_label[i];
	} else {
		return NULL;
	}
}

crypt::help::CipherNames& crypt::help::CipherNames::operator++()
{
	if (i != -1) {
		++i;
		if (i > cipher_categories[c][1]) {
			i = -1;
		}
	}
	return *this;
}

crypt::help::CipherModes::CipherModes(crypt::Cipher c) : cipher_index((size_t)c), i(0)
{
	if ((cipher_properties[cipher_index] & STREAM) == STREAM) {
		i = -1;
	}
}

const char* crypt::help::CipherModes::operator*() const
{
	if (i >= 0) {
		return Strings::mode[i];
	} else {
		return NULL;
	}
}

crypt::help::CipherModes& crypt::help::CipherModes::operator++()
{
	if (i != -1) {
		++i;
		while (i < (int)Mode::COUNT) {
			if (((int)Mode::eax == i && (cipher_properties[cipher_index] & EAX) != EAX)
				|| ((int)Mode::ccm == i && (cipher_properties[cipher_index] & CCM) != CCM)
				|| ((int)Mode::gcm == i && (cipher_properties[cipher_index] & GCM) != GCM)) {
				++i;
			} else {
				break;
			}
		}
		if (i >= (int)Mode::COUNT) {
			i = -1;
		}
	}
	return *this;
}

crypt::help::CipherKeys::CipherKeys(crypt::Cipher c) : cipher_index((size_t)c), i(0)
{
}

int crypt::help::CipherKeys::operator*() const
{
	if (i >= 0) {
		return cipher_keys[cipher_index][0] + i * cipher_keys[cipher_index][1];
	} else {
		return 0;
	}
}

crypt::help::CipherKeys& crypt::help::CipherKeys::operator++()
{
	++i;
	if (i >= (int)cipher_keys[cipher_index][2]) {
		i = -1;
	}
	return *this;
}

crypt::help::Hashnames::Hashnames(int filter) : f(filter), i(0)
{
	checkfilter();
}

const char* crypt::help::Hashnames::operator*() const
{
	if (i >= 0) {
		return Strings::hash_label[i];
	} else {
		return NULL;
	}
}

crypt::help::Hashnames& crypt::help::Hashnames::operator++()
{
	if (i != -1) {
		++i;
		checkfilter();
	}
	return *this;
}

void crypt::help::Hashnames::checkfilter()
{
	while (i < (int)Hash::COUNT) {
		if (((f & WEAK) == WEAK && (hash_properties[i] & WEAK) != WEAK) ||
			((f & HMAC_SUPPORT) == HMAC_SUPPORT && (hash_properties[i] & HMAC_SUPPORT) != HMAC_SUPPORT) ||
			((f & KEY_REQUIRED) == KEY_REQUIRED && (hash_properties[i] & KEY_REQUIRED) != KEY_REQUIRED) ||
			((f & KEY_SUPPORT) == KEY_SUPPORT && (hash_properties[i] & KEY_SUPPORT) != KEY_SUPPORT)) {
			++i;
		} else {
			break;
		}
	}
	if (i >= (int)Hash::COUNT) {
		i = -1;
	}
}

crypt::help::HashDigests::HashDigests(crypt::Hash h) : hash_index((size_t)h), i(0)
{
	getLength();
}

int crypt::help::HashDigests::operator*() const
{
	if (i >= 0) {
		return cur_length;
	} else {
		return 0;
	}
}

crypt::help::HashDigests& crypt::help::HashDigests::operator++()
{
	++i;
	getLength();
	return *this;
}

void crypt::help::HashDigests::getLength()
{
	while (i < 16) {
		unsigned int x = ipow<unsigned int>(2, i);
		if ((hash_digests[hash_index] & x) == x) {
			cur_length = (i + 1) * 4;
			return;
		}
		i++;
	}
	i = -1;
}