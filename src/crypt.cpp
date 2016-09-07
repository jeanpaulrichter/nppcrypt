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
#include "help.h"
#include "bcrypt/crypt_blowfish.h"
#include "keccak/KeccakHash.h"
#include "scrypt/crypto_scrypt.h"

#ifdef max
#undef max
#endif

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <cryptopp/md5.h>
#include <cryptopp/md4.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/hex.h>
#include <cryptopp/base32.h>
#include <cryptopp/base64.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/whrlpool.h>
#include <cryptopp/tiger.h>
#include <cryptopp/hmac.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/ccm.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/osrng.h>
#include <cryptopp/des.h>
#include <cryptopp/gost.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/rc2.h>
#include <cryptopp/rc5.h>
#include <cryptopp/rc6.h>
#include <cryptopp/idea.h>
#include <cryptopp/cast.h>
#include <cryptopp/camellia.h>
#include <cryptopp/seed.h>
#include <cryptopp/tea.h>
#include <cryptopp/skipjack.h>
#include <cryptopp/shacal2.h>
#include <cryptopp/mars.h>
#include <cryptopp/twofish.h>
#include <cryptopp/serpent.h>
#include <cryptopp/sosemanuk.h>
#include <cryptopp/arc4.h>
#include <cryptopp/salsa.h>
#include <cryptopp/panama.h>
#include <cryptopp/eax.h>

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

// ---------------------------- SUPPORTED CIPHER MODES -------------------------------------------------------------------------------------------------------------------------------------------
enum { C_AES=1, C_OTHER=2, C_STREAM=4, C_WEAK=8, MODE_EAX=16, MODE_CCM=32, MODE_GCM=64, BLOCK=128, STREAM=256 };
static const unsigned int cipher_flags[unsigned(crypt::Cipher::COUNT)] = 
{	
/* des			*/	BLOCK | C_WEAK,
/* des_ede		*/	BLOCK | C_OTHER,
/* des_ede3		*/	BLOCK | C_OTHER,
/* desx			*/	BLOCK | C_WEAK,
/* gost			*/	BLOCK | C_WEAK,
/* cast128		*/	BLOCK | C_WEAK,
/* cast256		*/	BLOCK | C_AES | MODE_EAX | MODE_CCM | MODE_GCM,
/* rc2			*/	BLOCK | C_WEAK,
/* rc4			*/	STREAM | C_WEAK | MODE_EAX | MODE_CCM | MODE_GCM,
/* rc5			*/	BLOCK | C_OTHER,
/* rc6			*/	BLOCK | C_AES | MODE_EAX | MODE_CCM | MODE_GCM,
/* idea			*/	BLOCK | C_OTHER,
/* blowfish		*/	BLOCK | C_OTHER,
/* camellia		*/	BLOCK | C_OTHER | MODE_EAX | MODE_CCM | MODE_GCM,
/* seed			*/	BLOCK | C_OTHER | MODE_EAX | MODE_CCM | MODE_GCM,
/* tea			*/	BLOCK | C_OTHER,
/* xtea			*/	BLOCK | C_OTHER,
/* shacal2		*/	BLOCK | C_OTHER | MODE_EAX,
/* mars			*/	BLOCK | C_AES | MODE_EAX | MODE_CCM | MODE_GCM,
/* twofish		*/	BLOCK | C_AES | MODE_EAX | MODE_CCM | MODE_GCM,
/* serpent		*/	BLOCK | C_AES | MODE_EAX | MODE_CCM | MODE_GCM,
/* rijndael128	*/	BLOCK | C_AES | MODE_EAX | MODE_CCM | MODE_GCM,
/* rijndael192	*/	BLOCK | C_AES | MODE_EAX | MODE_CCM | MODE_GCM,
/* rijndael256	*/	BLOCK | C_AES | MODE_EAX | MODE_CCM | MODE_GCM,
/* sosemanuk	*/	STREAM | C_STREAM,
/* salsa20		*/	STREAM | C_STREAM,
/* xsalsa20		*/	STREAM | C_STREAM,
/* panama		*/	STREAM | C_STREAM,
};

// ----------------------------- STRINGS ---------------------------------------------------------------------------------------------------------------------------------------------------------

static const TCHAR* cipher_str[] = { TEXT("des"), TEXT("des_ede"), TEXT("des_ede3"), TEXT("desx"), TEXT("gost"), TEXT("cast-128"), TEXT("cast-256"), TEXT("RC2"), TEXT("RC4"), TEXT("RC5"), TEXT("RC6"), TEXT("IDEA"), TEXT("Blowfish"), TEXT("Camellia"), TEXT("SEED"), TEXT("TEA"), TEXT("XTEA"), TEXT("SHACAL-2"), TEXT("MARS"), TEXT("Twofish"), TEXT("Serpent"), TEXT("Rijndael-128"), TEXT("Rijndael-192"), TEXT("Rijndael-256"), TEXT("Sosemanuk"), TEXT("Salsa20"), TEXT("XSalsa20"), TEXT("Panama") };
static const char*	cipher_str_c[] = { "des", "des_ede", "des_ede3", "desx", "gost", "cast128", "cast256", "rc2", "rc4", "rc5", "rc6", "idea", "blowfish", "camellia", "seed", "tea", "xtea", "shacal-2", "mars", "twofish", "serpent", "rijndael128", "rijndael192", "rijndael256", "sosemanuk", "salsa20", "xsalsa20", "panama" };
static const TCHAR* cipher_help_url[] = { TEXT("Data_Encryption_Standard"), TEXT("Data_Encryption_Standard"), TEXT("Data_Encryption_Standard"), TEXT("DES-X"), TEXT("GOST_(block_cipher)"), TEXT("CAST-128"), TEXT("CAST-256"), TEXT("RC2"), TEXT("RC4"), TEXT("RC5"), TEXT("RC6"), TEXT("International_Data_Encryption_Algorithm"), TEXT("Blowfish_(cipher)"), TEXT("Camellia_(cipher)"), TEXT("SEED"), TEXT("Tiny_Encryption_Algorithm"), TEXT("XTEA"), TEXT("SHACAL"), TEXT("MARS_(cryptography)"), TEXT("Twofish"), TEXT("Serpent_(cipher)"), TEXT("Advanced_Encryption_Standard"), TEXT("Advanced_Encryption_Standard"), TEXT("Advanced_Encryption_Standard"), TEXT("SOSEMANUK"), TEXT("Salsa20"), TEXT("Salsa20"), TEXT("Panama_(cryptography)") };

static const TCHAR* mode_str[] = { TEXT("ecb"), TEXT("cbc"), TEXT("cbc_cts"), TEXT("cfb"), TEXT("ofb"), TEXT("ctr"), TEXT("eax"), TEXT("ccm"), TEXT("gcm") };
static const char*	mode_str_c[] = { "ecb", "cbc", "cbc_cts", "cfb", "ofb", "ctr", "eax", "ccm", "gcm" };
static const TCHAR* mode_help_url[] = { TEXT("Block_cipher_mode_of_operation"), TEXT("Block_cipher_mode_of_operation"), TEXT("Block_cipher_mode_of_operation"), TEXT("Block_cipher_mode_of_operation"), TEXT("Block_cipher_mode_of_operation"), TEXT("Block_cipher_mode_of_operation"), TEXT("EAX_mode"), TEXT("CCM_mode"), TEXT("Galois/Counter_Mode") };

static const char*	iv_str_c[] = { "random", "keyderivation", "zero" };

static const TCHAR* hash_str[] = { TEXT("md4"), TEXT("md5"), TEXT("sha1"), TEXT("sha256"), TEXT("sha512"), TEXT("ripemd128"), TEXT("ripemd160"), TEXT("ripemd256"), TEXT("whirlpool"), TEXT("tiger"), TEXT("sha3_224"), TEXT("sha3_256"), TEXT("sha3_384"), TEXT("sha3_512") };
static const char*	hash_str_c[] = { "md4", "md5", "sha1", "sha256", "sha512", "ripemd128", "ripemd160", "ripemd256", "whirlpool", "tiger", "sha3_224", "sha3_256", "sha3_384", "sha3_512" };
static const TCHAR* hash_help_url[] = { TEXT("MD4"),TEXT("MD5"), TEXT("SHA-1"), TEXT("SHA-2"), TEXT("SHA-2"), TEXT("RIPEMD"), TEXT("RIPEMD"), TEXT("RIPEMD"), TEXT("Whirlpool_(cryptography)"), TEXT("Tiger_(cryptography)"), TEXT("SHA-3"), TEXT("SHA-3"), TEXT("SHA-3"), TEXT("SHA-3") };

static const char*	encoding_str_c[] = { "ascii", "base16", "base32", "base64" };
static const TCHAR* encoding_help_url[] = { TEXT("ASCII"), TEXT("Hexadecimal"), TEXT("Base32"), TEXT("Base64") };

static const char*	key_algo_str_c[] = { "pbkdf2", "bcrypt", "scrypt" };
static const TCHAR* key_algo_help_url[] = { TEXT("PBKDF2"), TEXT("Bcrypt"), TEXT("Scrypt") };

static const char*	random_mode_str_c[] = { "charnum", "specials", "ascii", "base16" , "base64" };

static TCHAR		help_url_wikipedia[100] = TEXT("https://en.wikipedia.org/wiki/");
static const int	help_url_wikipedia_len = 30;

static std::string	s_eol_windows = "\r\n";
static std::string	s_eol_unix = "\n";

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
	case crypt::Cipher::panama:
		block_size = 0;
		key_length = PanamaCipher<LittleEndian>::DEFAULT_KEYLENGTH;
		iv_length = PanamaCipher<LittleEndian>::IV_LENGTH;
		break;
	default: return false;
	}
	return true;
}

void crypt::encrypt(const unsigned char* in, size_t in_len, std::basic_string<byte>& buffer, const Options::Crypt& options, InitStrings& init)
{
	if (!in || !in_len) {
		throw CExc(CExc::File::crypt, __LINE__);
	}
	if (!options.password.size()) {
		throw CExc(CExc::File::crypt, __LINE__);
	}

	using namespace CryptoPP;

	std::vector<byte>	tKey;
	std::vector<byte>	tVec;
	std::vector<byte>	tSalt;
	const byte*			ptVec = NULL;
	const byte*			ptSalt = NULL;
	int					key_len, iv_len;
	int					block_size;

	getCipherInfo(options.cipher, options.mode, key_len, iv_len, block_size);

	// --------------------------- prepare salt vector:
	if (options.key.salt_bytes > 0)	{
		if (options.key.algorithm == crypt::KeyDerivation::bcrypt && options.key.salt_bytes != 16) {
			throw CExc(CExc::Code::bcrypt_salt);
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
			tVec.resize(iv_len);
			memset(&tVec[0], 0, tVec.size());
			ptVec = &tVec[0];
		}
	}
	// --------------------------- key derivation:
	switch (options.key.algorithm)
	{
	case crypt::KeyDerivation::pbkdf2:
	{
		std::unique_ptr<PasswordBasedKeyDerivationFunction> pbkdf2;
		switch (crypt::Hash(options.key.option1))
		{
		case crypt::Hash::md4:
			pbkdf2.reset( new PKCS5_PBKDF2_HMAC< Weak::MD4 > ); break;
		case crypt::Hash::md5:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< Weak::MD5 >); break;
		case crypt::Hash::sha1:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA1 >); break;
		case crypt::Hash::sha256:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA256 >); break;
		case crypt::Hash::sha512:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA512 >); break;
		case crypt::Hash::ripemd128:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< RIPEMD128 >); break;
		case crypt::Hash::ripemd160:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< RIPEMD160 >); break;
		case crypt::Hash::ripemd256:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< RIPEMD256 >); break;
		case crypt::Hash::whirlpool:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< Whirlpool >); break;
		case crypt::Hash::tiger:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< Tiger >); break;
		default: throw CExc(CExc::File::crypt, __LINE__);
		}
		pbkdf2->DeriveKey(&tKey[0], tKey.size(), 0, (const byte*)options.password.c_str(), options.password.size(), ptSalt, options.key.salt_bytes, options.key.option2);
		break;
	}
	case crypt::KeyDerivation::bcrypt:
	{
		char output[64];
		char settings[32];

		if (_crypt_gensalt_blowfish_rn("$2a$", (unsigned long)options.key.option1, (const char*)ptSalt, 16, settings, 32) == NULL) {
			throw CExc(CExc::File::crypt, __LINE__);
		}
		memset(output, 0, sizeof(output));
		if (_crypt_blowfish_rn(options.password.c_str(), settings, output, 64) == NULL) {
			throw CExc(CExc::File::crypt, __LINE__);
		}

		shake128((unsigned char*)output, 24, &tKey[0], tKey.size());
		break;
	}
	case crypt::KeyDerivation::scrypt:
	{
		if (crypto_scrypt((unsigned char*)options.password.c_str(), options.password.size(), ptSalt, options.key.salt_bytes, ipow(2, options.key.option1), options.key.option2, options.key.option3, &tKey[0], tKey.size()) != 0) {
			throw CExc(CExc::File::crypt, __LINE__);
		}
		break;
	}
	}
	// --------------------------- return encoded IV and Salt
	init.encoding = Encoding::base64;
	if (options.iv == crypt::IV::random && tVec.size() > 0) {
		StringSource ss(&tVec[0], tVec.size(), true, new Base64Encoder(new StringSink(init.iv), false));
	}
	if (options.key.salt_bytes > 0)	{
		StringSource ss(&tSalt[0], tSalt.size(), true, new Base64Encoder(new StringSink(init.salt), false));
	}

	try	{
		if ((cipher_flags[int(options.cipher)] & STREAM) == STREAM)	{
			std::unique_ptr<SymmetricCipherDocumentation::Encryption> pEnc;
			switch (options.cipher) {
			case Cipher::sosemanuk: pEnc.reset(new Sosemanuk::Encryption(tKey.data(), key_len, ptVec)); break;
			case Cipher::rc4: pEnc.reset(new Weak::ARC4::Encryption(tKey.data(), key_len)); break;
			case Cipher::salsa20: pEnc.reset(new Salsa20::Encryption(tKey.data(), key_len, ptVec)); break;
			case Cipher::xsalsa20: pEnc.reset(new XSalsa20::Encryption(tKey.data(), key_len, ptVec)); break;
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
				int linelength = options.encoding.linebreaks ? options.encoding.linelength : 0;
				std::string& seperator = options.encoding.windows ? s_eol_windows : s_eol_unix;
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
					new Base64Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.encoding.linebreaks, (options.encoding.windows ? EOL::Windows : EOL::Unix), options.encoding.linelength)
				);
				if (options.encoding.linebreaks) {
					buffer.pop_back();
					if (options.encoding.windows) {
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
					default: throw CExc(CExc::File::crypt, __LINE__);
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

				ef.ChannelPut(AAD_CHANNEL, (const byte*)init.salt.c_str(), init.salt.size());
				ef.ChannelPut(AAD_CHANNEL, (const byte*)init.iv.c_str(), init.iv.size());
				ef.ChannelMessageEnd(AAD_CHANNEL);
				ef.ChannelPut(DEFAULT_CHANNEL, in, in_len);
				ef.ChannelMessageEnd(DEFAULT_CHANNEL);

				switch (options.encoding.enc)
				{
				case Encoding::ascii:
				{
					StringSource(&buffer[0] + buffer.size() - tag_size, tag_size, true, new Base64Encoder(new StringSink(init.tag), false));
					buffer.resize(buffer.size() - tag_size);
					break;
				}
				case Encoding::base16: case Encoding::base32:
				{
					int linelength = options.encoding.linebreaks ? options.encoding.linelength : 0;
					std::string& seperator = options.encoding.windows ? s_eol_windows : s_eol_unix;
					if (options.encoding.enc == Encoding::base16) {
						StringSource(temp.data(), temp.size() - tag_size, true, new HexEncoder(new StringSinkTemplate<std::basic_string<byte>>(buffer),
							options.encoding.uppercase, linelength, seperator));
					} else {
						StringSource(temp.data(), temp.size() - tag_size, true, new Base32Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer),
							options.encoding.uppercase, linelength, seperator));
					}
					StringSource(temp.data() + temp.size() - tag_size, tag_size, true, new Base64Encoder(new StringSink(init.tag), false));
					break;
				}
				case Encoding::base64:
				{
					StringSource(temp.data(), temp.size() - tag_size, true, new Base64Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer),
						options.encoding.linebreaks, (options.encoding.windows ? EOL::Windows : EOL::Unix), options.encoding.linelength));
					if (options.encoding.linebreaks) {
						buffer.pop_back();
						if (options.encoding.windows) {
							buffer.pop_back();
						}
					}
					StringSource(temp.data() + temp.size() - tag_size, tag_size, true, new Base64Encoder(new StringSink(init.tag), false));
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
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<DES>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<DES>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<DES>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<DES>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::des_ede:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<DES_EDE2>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<DES_EDE2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<DES_EDE2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<DES_EDE2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<DES_EDE2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<DES_EDE2>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::des_ede3:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<DES_EDE3>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<DES_EDE3>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<DES_EDE3>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<DES_EDE3>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<DES_EDE3>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<DES_EDE3>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::desx:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<DES_XEX3>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<DES_XEX3>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<DES_XEX3>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<DES_XEX3>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<DES_XEX3>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<DES_XEX3>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::gost:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<GOST>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<GOST>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<GOST>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<GOST>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<GOST>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<GOST>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::cast128:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<CAST128>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<CAST128>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<CAST128>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<CAST128>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<CAST128>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<CAST128>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::cast256:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<CAST256>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<CAST256>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<CAST256>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<CAST256>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<CAST256>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<CAST256>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::rc2:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<RC2>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<RC2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<RC2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<RC2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<RC2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<RC2>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::rc5:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<RC5>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<RC5>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<RC5>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<RC5>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<RC5>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<RC5>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::rc6:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<RC6>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<RC6>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<RC6>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<RC6>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<RC6>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<RC6>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::idea:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<IDEA>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<IDEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<IDEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<IDEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<IDEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<IDEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::blowfish:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<Blowfish>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<Blowfish>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<Blowfish>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<Blowfish>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<Blowfish>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<Blowfish>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::camellia:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<Camellia>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<Camellia>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<Camellia>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<Camellia>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<Camellia>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<Camellia>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::seed:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<SEED>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<SEED>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<SEED>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<SEED>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<SEED>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<SEED>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::tea:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<TEA>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<TEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<TEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<TEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<TEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<TEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::xtea:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<XTEA>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<XTEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<XTEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<XTEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<XTEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<XTEA>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::shacal2:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<SHACAL2>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<SHACAL2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<SHACAL2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<SHACAL2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<SHACAL2>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<SHACAL2>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::mars:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<MARS>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<MARS>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<MARS>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<MARS>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<MARS>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<MARS>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::twofish:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<Twofish>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<Twofish>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<Twofish>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<Twofish>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<Twofish>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<Twofish>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::serpent:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<Serpent>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<Serpent>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<Serpent>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<Serpent>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<Serpent>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<Serpent>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::rijndael128: case Cipher::rijndael256: case Cipher::rijndael192:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<AES>::Encryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<AES>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<AES>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<AES>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<AES>::Encryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<AES>::Encryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				default: throw CExc(CExc::File::crypt, __LINE__);
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
					int linelength = options.encoding.linebreaks ? options.encoding.linelength : 0;
					std::string& seperator = options.encoding.windows ? s_eol_windows : s_eol_unix;
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
							new Base64Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.encoding.linebreaks, (options.encoding.windows ? EOL::Windows : EOL::Unix), options.encoding.linelength)
							));
					if (options.encoding.linebreaks) {
						buffer.pop_back();
						if (options.encoding.windows) {
							buffer.pop_back();
						}
					}
					break;
				}
				}
			}
		}
	} catch (Exception& ) {
		throw CExc(CExc::File::crypt, __LINE__);
	} catch (...) {
		throw CExc(CExc::File::crypt, __LINE__);
	}
}

void crypt::decrypt(const unsigned char* in, size_t in_len, std::basic_string<byte>& buffer, const Options::Crypt& options, const InitStrings& init)
{
	if (!in || !in_len) {
		throw CExc(CExc::File::crypt, __LINE__);
	}
	if (!options.password.size()) {
		throw CExc(CExc::File::crypt, __LINE__);
	}

	using namespace		CryptoPP;

	std::vector<byte>	tKey;
	std::vector<byte>	tVec;
	std::vector<byte>	tSalt;
	const byte*			ptVec = NULL;
	const byte*			ptSalt = NULL;
	int					iv_len, key_len;
	int					block_size;

	getCipherInfo(options.cipher, options.mode, key_len, iv_len, block_size);

	// --------------------------- prepare salt vector:
	if (options.key.salt_bytes > 0)	{
		if (options.key.algorithm == crypt::KeyDerivation::bcrypt && options.key.salt_bytes != 16) {
			throw CExc(CExc::Code::bcrypt_salt);
		}
		if (!init.salt.size()) {
			throw CExc(CExc::Code::decrypt_nosalt);
		}
		tSalt.resize(options.key.salt_bytes);
		StringSource ss(init.salt, true, new Base64Decoder(new ArraySink(&tSalt[0], tSalt.size())));
		if (tSalt.size() != (size_t)options.key.salt_bytes) {
			throw CExc(CExc::Code::decrypt_badsalt);
		}
		ptSalt = &tSalt[0];
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
				throw CExc(CExc::Code::decrypt_noiv);
			}			
			tVec.resize(iv_len);
			StringSource ss(init.iv, true, new Base64Decoder(new ArraySink(&tVec[0], tVec.size())));
			if (tVec.size() != iv_len) {
				throw CExc(CExc::Code::decrypt_badiv);
			}
			ptVec = &tVec[0];
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
	case crypt::KeyDerivation::pbkdf2:
	{
		std::unique_ptr<PasswordBasedKeyDerivationFunction> pbkdf2;
		switch (crypt::Hash(options.key.option1))
		{
		case crypt::Hash::md4:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< Weak::MD4 >); break;
		case crypt::Hash::md5:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< Weak::MD5 >); break;
		case crypt::Hash::sha1:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA1 >); break;
		case crypt::Hash::sha256:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA256 >); break;
		case crypt::Hash::sha512:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< SHA512 >); break;
		case crypt::Hash::ripemd128:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< RIPEMD128 >); break;
		case crypt::Hash::ripemd160:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< RIPEMD160 >); break;
		case crypt::Hash::ripemd256:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< RIPEMD256 >); break;
		case crypt::Hash::whirlpool:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< Whirlpool >); break;
		case crypt::Hash::tiger:
			pbkdf2.reset(new PKCS5_PBKDF2_HMAC< Tiger >); break;
		default: throw CExc(CExc::File::crypt, __LINE__);
		}
		pbkdf2->DeriveKey(tKey.data(), tKey.size(), 0, (const byte*)options.password.c_str(), options.password.size(), ptSalt, options.key.salt_bytes, options.key.option2);
		break;
	}
	case crypt::KeyDerivation::bcrypt:
	{
		char output[64];
		char settings[32];

		if (_crypt_gensalt_blowfish_rn("$2a$", (unsigned long)options.key.option1, (const char*)ptSalt, 16, settings, 32) == NULL) {
			throw CExc(CExc::File::crypt, __LINE__);
		}
		memset(output, 0, sizeof(output));
		if (_crypt_blowfish_rn(options.password.c_str(), settings, output, 64) == NULL) {
			throw CExc(CExc::File::crypt, __LINE__);
		}
		shake128((unsigned char*)output, 24, &tKey[0], tKey.size());
		break;
	}
	case crypt::KeyDerivation::scrypt:
	{
		if (crypto_scrypt((unsigned char*)options.password.c_str(), options.password.size(), ptSalt, options.key.salt_bytes, ipow<uint64_t>(2, options.key.option1), options.key.option2, options.key.option3, &tKey[0], tKey.size()) != 0) {
			throw CExc(CExc::File::crypt, __LINE__);
		}
		break;
	}
	}
	try	{
		if ((cipher_flags[int(options.cipher)] & STREAM) == STREAM)	{
			std::unique_ptr<SymmetricCipherDocumentation::Decryption> pEnc;
			switch (options.cipher) {
			case Cipher::sosemanuk: pEnc.reset(new Sosemanuk::Decryption(tKey.data(), key_len, ptVec)); break;
			case Cipher::rc4: pEnc.reset(new Weak::ARC4::Decryption(tKey.data(), key_len)); break;
			case Cipher::salsa20: pEnc.reset(new Salsa20::Decryption(tKey.data(), key_len, ptVec)); break;
			case Cipher::xsalsa20: pEnc.reset(new XSalsa20::Encryption(tKey.data(), key_len, ptVec)); break;
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
					default: throw CExc(CExc::File::crypt, __LINE__);
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

				std::basic_string<byte> mac;
				std::basic_string<byte> temp;
				const byte*				pEncrypted;
				size_t					Encrypted_size;
				StringSource((const byte*)init.tag.c_str(), init.tag.size(), true, new Base64Decoder(new StringSinkTemplate<std::basic_string<byte>>(mac)));
				
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

				df.ChannelPut("", mac.c_str(), mac.size());
				df.ChannelPut("AAD", (const byte*)init.salt.c_str(), init.salt.size());
				df.ChannelPut("AAD", (const byte*)init.iv.c_str(), init.iv.size());
				df.ChannelPut("", pEncrypted, Encrypted_size);
				df.MessageEnd();

				if (!df.GetLastResult()) {
					throw CExc(CExc::Code::authentication);
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
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<DES>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<DES>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<DES>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<DES>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::des_ede:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<DES_EDE2>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<DES_EDE2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<DES_EDE2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<DES_EDE2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<DES_EDE2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<DES_EDE2>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::des_ede3:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<DES_EDE3>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<DES_EDE3>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<DES_EDE3>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<DES_EDE3>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<DES_EDE3>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<DES_EDE3>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::desx:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<DES_XEX3>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<DES_XEX3>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<DES_XEX3>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<DES_XEX3>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<DES_XEX3>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<DES_XEX3>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::gost:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<GOST>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<GOST>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<GOST>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<GOST>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<GOST>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<GOST>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::cast128:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<CAST128>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<CAST128>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<CAST128>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<CAST128>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<CAST128>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<CAST128>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::cast256:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<CAST256>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<CAST256>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<CAST256>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<CAST256>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<CAST256>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<CAST256>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::rc2:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<RC2>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<RC2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<RC2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<RC2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<RC2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<RC2>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::rc5:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<RC5>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<RC5>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<RC5>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<RC5>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<RC5>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<RC5>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::rc6:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<RC6>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<RC6>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<RC6>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<RC6>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<RC6>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<RC6>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::idea:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<IDEA>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<IDEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<IDEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<IDEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<IDEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<IDEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::blowfish:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<Blowfish>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<Blowfish>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<Blowfish>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<Blowfish>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<Blowfish>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<Blowfish>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::camellia:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<Camellia>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<Camellia>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<Camellia>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<Camellia>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<Camellia>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<Camellia>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::seed:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<SEED>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<SEED>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<SEED>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<SEED>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<SEED>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<SEED>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::tea:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<TEA>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<TEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<TEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<TEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<TEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<TEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::xtea:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<XTEA>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<XTEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<XTEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<XTEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<XTEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<XTEA>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::shacal2:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<SHACAL2>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<SHACAL2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<SHACAL2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<SHACAL2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<SHACAL2>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<SHACAL2>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::mars:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<MARS>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<MARS>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<MARS>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<MARS>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<MARS>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<MARS>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::twofish:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<Twofish>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<Twofish>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<Twofish>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<Twofish>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<Twofish>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<Twofish>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::serpent:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<Serpent>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<Serpent>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<Serpent>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<Serpent>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<Serpent>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<Serpent>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				case Cipher::rijndael128: case Cipher::rijndael192: case Cipher::rijndael256:
				{
					switch (options.mode) {
					case Mode::ecb: pEnc.reset(new ECB_Mode<AES>::Decryption(tKey.data(), key_len)); break;
					case Mode::cbc: pEnc.reset(new CBC_Mode<AES>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cbc_cts: pEnc.reset(new CBC_CTS_Mode<AES>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::cfb: pEnc.reset(new CFB_Mode<AES>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ofb: pEnc.reset(new OFB_Mode<AES>::Decryption(tKey.data(), key_len, ptVec)); break;
					case Mode::ctr: pEnc.reset(new CTR_Mode<AES>::Decryption(tKey.data(), key_len, ptVec)); break;
					default: throw CExc(CExc::File::crypt, __LINE__);
					} break;
				}
				default: throw CExc(CExc::File::crypt, __LINE__);
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
	} catch (Exception& e) {
		if (e.GetErrorType() == Exception::DATA_INTEGRITY_CHECK_FAILED) {
			throw CExc(CExc::Code::authentication);
		}
		throw CExc(CExc::Code::decrypt);
	} catch (...) {
		throw CExc(CExc::File::crypt, __LINE__);
	}
}

void doHash(CryptoPP::HashTransformation& hash, const unsigned char* in, size_t in_len, CryptoPP::SecByteBlock& sbbDigest)
{
	using namespace std;
	using namespace CryptoPP;
	
	sbbDigest.resize(hash.DigestSize());
	hash.CalculateDigest(sbbDigest.begin(), in, in_len);
}

void crypt::hash(const unsigned char* in, size_t in_len, std::basic_string<byte>& buffer, const Options::Hash& options)
{
	if (!in && in_len > 0) {
		throw CExc(CExc::File::crypt, __LINE__);
	}
	
	try	{
		using namespace CryptoPP;
		using namespace std;

		SecByteBlock	digest;

		if (options.use_key) {
			std::unique_ptr<HMAC_Base> phmac;
			switch (options.algorithm)
			{
			case crypt::Hash::md4:
				phmac.reset(new HMAC< Weak::MD4 >); break;
			case crypt::Hash::md5:
				phmac.reset(new HMAC< Weak::MD5 >); break;
			case crypt::Hash::sha1:
				phmac.reset(new HMAC< SHA1 >); break;
			case crypt::Hash::sha256:
				phmac.reset(new HMAC< SHA256 >); break;
			case crypt::Hash::sha512:
				phmac.reset(new HMAC< SHA512 >); break;
			case crypt::Hash::ripemd128:
				phmac.reset(new HMAC< RIPEMD128 >); break;
			case crypt::Hash::ripemd160:
				phmac.reset(new HMAC< RIPEMD160 >); break;
			case crypt::Hash::ripemd256:
				phmac.reset(new HMAC< RIPEMD256 >); break;
			case crypt::Hash::whirlpool:
				phmac.reset(new HMAC< Whirlpool >); break;
			case crypt::Hash::tiger:
				phmac.reset(new HMAC< Tiger >); break;
			default: throw CExc(CExc::File::crypt, __LINE__);
			}
			digest.resize(phmac->DigestSize());
			phmac->SetKey(options.key.data(), options.key.size());
			StringSource ss2(in, in_len, true, new HashFilter(*phmac, new ArraySink(digest.BytePtr(), digest.size())));
		} else {
			switch (options.algorithm)
			{
			case crypt::Hash::md4: doHash(Weak::MD4(), in, in_len, digest); break;
			case crypt::Hash::md5: doHash(Weak::MD5(), in, in_len, digest); break;
			case crypt::Hash::sha1: doHash(SHA1(), in, in_len, digest); break;
			case crypt::Hash::sha256: doHash(SHA256(), in, in_len, digest); break;
			case crypt::Hash::sha512: doHash(SHA512(), in, in_len, digest); break;
			case crypt::Hash::ripemd128: doHash(RIPEMD128(), in, in_len, digest); break;
			case crypt::Hash::ripemd160: doHash(RIPEMD160(), in, in_len, digest); break;
			case crypt::Hash::ripemd256: doHash(RIPEMD256(), in, in_len, digest); break;
			case crypt::Hash::whirlpool: doHash(Whirlpool(), in, in_len, digest); break;
			case crypt::Hash::tiger: doHash(Tiger(), in, in_len, digest); break;
			case crypt::Hash::sha3_224: doHash(SHA3_224(), in, in_len, digest); break;
			case crypt::Hash::sha3_256: doHash(SHA3_256(), in, in_len, digest); break;
			case crypt::Hash::sha3_384: doHash(SHA3_384(), in, in_len, digest); break;
			case crypt::Hash::sha3_512: doHash(SHA3_512(), in, in_len, digest); break;
			}
		}
		switch (options.encoding)
		{
		case crypt::Encoding::ascii:
		{
			buffer.resize(digest.size());
			for (size_t i = 0; i < digest.size(); i++) {
				buffer[i] = digest[i];
			}
			break;
		}
		case crypt::Encoding::base16:
		{
			HexEncoder(new StringSinkTemplate<basic_string<byte>>(buffer), true).Put(digest.begin(), digest.size());
			break;
		}
		case crypt::Encoding::base32:
		{
			Base32Encoder(new StringSinkTemplate<basic_string<byte>>(buffer), true).Put(digest.begin(), digest.size());
			break;
		}
		case crypt::Encoding::base64:
		{
			StringSource ss(digest, digest.size(), true,
				new Base64Encoder( new StringSinkTemplate<basic_string<byte>>(buffer), false )
				);
			break;
		}
		}
	} catch (std::exception& ) {
		throw CExc(CExc::File::crypt, __LINE__);
	}
}

void crypt::hmac_header(const char* a, size_t a_len, const byte* b, size_t b_len, const Options::Crypt::HMAC& options, std::string& out)
{
	try	{
		using namespace CryptoPP;
		using namespace std;

		SecByteBlock	digest;

		std::unique_ptr<HMAC_Base> phmac;
		switch (options.hash)
		{
		case crypt::Hash::md4:
			phmac.reset(new HMAC< Weak::MD4 >); break;
		case crypt::Hash::md5:
			phmac.reset(new HMAC< Weak::MD5 >); break;
		case crypt::Hash::sha1:
			phmac.reset(new HMAC< SHA1 >); break;
		case crypt::Hash::sha256:
			phmac.reset(new HMAC< SHA256 >); break;
		case crypt::Hash::sha512:
			phmac.reset(new HMAC< SHA512 >); break;
		case crypt::Hash::ripemd128:
			phmac.reset(new HMAC< RIPEMD128 >); break;
		case crypt::Hash::ripemd160:
			phmac.reset(new HMAC< RIPEMD160 >); break;
		case crypt::Hash::ripemd256:
			phmac.reset(new HMAC< RIPEMD256 >); break;
		case crypt::Hash::whirlpool:
			phmac.reset(new HMAC< Whirlpool >); break;
		case crypt::Hash::tiger:
			phmac.reset(new HMAC< Tiger >); break;
		default: throw CExc(CExc::File::crypt, __LINE__);
		}

		digest.resize(phmac->DigestSize());
		phmac->SetKey(options.key.data(), options.key.size());
		HashFilter f(*phmac, new Base64Encoder(new StringSink(out), false));
		f.Put((const byte*)a, a_len);
		f.Put(b, b_len);
		f.MessageEnd();
	} catch (std::exception& ) {
		throw CExc(CExc::File::crypt, __LINE__);
	}
}

void crypt::shake128(const unsigned char* in, size_t in_len, unsigned char* out, size_t out_len)
{
	Keccak_HashInstance keccak_inst;
	if (Keccak_HashInitialize_SHAKE128(&keccak_inst) != 0) {
		throw CExc(CExc::File::crypt, __LINE__);
	}
	if (Keccak_HashUpdate(&keccak_inst, in, in_len * 8) != 0) {
		throw CExc(CExc::File::crypt, __LINE__);
	}
	if (Keccak_HashFinal(&keccak_inst, out) != 0) {
		throw CExc(CExc::File::crypt, __LINE__);
	}
	if (Keccak_HashSqueeze(&keccak_inst, out, out_len * 8) != 0) {
		throw CExc(CExc::File::crypt, __LINE__);
	}
}

void crypt::random(const Options::Random& options, std::basic_string<byte>& buffer)
{
	if (options.length == 0) {
		throw CExc(CExc::File::crypt, __LINE__);
	}

	using namespace CryptoPP;

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

	std::string s_seperator = options.windows ? "\r\n" : "\n";
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
			StringSource(in, in_len, true, new Base64Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.linebreaks, (options.windows ? EOL::Windows : EOL::Unix), options.linelength));
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
			StringSource(in, in_len, true, new HexDecoder(new Base64Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.linebreaks, (options.windows ? EOL::Windows : EOL::Unix), options.linelength)));
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
			StringSource(in, in_len, true, new Base32Decoder(new Base64Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.linebreaks, (options.windows ? EOL::Windows : EOL::Unix), options.linelength)));
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

size_t crypt::getHashLength(Hash h)
{
	using namespace CryptoPP;
	switch(h)
	{
	case crypt::Hash::md4: return Weak::MD4::DIGESTSIZE;
	case crypt::Hash::md5: return Weak::MD5::DIGESTSIZE;
	case crypt::Hash::sha1: return SHA1::DIGESTSIZE;
	case crypt::Hash::sha256: return SHA256::DIGESTSIZE;
	case crypt::Hash::sha512: return SHA512::DIGESTSIZE;
	case crypt::Hash::ripemd128: return RIPEMD128::DIGESTSIZE;
	case crypt::Hash::ripemd160: return RIPEMD160::DIGESTSIZE;
	case crypt::Hash::ripemd256: return RIPEMD256::DIGESTSIZE;
	case crypt::Hash::whirlpool: return Whirlpool::DIGESTSIZE;
	case crypt::Hash::tiger: return Tiger::DIGESTSIZE;
	case crypt::Hash::sha3_224: return SHA3_224::DIGESTSIZE;
	case crypt::Hash::sha3_256: return SHA3_256::DIGESTSIZE;
	case crypt::Hash::sha3_384: return SHA3_384::DIGESTSIZE;
	case crypt::Hash::sha3_512: return SHA3_512::DIGESTSIZE;
	}
	return 0;
}

// ===========================================================================================================================================================================

int crypt::help::Iter::_what = 0;
int crypt::help::Iter::i = -1;
int crypt::help::Iter::_cipher = -1;
int crypt::help::Iter::_temp = 0;

void crypt::help::Iter::setup_cipher(CipherCat category)
{
	_what = 0;
	i = -1;
	switch (category) {
	case CipherCat::aes: _temp = C_AES; break;
	case CipherCat::other: _temp = C_OTHER; break;
	case CipherCat::stream: _temp = C_STREAM; break;
	case CipherCat::weak: _temp = C_WEAK; break;
	default: _temp = -1;
	}
}

void crypt::help::Iter::setup_mode(Cipher cipher)
{
	_what = 1;
	_cipher = int(cipher);
	i = -1;
}

void crypt::help::Iter::setup_hash(bool hmac)
{
	_what = 2;
	i = -1;
	_temp = hmac ? 1 : 0;
}

bool crypt::help::Iter::next()
{
	i++;
	switch (_what)
	{
	case 0:
	{
		while (i < static_cast<int>(Cipher::COUNT))	{
			if (_temp == -1 || (cipher_flags[i] & _temp) == _temp) {
				return true;
			}
			i++;
		}
		return false;
	}
	case 1:
	{
		if ((cipher_flags[_cipher] & STREAM) == STREAM) {
			return false;
		}
		while (i < static_cast<int>(Mode::COUNT)) {
			if (((int(Mode::eax) == i && (cipher_flags[_cipher] & MODE_EAX) != MODE_EAX))
				|| ((int(Mode::ccm) == i && (cipher_flags[_cipher] & MODE_CCM) != MODE_CCM))
				|| ((int(Mode::gcm) == i && (cipher_flags[_cipher] & MODE_GCM) != MODE_GCM)))
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
		if (_temp == 1)	{
			if (i < static_cast<int>(Hash::HMAC_COUNT)) {
				return true;
			}
		} else {
			if (i < static_cast<int>(Hash::COUNT)) {
				return true;
			}
		}
		i = -1;
		return false;
	}
	}
	return false;
}

const TCHAR* crypt::help::Iter::getString()
{
	if (i < 0) {
		return NULL;
	}
	switch (_what)
	{
	case 0:	return cipher_str[i];
	case 1:	return mode_str[i];
	case 2:	return hash_str[i];
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
	if (!s) {
		return false;
	}
	size_t sl = strlen(s);
	for (size_t i = 0; i< static_cast<int>(Cipher::COUNT); i++)	{
		if (sl != strlen(cipher_str_c[i])) {
			continue;
		}
		size_t x = 0;
		for (x = 0; x< sl; x++) {
			if (s[x] != cipher_str_c[i][x]) {
				break;
			}
		}
		if (x == sl) {
			c = (crypt::Cipher)i;
			return true;
		}
	}
	static const char* s_old[] = { "cast5", "aes128", "aes192", "aes256" };
	static const crypt::Cipher o_cipher[] = { Cipher::cast128, Cipher::rijndael128, Cipher::rijndael192, Cipher::rijndael256 };
	for (size_t i = 0; i < 4; i++) {
		if (std::strcmp(s, s_old[i]) == 0) {
			c = o_cipher[i];
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
		if (sl != lstrlen(mode_str[i])) {
			continue;
		}
		for (x = 0; x< sl; x++) {
			if (s[x] != (char)mode_str[i][x]) {
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
		if (strcmp(s, key_algo_str_c[i]) == 0) {
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
		if (strcmp(s, iv_str_c[i]) == 0) {
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
		if (strcmp(s, encoding_str_c[i]) == 0) {
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
		if (strcmp(s, random_mode_str_c[i]) == 0) {
			m = (crypt::Random)i;
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
		if (sl != lstrlen(hash_str[i])) {
			continue;
		}
		for (x = 0; x< sl; x++) {
			if (s[x] != (char)hash_str[i][x]) {
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
		if ((cipher_flags[int(cipher)] & MODE_EAX) == MODE_EAX) {
			return Mode::eax;
		}
	} else if (index == int(Mode::ccm))	{
		if ((cipher_flags[int(cipher)] & MODE_CCM) == MODE_CCM) {
			return Mode::ccm;
		}
	} else if (index == int(Mode::gcm))	{
		if ((cipher_flags[int(cipher)] & MODE_GCM) == MODE_GCM) {
			return Mode::gcm;
		}
	}
	return Mode::cbc;
}

int crypt::help::getIndexByMode(crypt::Cipher cipher, crypt::Mode mode)
{
	if (mode == Mode::eax) {
		if ((cipher_flags[int(cipher)] & MODE_EAX) == MODE_EAX) {
			return int(Mode::eax);
		}
	} else if (mode == Mode::ccm) {
		if ((cipher_flags[int(cipher)] & MODE_CCM) == MODE_CCM) {
			return int(Mode::ccm);
		}
	} else if (mode == Mode::gcm) {
		if ((cipher_flags[int(cipher)] & MODE_GCM) == MODE_GCM) {
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
		if ((cipher_flags[int(cipher)] & MODE_EAX) == MODE_EAX) {
			return true;
		}
	} else if (mode == Mode::ccm) {
		if ((cipher_flags[int(cipher)] & MODE_CCM) == MODE_CCM) {
			return true;
		}
	} else if (mode == Mode::gcm) {
		if ((cipher_flags[int(cipher)] & MODE_GCM) == MODE_GCM) {
			return true;
		}
	} else {
		return true;
	}
	return false;
}

int crypt::help::getCipherCategory(Cipher cipher)
{
	if ((cipher_flags[int(cipher)] & C_AES) == C_AES) {
		return 0;
	} else if ((cipher_flags[int(cipher)] & C_OTHER) == C_OTHER) {
		return 1;
	} else if ((cipher_flags[int(cipher)] & C_STREAM) == C_STREAM) {
		return 2;
	} else if ((cipher_flags[int(cipher)] & C_WEAK) == C_WEAK) {
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
	case CipherCat::aes: cat = C_AES; break;
	case CipherCat::other: cat = C_OTHER; break;
	case CipherCat::stream: cat = C_STREAM; break;
	case CipherCat::weak: cat = C_WEAK; break;
	}
	for (i = 0; i < int(Cipher::COUNT); i++) {
		if ((cipher_flags[i] & cat) == cat) {
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
	if ((cipher_flags[int(cipher)] & C_AES) == C_AES) {
		cat = C_AES;
	} else if ((cipher_flags[int(cipher)] & C_OTHER) == C_OTHER) {
		cat = C_OTHER;
	} else if ((cipher_flags[int(cipher)] & C_STREAM) == C_STREAM) {
		cat = C_STREAM;
	} else {
		cat = C_WEAK;
	}
	int index = -1;
	for (int i = 0; i < int(Cipher::COUNT); i++) {
		if ((cipher_flags[i] & cat) == cat) {
			index++;
		}
		if (i == int(cipher)) {
			break;
		}
	}
	return index;
}

bool crypt::help::canCalcHMAC(crypt::Hash h)
{
	return (h < Hash::sha3_256);
}

const TCHAR* crypt::help::getHelpURL(crypt::Encoding enc)
{
	lstrcpy(help_url_wikipedia + help_url_wikipedia_len, encoding_help_url[unsigned(enc)]);
	return help_url_wikipedia;
}

const TCHAR* crypt::help::getHelpURL(crypt::Cipher cipher)
{
	lstrcpy(help_url_wikipedia + help_url_wikipedia_len, cipher_help_url[unsigned(cipher)]);
	return help_url_wikipedia;
}

const TCHAR* crypt::help::getHelpURL(crypt::Hash h)
{
	lstrcpy(help_url_wikipedia + help_url_wikipedia_len, hash_help_url[unsigned(h)]);
	return help_url_wikipedia;
}

const TCHAR* crypt::help::getHelpURL(crypt::KeyDerivation k)
{
	lstrcpy(help_url_wikipedia + help_url_wikipedia_len, key_algo_help_url[unsigned(k)]);
	return help_url_wikipedia;
}

const TCHAR* crypt::help::getHelpURL(crypt::Mode m)
{
	lstrcpy(help_url_wikipedia + help_url_wikipedia_len, mode_help_url[unsigned(m)]);
	return help_url_wikipedia;
}