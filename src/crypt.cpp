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

#include "crypt.h"
#include "exception.h"

#include "bcrypt/crypt_blowfish.h"
#include "keccak/KeccakHash.h"

extern "C" {
#include "scrypt/crypto_scrypt.h"
}

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptopp/md5.h"
#include "cryptopp/md4.h"
#include "cryptopp/md2.h"
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
#include "cryptopp/3way.h"
#include "cryptopp/aria.h"
#include "cryptopp/kalyna.h"
#include "cryptopp/safer.h"
#include "cryptopp/seal.h"
#include "cryptopp/shark.h"
#include "cryptopp/simon.h"
#include "cryptopp/sm3.h"
#include "cryptopp/sm4.h"
#include "cryptopp/speck.h"
#include "cryptopp/square.h"
#include "cryptopp/threefish.h"
#include "cryptopp/wake.h"
#include "cryptopp/factory.h"
#include "cryptopp/adler32.h"
#include "cryptopp/crc.h"
#include "cryptopp/siphash.h"

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

namespace Strings
{
	static const std::string eol[3] = { "\r\n", "\n", "\r" };
}

using namespace crypt;

// ===========================================================================================================================================================================================
// TODO: maybe the factory should be used ... ( cryptopp/factory.h )
// ===========================================================================================================================================================================================

namespace intern
{
	CryptoPP::PasswordBasedKeyDerivationFunction* getKeyDerivation(Hash hash, int digest)
	{
		using namespace CryptoPP;

		switch (hash)
		{
		case Hash::keccak:
			if (digest == 28) {
				return new PKCS5_PBKDF2_HMAC< Keccak_224 >;
			} else if (digest == 48) {
				return new PKCS5_PBKDF2_HMAC< Keccak_384 >;
			} else if (digest == 64) {
				return new PKCS5_PBKDF2_HMAC< Keccak_512 >;
			} else {
				return new PKCS5_PBKDF2_HMAC< Keccak_256 >;
			}			
		case Hash::md2:
			return new PKCS5_PBKDF2_HMAC<Weak::MD2>;
		case Hash::md4:
			return new PKCS5_PBKDF2_HMAC<Weak::MD4>;
		case Hash::md5:
			return new PKCS5_PBKDF2_HMAC<Weak::MD5>;
		case Hash::ripemd:
			if (digest == 16) {
				return new PKCS5_PBKDF2_HMAC< RIPEMD128 >;
			} else if (digest == 20) {
				return new PKCS5_PBKDF2_HMAC< RIPEMD160 >;
			} else if (digest == 40) {
				return new PKCS5_PBKDF2_HMAC< RIPEMD320 >;
			} else {
				return new PKCS5_PBKDF2_HMAC< RIPEMD256 >;
			}			
		case Hash::sha1:
			return new PKCS5_PBKDF2_HMAC<SHA1>;
		case Hash::sha2:
			if (digest == 28) {
				return new PKCS5_PBKDF2_HMAC< SHA224 >;
			} else if (digest == 48) {
				return new PKCS5_PBKDF2_HMAC< SHA384 >;
			} else if (digest == 64) {
				return new PKCS5_PBKDF2_HMAC< SHA512 >;
			} else {
				return new PKCS5_PBKDF2_HMAC< SHA256 >;
			}			
		case Hash::sha3:
			if (digest == 28) {
				return new PKCS5_PBKDF2_HMAC< SHA3_224 >;
			} else if (digest == 48) {
				return new PKCS5_PBKDF2_HMAC< SHA3_384 >;
			} else if (digest == 64) {
				return new PKCS5_PBKDF2_HMAC< SHA3_512 >;
			} else {
				return new PKCS5_PBKDF2_HMAC< SHA3_256 >;
			}			
		case Hash::sm3:
			return new PKCS5_PBKDF2_HMAC< SM3 >;
		case Hash::tiger:
			return new PKCS5_PBKDF2_HMAC< Tiger >;
		case Hash::whirlpool:
			return new PKCS5_PBKDF2_HMAC< Whirlpool >;
		}
		return NULL;
	}

	CryptoPP::AuthenticatedSymmetricCipher* getAuthenticatedCipher(Cipher cipher, Mode mode, bool encryption)
	{
		using namespace CryptoPP;
		switch (cipher)
		{
		case Cipher::aria:
		{
			switch (mode)
			{
			case Mode::gcm: return (encryption ? (AuthenticatedSymmetricCipher*)(new GCM< ARIA >::Encryption) : (new GCM< ARIA >::Decryption));
			case Mode::ccm: return (encryption ? (AuthenticatedSymmetricCipher*)(new CCM< ARIA >::Encryption) : (new CCM< ARIA >::Decryption));
			case Mode::eax: return (encryption ? (AuthenticatedSymmetricCipher*)(new EAX< ARIA >::Encryption) : (new EAX< ARIA >::Decryption));
			}
			break;
		}
		case Cipher::camellia:
		{
			switch (mode)
			{
			case Mode::gcm: return (encryption ? (AuthenticatedSymmetricCipher*)(new GCM< Camellia >::Encryption) : (new GCM< Camellia >::Decryption));
			case Mode::ccm: return (encryption ? (AuthenticatedSymmetricCipher*)(new CCM< Camellia >::Encryption) : (new CCM< Camellia >::Decryption));
			case Mode::eax: return (encryption ? (AuthenticatedSymmetricCipher*)(new EAX< Camellia >::Encryption) : (new EAX< Camellia >::Decryption));
			}
			break;
		}
		case Cipher::cast256:
		{
			switch (mode)
			{
			case Mode::gcm: return (encryption ? (AuthenticatedSymmetricCipher*)(new GCM< CAST256 >::Encryption) : (new GCM< CAST256 >::Decryption));
			case Mode::ccm: return (encryption ? (AuthenticatedSymmetricCipher*)(new CCM< CAST256 >::Encryption) : (new CCM< CAST256 >::Decryption));
			case Mode::eax: return (encryption ? (AuthenticatedSymmetricCipher*)(new EAX< CAST256 >::Encryption) : (new EAX< CAST256 >::Decryption));
			}
			break;
		}
		case Cipher::kalyna128:
		{
			switch (mode)
			{
			case Mode::gcm: return (encryption ? (AuthenticatedSymmetricCipher*)(new GCM< Kalyna128 >::Encryption) : (new GCM< Kalyna128 >::Decryption));
			case Mode::ccm: return (encryption ? (AuthenticatedSymmetricCipher*)(new CCM< Kalyna128 >::Encryption) : (new CCM< Kalyna128 >::Decryption));
			case Mode::eax: return (encryption ? (AuthenticatedSymmetricCipher*)(new EAX< Kalyna128 >::Encryption) : (new EAX< Kalyna128 >::Decryption));
			}
			break;
		}
		case Cipher::mars:
		{
			switch (mode)
			{
			case Mode::gcm: return (encryption ? (AuthenticatedSymmetricCipher*)(new GCM< MARS >::Encryption) : (new GCM< MARS >::Decryption));
			case Mode::ccm: return (encryption ? (AuthenticatedSymmetricCipher*)(new CCM< MARS >::Encryption) : (new CCM< MARS >::Decryption));
			case Mode::eax: return (encryption ? (AuthenticatedSymmetricCipher*)(new EAX< MARS >::Encryption) : (new EAX< MARS >::Decryption));
			}
			break;
		}
		case Cipher::rc6:
		{
			switch (mode)
			{
			case Mode::gcm: return (encryption ? (AuthenticatedSymmetricCipher*)(new GCM< RC6 >::Encryption) : (new GCM< RC6 >::Decryption));
			case Mode::ccm: return (encryption ? (AuthenticatedSymmetricCipher*)(new CCM< RC6 >::Encryption) : (new CCM< RC6 >::Decryption));
			case Mode::eax: return (encryption ? (AuthenticatedSymmetricCipher*)(new EAX< RC6 >::Encryption) : (new EAX< RC6 >::Decryption));
			}
			break;
		}
		case Cipher::rijndael:
		{
			switch (mode)
			{
			case Mode::gcm: return (encryption ? (AuthenticatedSymmetricCipher*)(new GCM< AES >::Encryption) : (new GCM< AES >::Decryption));
			case Mode::ccm: return (encryption ? (AuthenticatedSymmetricCipher*)(new CCM< AES >::Encryption) : (new CCM< AES >::Decryption));
			case Mode::eax: return (encryption ? (AuthenticatedSymmetricCipher*)(new EAX< AES >::Encryption) : (new EAX< AES >::Decryption));
			}
			break;
		}
		case Cipher::seed:
		{
			switch (mode)
			{
			case Mode::gcm: return (encryption ? (AuthenticatedSymmetricCipher*)(new GCM< SEED >::Encryption) : (new GCM< SEED >::Decryption));
			case Mode::ccm: return (encryption ? (AuthenticatedSymmetricCipher*)(new CCM< SEED >::Encryption) : (new CCM< SEED >::Decryption));
			case Mode::eax: return (encryption ? (AuthenticatedSymmetricCipher*)(new EAX< SEED >::Encryption) : (new EAX< SEED >::Decryption));
			}
			break;
		}
		case Cipher::serpent:
		{
			switch (mode)
			{
			case Mode::gcm: return (encryption ? (AuthenticatedSymmetricCipher*)(new GCM< Serpent >::Encryption) : (new GCM< Serpent >::Decryption));
			case Mode::ccm: return (encryption ? (AuthenticatedSymmetricCipher*)(new CCM< Serpent >::Encryption) : (new CCM< Serpent >::Decryption));
			case Mode::eax: return (encryption ? (AuthenticatedSymmetricCipher*)(new EAX< Serpent >::Encryption) : (new EAX< Serpent >::Decryption));
			}
			break;
		}
		case Cipher::simon128:
		{
			switch (mode)
			{
			case Mode::gcm: return (encryption ? (AuthenticatedSymmetricCipher*)(new GCM< SIMON128 >::Encryption) : (new GCM< SIMON128 >::Decryption));
			case Mode::ccm: return (encryption ? (AuthenticatedSymmetricCipher*)(new CCM< SIMON128 >::Encryption) : (new CCM< SIMON128 >::Decryption));
			case Mode::eax: return (encryption ? (AuthenticatedSymmetricCipher*)(new EAX< SIMON128 >::Encryption) : (new EAX< SIMON128 >::Decryption));
			}
			break;
		}
		case Cipher::sm4:
		{
			switch (mode)
			{
			case Mode::gcm: return (encryption ? (AuthenticatedSymmetricCipher*)(new GCM< SM4 >::Encryption) : (new GCM< SM4 >::Decryption));
			case Mode::ccm: return (encryption ? (AuthenticatedSymmetricCipher*)(new CCM< SM4 >::Encryption) : (new CCM< SM4 >::Decryption));
			case Mode::eax: return (encryption ? (AuthenticatedSymmetricCipher*)(new EAX< SM4 >::Encryption) : (new EAX< SM4 >::Decryption));
			}
			break;
		}
		case Cipher::speck128:
		{
			switch (mode)
			{
			case Mode::gcm: return (encryption ? (AuthenticatedSymmetricCipher*)(new GCM< SPECK128 >::Encryption) : (new GCM< SPECK128 >::Decryption));
			case Mode::ccm: return (encryption ? (AuthenticatedSymmetricCipher*)(new CCM< SPECK128 >::Encryption) : (new CCM< SPECK128 >::Decryption));
			case Mode::eax: return (encryption ? (AuthenticatedSymmetricCipher*)(new EAX< SPECK128 >::Encryption) : (new EAX< SPECK128 >::Decryption));
			}
			break;
		}
		case Cipher::square:
		{
			switch (mode)
			{
			case Mode::gcm: return (encryption ? (AuthenticatedSymmetricCipher*)(new GCM< Square >::Encryption) : (new GCM< Square >::Decryption));
			case Mode::ccm: return (encryption ? (AuthenticatedSymmetricCipher*)(new CCM< Square >::Encryption) : (new CCM< Square >::Decryption));
			case Mode::eax: return (encryption ? (AuthenticatedSymmetricCipher*)(new EAX< Square >::Encryption) : (new EAX< Square >::Decryption));
			}
			break;
		}
		case Cipher::twofish:
		{
			switch (mode)
			{
			case Mode::gcm: return (encryption ? (AuthenticatedSymmetricCipher*)(new GCM< Twofish >::Encryption) : (new GCM< Twofish >::Decryption));
			case Mode::ccm: return (encryption ? (AuthenticatedSymmetricCipher*)(new CCM< Twofish >::Encryption) : (new CCM< Twofish >::Decryption));
			case Mode::eax: return (encryption ? (AuthenticatedSymmetricCipher*)(new EAX< Twofish >::Encryption) : (new EAX< Twofish >::Decryption));
			}
			break;
		}
		}
		return NULL;
	}

	CryptoPP::SymmetricCipher* getSymmetricCipher(Cipher cipher, Mode mode, bool encryption)
	{
		using namespace CryptoPP;
		switch (cipher)
		{
		case Cipher::threeway:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<ThreeWay>::Encryption) : (new ECB_Mode<ThreeWay>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<ThreeWay>::Encryption) : (new CBC_Mode<ThreeWay>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<ThreeWay>::Encryption) : (new CFB_Mode<ThreeWay>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<ThreeWay>::Encryption) : (new OFB_Mode<ThreeWay>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<ThreeWay>::Encryption) : (new CTR_Mode<ThreeWay>::Decryption);
			}
			break;
		}
		case Cipher::aria:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<ARIA>::Encryption) : (new ECB_Mode<ARIA>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<ARIA>::Encryption) : (new CBC_Mode<ARIA>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<ARIA>::Encryption) : (new CFB_Mode<ARIA>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<ARIA>::Encryption) : (new OFB_Mode<ARIA>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<ARIA>::Encryption) : (new CTR_Mode<ARIA>::Decryption);
			}
			break;
		}
		case Cipher::blowfish:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<Blowfish>::Encryption) : (new ECB_Mode<Blowfish>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<Blowfish>::Encryption) : (new CBC_Mode<Blowfish>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<Blowfish>::Encryption) : (new CFB_Mode<Blowfish>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<Blowfish>::Encryption) : (new OFB_Mode<Blowfish>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<Blowfish>::Encryption) : (new CTR_Mode<Blowfish>::Decryption);
			}
			break;
		}
		/*case Cipher::btea:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<BTEA>::Encryption) : (new ECB_Mode<BTEA>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<BTEA>::Encryption) : (new CBC_Mode<BTEA>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<BTEA>::Encryption) : (new CFB_Mode<BTEA>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<BTEA>::Encryption) : (new OFB_Mode<BTEA>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<BTEA>::Encryption) : (new CTR_Mode<BTEA>::Decryption);
			}
			break;
		}*/
		case Cipher::camellia:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<Camellia>::Encryption) : (new ECB_Mode<Camellia>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<Camellia>::Encryption) : (new CBC_Mode<Camellia>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<Camellia>::Encryption) : (new CFB_Mode<Camellia>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<Camellia>::Encryption) : (new OFB_Mode<Camellia>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<Camellia>::Encryption) : (new CTR_Mode<Camellia>::Decryption);
			}
			break;
		}
		case Cipher::cast128:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<CAST128>::Encryption) : (new ECB_Mode<CAST128>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<CAST128>::Encryption) : (new CBC_Mode<CAST128>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<CAST128>::Encryption) : (new CFB_Mode<CAST128>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<CAST128>::Encryption) : (new OFB_Mode<CAST128>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<CAST128>::Encryption) : (new CTR_Mode<CAST128>::Decryption);
			}
			break;
		}
		case Cipher::cast256:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<CAST256>::Encryption) : (new ECB_Mode<CAST256>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<CAST256>::Encryption) : (new CBC_Mode<CAST256>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<CAST256>::Encryption) : (new CFB_Mode<CAST256>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<CAST256>::Encryption) : (new OFB_Mode<CAST256>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<CAST256>::Encryption) : (new CTR_Mode<CAST256>::Decryption);
			}
			break;
		}
		case Cipher::des:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<DES>::Encryption) : (new ECB_Mode<DES>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<DES>::Encryption) : (new CBC_Mode<DES>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<DES>::Encryption) : (new CFB_Mode<DES>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<DES>::Encryption) : (new OFB_Mode<DES>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<DES>::Encryption) : (new CTR_Mode<DES>::Decryption);
			}
			break;
		}
		case Cipher::des_ede2:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<DES_EDE2>::Encryption) : (new ECB_Mode<DES_EDE2>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<DES_EDE2>::Encryption) : (new CBC_Mode<DES_EDE2>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<DES_EDE2>::Encryption) : (new CFB_Mode<DES_EDE2>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<DES_EDE2>::Encryption) : (new OFB_Mode<DES_EDE2>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<DES_EDE2>::Encryption) : (new CTR_Mode<DES_EDE2>::Decryption);
			}
			break;
		}
		case Cipher::des_ede3:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<DES_EDE3>::Encryption) : (new ECB_Mode<DES_EDE3>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<DES_EDE3>::Encryption) : (new CBC_Mode<DES_EDE3>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<DES_EDE3>::Encryption) : (new CFB_Mode<DES_EDE3>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<DES_EDE3>::Encryption) : (new OFB_Mode<DES_EDE3>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<DES_EDE3>::Encryption) : (new CTR_Mode<DES_EDE3>::Decryption);
			}
			break;
		}
		case Cipher::desx:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<DES_XEX3>::Encryption) : (new ECB_Mode<DES_XEX3>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<DES_XEX3>::Encryption) : (new CBC_Mode<DES_XEX3>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<DES_XEX3>::Encryption) : (new CFB_Mode<DES_XEX3>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<DES_XEX3>::Encryption) : (new OFB_Mode<DES_XEX3>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<DES_XEX3>::Encryption) : (new CTR_Mode<DES_XEX3>::Decryption);
			}
			break;
		}
		case Cipher::gost:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<GOST>::Encryption) : (new ECB_Mode<GOST>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<GOST>::Encryption) : (new CBC_Mode<GOST>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<GOST>::Encryption) : (new CFB_Mode<GOST>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<GOST>::Encryption) : (new OFB_Mode<GOST>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<GOST>::Encryption) : (new CTR_Mode<GOST>::Decryption);
			}
			break;
		}
		case Cipher::idea:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<IDEA>::Encryption) : (new ECB_Mode<IDEA>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<IDEA>::Encryption) : (new CBC_Mode<IDEA>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<IDEA>::Encryption) : (new CFB_Mode<IDEA>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<IDEA>::Encryption) : (new OFB_Mode<IDEA>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<IDEA>::Encryption) : (new CTR_Mode<IDEA>::Decryption);
			}
			break;
		}
		case Cipher::kalyna128:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<Kalyna128>::Encryption) : (new ECB_Mode<Kalyna128>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<Kalyna128>::Encryption) : (new CBC_Mode<Kalyna128>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<Kalyna128>::Encryption) : (new CFB_Mode<Kalyna128>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<Kalyna128>::Encryption) : (new OFB_Mode<Kalyna128>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<Kalyna128>::Encryption) : (new CTR_Mode<Kalyna128>::Decryption);
			}
			break;
		}
		case Cipher::kalyna256:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<Kalyna256>::Encryption) : (new ECB_Mode<Kalyna256>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<Kalyna256>::Encryption) : (new CBC_Mode<Kalyna256>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<Kalyna256>::Encryption) : (new CFB_Mode<Kalyna256>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<Kalyna256>::Encryption) : (new OFB_Mode<Kalyna256>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<Kalyna256>::Encryption) : (new CTR_Mode<Kalyna256>::Decryption);
			}
			break;
		}
		case Cipher::kalyna512:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<Kalyna512>::Encryption) : (new ECB_Mode<Kalyna512>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<Kalyna512>::Encryption) : (new CBC_Mode<Kalyna512>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<Kalyna512>::Encryption) : (new CFB_Mode<Kalyna512>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<Kalyna512>::Encryption) : (new OFB_Mode<Kalyna512>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<Kalyna512>::Encryption) : (new CTR_Mode<Kalyna512>::Decryption);
			}
			break;
		}
		case Cipher::mars:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<MARS>::Encryption) : (new ECB_Mode<MARS>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<MARS>::Encryption) : (new CBC_Mode<MARS>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<MARS>::Encryption) : (new CFB_Mode<MARS>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<MARS>::Encryption) : (new OFB_Mode<MARS>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<MARS>::Encryption) : (new CTR_Mode<MARS>::Decryption);
			}
			break;
		}
		case Cipher::rc2:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<RC2>::Encryption) : (new ECB_Mode<RC2>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<RC2>::Encryption) : (new CBC_Mode<RC2>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<RC2>::Encryption) : (new CFB_Mode<RC2>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<RC2>::Encryption) : (new OFB_Mode<RC2>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<RC2>::Encryption) : (new CTR_Mode<RC2>::Decryption);
			}
			break;
		}
		case Cipher::rc5:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<RC5>::Encryption) : (new ECB_Mode<RC5>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<RC5>::Encryption) : (new CBC_Mode<RC5>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<RC5>::Encryption) : (new CFB_Mode<RC5>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<RC5>::Encryption) : (new OFB_Mode<RC5>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<RC5>::Encryption) : (new CTR_Mode<RC5>::Decryption);
			}
			break;
		}
		case Cipher::rc6:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<RC6>::Encryption) : (new ECB_Mode<RC6>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<RC6>::Encryption) : (new CBC_Mode<RC6>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<RC6>::Encryption) : (new CFB_Mode<RC6>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<RC6>::Encryption) : (new OFB_Mode<RC6>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<RC6>::Encryption) : (new CTR_Mode<RC6>::Decryption);
			}
			break;
		}
		case Cipher::rijndael:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<AES>::Encryption) : (new ECB_Mode<AES>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<AES>::Encryption) : (new CBC_Mode<AES>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<AES>::Encryption) : (new CFB_Mode<AES>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<AES>::Encryption) : (new OFB_Mode<AES>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<AES>::Encryption) : (new CTR_Mode<AES>::Decryption);
			}
			break;
		}
		case Cipher::saferk:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<SAFER_K>::Encryption) : (new ECB_Mode<SAFER_K>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<SAFER_K>::Encryption) : (new CBC_Mode<SAFER_K>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<SAFER_K>::Encryption) : (new CFB_Mode<SAFER_K>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<SAFER_K>::Encryption) : (new OFB_Mode<SAFER_K>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<SAFER_K>::Encryption) : (new CTR_Mode<SAFER_K>::Decryption);
			}
			break;
		}
		case Cipher::safersk:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<SAFER_SK>::Encryption) : (new ECB_Mode<SAFER_SK>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<SAFER_SK>::Encryption) : (new CBC_Mode<SAFER_SK>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<SAFER_SK>::Encryption) : (new CFB_Mode<SAFER_SK>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<SAFER_SK>::Encryption) : (new OFB_Mode<SAFER_SK>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<SAFER_SK>::Encryption) : (new CTR_Mode<SAFER_SK>::Decryption);
			}
			break;
		}
		case Cipher::seed:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<SEED>::Encryption) : (new ECB_Mode<SEED>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<SEED>::Encryption) : (new CBC_Mode<SEED>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<SEED>::Encryption) : (new CFB_Mode<SEED>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<SEED>::Encryption) : (new OFB_Mode<SEED>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<SEED>::Encryption) : (new CTR_Mode<SEED>::Decryption);
			}
			break;
		}
		case Cipher::serpent:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<Serpent>::Encryption) : (new ECB_Mode<Serpent>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<Serpent>::Encryption) : (new CBC_Mode<Serpent>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<Serpent>::Encryption) : (new CFB_Mode<Serpent>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<Serpent>::Encryption) : (new OFB_Mode<Serpent>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<Serpent>::Encryption) : (new CTR_Mode<Serpent>::Decryption);
			}
			break;
		}
		case Cipher::shacal2:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<SHACAL2>::Encryption) : (new ECB_Mode<SHACAL2>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<SHACAL2>::Encryption) : (new CBC_Mode<SHACAL2>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<SHACAL2>::Encryption) : (new CFB_Mode<SHACAL2>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<SHACAL2>::Encryption) : (new OFB_Mode<SHACAL2>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<SHACAL2>::Encryption) : (new CTR_Mode<SHACAL2>::Decryption);
			}
			break;
		}
		case Cipher::shark:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<SHARK>::Encryption) : (new ECB_Mode<SHARK>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<SHARK>::Encryption) : (new CBC_Mode<SHARK>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<SHARK>::Encryption) : (new CFB_Mode<SHARK>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<SHARK>::Encryption) : (new OFB_Mode<SHARK>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<SHARK>::Encryption) : (new CTR_Mode<SHARK>::Decryption);
			}
			break;
		}
		case Cipher::simon128:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<SIMON128>::Encryption) : (new ECB_Mode<SIMON128>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<SIMON128>::Encryption) : (new CBC_Mode<SIMON128>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<SIMON128>::Encryption) : (new CFB_Mode<SIMON128>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<SIMON128>::Encryption) : (new OFB_Mode<SIMON128>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<SIMON128>::Encryption) : (new CTR_Mode<SIMON128>::Decryption);
			}
			break;
		}
		case Cipher::skipjack:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<SKIPJACK>::Encryption) : (new ECB_Mode<SKIPJACK>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<SKIPJACK>::Encryption) : (new CBC_Mode<SKIPJACK>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<SKIPJACK>::Encryption) : (new CFB_Mode<SKIPJACK>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<SKIPJACK>::Encryption) : (new OFB_Mode<SKIPJACK>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<SKIPJACK>::Encryption) : (new CTR_Mode<SKIPJACK>::Decryption);
			}
			break;
		}
		case Cipher::sm4:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<SM4>::Encryption) : (new ECB_Mode<SM4>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<SM4>::Encryption) : (new CBC_Mode<SM4>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<SM4>::Encryption) : (new CFB_Mode<SM4>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<SM4>::Encryption) : (new OFB_Mode<SM4>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<SM4>::Encryption) : (new CTR_Mode<SM4>::Decryption);
			}
			break;
		}
		case Cipher::speck128:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<SPECK128>::Encryption) : (new ECB_Mode<SPECK128>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<SPECK128>::Encryption) : (new CBC_Mode<SPECK128>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<SPECK128>::Encryption) : (new CFB_Mode<SPECK128>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<SPECK128>::Encryption) : (new OFB_Mode<SPECK128>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<SPECK128>::Encryption) : (new CTR_Mode<SPECK128>::Decryption);
			}
			break;
		}
		case Cipher::square:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<Square>::Encryption) : (new ECB_Mode<Square>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<Square>::Encryption) : (new CBC_Mode<Square>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<Square>::Encryption) : (new CFB_Mode<Square>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<Square>::Encryption) : (new OFB_Mode<Square>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<Square>::Encryption) : (new CTR_Mode<Square>::Decryption);
			}
			break;
		}
		case Cipher::tea:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<TEA>::Encryption) : (new ECB_Mode<TEA>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<TEA>::Encryption) : (new CBC_Mode<TEA>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<TEA>::Encryption) : (new CFB_Mode<TEA>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<TEA>::Encryption) : (new OFB_Mode<TEA>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<TEA>::Encryption) : (new CTR_Mode<TEA>::Decryption);
			}
			break;
		}
		case Cipher::threefish256:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<Threefish256>::Encryption) : (new ECB_Mode<Threefish256>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<Threefish256>::Encryption) : (new CBC_Mode<Threefish256>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<Threefish256>::Encryption) : (new CFB_Mode<Threefish256>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<Threefish256>::Encryption) : (new OFB_Mode<Threefish256>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<Threefish256>::Encryption) : (new CTR_Mode<Threefish256>::Decryption);
			}
			break;
		}
		case Cipher::threefish512:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<Threefish512>::Encryption) : (new ECB_Mode<Threefish512>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<Threefish512>::Encryption) : (new CBC_Mode<Threefish512>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<Threefish512>::Encryption) : (new CFB_Mode<Threefish512>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<Threefish512>::Encryption) : (new OFB_Mode<Threefish512>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<Threefish512>::Encryption) : (new CTR_Mode<Threefish512>::Decryption);
			}
			break;
		}
		case Cipher::threefish1024:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<Threefish1024>::Encryption) : (new ECB_Mode<Threefish1024>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<Threefish1024>::Encryption) : (new CBC_Mode<Threefish1024>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<Threefish1024>::Encryption) : (new CFB_Mode<Threefish1024>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<Threefish1024>::Encryption) : (new OFB_Mode<Threefish1024>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<Threefish1024>::Encryption) : (new CTR_Mode<Threefish1024>::Decryption);
			}
			break;
		}
		case Cipher::twofish:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<Twofish>::Encryption) : (new ECB_Mode<Twofish>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<Twofish>::Encryption) : (new CBC_Mode<Twofish>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<Twofish>::Encryption) : (new CFB_Mode<Twofish>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<Twofish>::Encryption) : (new OFB_Mode<Twofish>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<Twofish>::Encryption) : (new CTR_Mode<Twofish>::Decryption);
			}
			break;
		}
		case Cipher::xtea:
		{
			switch (mode) {
			case Mode::ecb: return encryption ? (SymmetricCipher*)(new ECB_Mode<XTEA>::Encryption) : (new ECB_Mode<XTEA>::Decryption);
			case Mode::cbc: return encryption ? (SymmetricCipher*)(new CBC_Mode<XTEA>::Encryption) : (new CBC_Mode<XTEA>::Decryption);
			case Mode::cfb: return encryption ? (SymmetricCipher*)(new CFB_Mode<XTEA>::Encryption) : (new CFB_Mode<XTEA>::Decryption);
			case Mode::ofb: return encryption ? (SymmetricCipher*)(new OFB_Mode<XTEA>::Encryption) : (new OFB_Mode<XTEA>::Decryption);
			case Mode::ctr: return encryption ? (SymmetricCipher*)(new CTR_Mode<XTEA>::Encryption) : (new CTR_Mode<XTEA>::Decryption);
			}
			break;
		}
		case Cipher::sosemanuk:
		{
			return encryption ? (SymmetricCipher*)(new Sosemanuk::Encryption) : (new Sosemanuk::Decryption);
		}
		case Cipher::rc4:
		{
			return encryption ? (SymmetricCipher*)(new Weak::ARC4::Encryption) : (new Weak::ARC4::Decryption);
		}
		case Cipher::salsa20:
		{
			return encryption ? (SymmetricCipher*)(new Salsa20::Encryption) : (new Salsa20::Decryption);
		}
		case Cipher::xsalsa20:
		{
			return encryption ? (SymmetricCipher*)(new XSalsa20::Encryption) : (new XSalsa20::Decryption);
		}
		case Cipher::chacha20:
		{
			return encryption ? (SymmetricCipher*)(new ChaCha20::Encryption) : (new ChaCha20::Decryption);
		}
		case Cipher::panama:
		{
			return encryption ? (SymmetricCipher*)(new PanamaCipher<LittleEndian>::Encryption) : (new PanamaCipher<LittleEndian>::Decryption);
		}
		case Cipher::wake:
		{
			return encryption ? (SymmetricCipher*)(new WAKE_OFB<LittleEndian>::Encryption) : (new WAKE_OFB<LittleEndian>::Decryption);
		}
		case Cipher::seal:
		{
			return encryption ? (SymmetricCipher*)(new SEAL<LittleEndian>::Encryption) : (new SEAL<LittleEndian>::Decryption);
		}
		}
		return NULL;
	}

	CryptoPP::HashTransformation* getHashTransformation(crypt::Options::Hash options)
	{
		using namespace CryptoPP;

		if (options.use_key) {
			switch (options.algorithm) {
			case Hash::blake2b:
			{
				if (options.digest_length < 1 || options.digest_length > 64) {
					options.digest_length = 32;
				}
				return new BLAKE2b(options.key.BytePtr(), options.key.size(), NULL, 0, NULL, 0Ui64, false, (unsigned int)options.digest_length);
				break;
			}
			case Hash::blake2s:
			{
				if (options.digest_length < 1 && options.digest_length > 32) {
					options.digest_length = 32;
				}
				return new BLAKE2s(options.key.BytePtr(), options.key.size(), NULL, 0, NULL, 0Ui64, false, (unsigned int)options.digest_length);
				break;
			}
			case Hash::cmac_aes:
				options.digest_length = 16;
				return new CMAC<AES>(options.key.BytePtr(), options.key.size());
			case Hash::keccak:
			{
				if (options.digest_length == 28) {
					return new HMAC<Keccak_224>(options.key.BytePtr(), options.key.size());
				} else if (options.digest_length == 32) {
					return new HMAC<Keccak_256>(options.key.BytePtr(), options.key.size());
				} else if (options.digest_length == 48) {
					return new HMAC<Keccak_384>(options.key.BytePtr(), options.key.size());
				} else if (options.digest_length == 64) {
					return new HMAC<Keccak_512>(options.key.BytePtr(), options.key.size());
				} else {
					options.digest_length = 32;
					return new HMAC<Keccak_256>(options.key.BytePtr(), options.key.size());
				}
				break;
			}
			case Hash::md2:
			{
				options.digest_length = 16;
				return new HMAC<Weak::MD2>(options.key.BytePtr(), options.key.size());
			}
			case Hash::md4:
			{
				options.digest_length = 16;
				return new HMAC<Weak::MD4>(options.key.BytePtr(), options.key.size());
			}
			case Hash::md5:
			{
				options.digest_length = 16;
				return new HMAC<Weak::MD5>(options.key.BytePtr(), options.key.size());
			}
			case Hash::ripemd:
			{
				if (options.digest_length == 16) {
					return new HMAC<RIPEMD128>(options.key.BytePtr(), options.key.size());
				} else if (options.digest_length == 20) {
					return new HMAC<RIPEMD160>(options.key.BytePtr(), options.key.size());
				} else if (options.digest_length == 32) {
					return new HMAC<RIPEMD256>(options.key.BytePtr(), options.key.size());
				} else if (options.digest_length == 40) {
					return new HMAC<RIPEMD320>(options.key.BytePtr(), options.key.size());
				} else {
					options.digest_length = 32;
					return new HMAC<RIPEMD256>(options.key.BytePtr(), options.key.size());
				}
				break;
			}
			case Hash::sha1:
			{
				options.digest_length = 20;
				return new HMAC<SHA1>(options.key.BytePtr(), options.key.size());
			}
			case Hash::sha2:
			{
				if (options.digest_length == 28) {
					return new HMAC<SHA224>(options.key.BytePtr(), options.key.size());
				} else if (options.digest_length == 32) {
					return new HMAC<SHA256>(options.key.BytePtr(), options.key.size());
				} else if (options.digest_length == 48) {
					return new HMAC<SHA384>(options.key.BytePtr(), options.key.size());
				} else if (options.digest_length == 64) {
					return new HMAC<SHA512>(options.key.BytePtr(), options.key.size());
				} else {
					options.digest_length = 32;
					return new HMAC<SHA256>(options.key.BytePtr(), options.key.size());
				}
				break;
			}
			case Hash::sha3:
			{
				if (options.digest_length == 28) {
					return new HMAC<SHA3_224>(options.key.BytePtr(), options.key.size());
				} else if (options.digest_length == 32) {
					return new HMAC<SHA3_256>(options.key.BytePtr(), options.key.size());
				} else if (options.digest_length == 48) {
					return new HMAC<SHA3_384>(options.key.BytePtr(), options.key.size());
				} else if (options.digest_length == 64) {
					return new HMAC<SHA3_512>(options.key.BytePtr(), options.key.size());
				} else {
					options.digest_length = 32;
					return new HMAC<SHA3_256>(options.key.BytePtr(), options.key.size());
				}
				break;
			}
			case Hash::siphash24:
			{
				if (options.digest_length == 8) {
					return new SipHash<2, 4, false>(options.key.BytePtr(), (unsigned int)options.key.size());
				} else if (options.digest_length == 16) {
					return new SipHash<2, 4, true>(options.key.BytePtr(), (unsigned int)options.key.size());
				} else {
					options.digest_length = 16;
					return new SipHash<2, 4, true>(options.key.BytePtr(), (unsigned int)options.key.size());
				}
				break;
			}
			case Hash::siphash48:
			{
				if (options.digest_length == 8) {
					return new SipHash<4, 8, false>(options.key.BytePtr(), (unsigned int)options.key.size());
				} else if (options.digest_length == 16) {
					return new SipHash<4, 8, true>(options.key.BytePtr(), (unsigned int)options.key.size());
				} else {
					options.digest_length = 16;
					return new SipHash<4, 8, true>(options.key.BytePtr(), (unsigned int)options.key.size());
				}
				break;
			}
			case Hash::sm3:
			{
				options.digest_length = 32;
				return new HMAC<SM3>(options.key.BytePtr(), options.key.size());
			}
			case Hash::tiger:
			{
				options.digest_length = 24;
				return new HMAC<Tiger>(options.key.BytePtr(), options.key.size());
				break;
			}
			case Hash::whirlpool:
			{
				options.digest_length = 64;
				return new HMAC<Whirlpool>(options.key.BytePtr(), options.key.size());
			}
			}
		} else {
			switch (options.algorithm) {
			case Hash::adler32:
			{
				options.digest_length = 4;
				return new Adler32;
			}
			case Hash::blake2b:
			{
				if (options.digest_length < 1 || options.digest_length > 64) {
					options.digest_length = 32;
				}
				return new BLAKE2b(false, (unsigned int)options.digest_length);
				break;
			}
			case Hash::blake2s:
			{
				if (options.digest_length < 1 || options.digest_length > 32) {
					options.digest_length = 32;
				}
				return new BLAKE2s(false, (unsigned int)options.digest_length);
				break;
			}
			case Hash::crc32:
			{
				options.digest_length = 4;
				return new CRC32;
			}
			case Hash::keccak:
			{
				if (options.digest_length == 28) {
					return new Keccak_224;
				} else if (options.digest_length == 32) {
					return new Keccak_256;
				} else if (options.digest_length == 48) {
					return new Keccak_384;
				} else if (options.digest_length == 64) {
					return new Keccak_512;
				} else {
					options.digest_length = 32;
					return new Keccak_256;
				}
				break;
			}
			case Hash::md2:
			{
				options.digest_length = 16;
				return new Weak::MD2;
			}
			case Hash::md4:
			{
				options.digest_length = 16;
				return new Weak::MD4;
			}
			case Hash::md5:
			{
				options.digest_length = 16;
				return new Weak::MD5;
			}
			case Hash::ripemd:
			{
				if (options.digest_length == 16) {
					return new RIPEMD128;
				} else if (options.digest_length == 20) {
					return new RIPEMD160;
				} else if (options.digest_length == 32) {
					return new RIPEMD256;
				} else if (options.digest_length == 40) {
					return new RIPEMD320;
				} else {
					options.digest_length = 32;
					return new RIPEMD256;
				}
				break;
			}
			case Hash::sha1:
			{
				options.digest_length = 20;
				return new SHA1;
			}
			case Hash::sha2:
			{
				if (options.digest_length == 28) {
					return new SHA224;
				} else if (options.digest_length == 32) {
					return new SHA256;
				} else if (options.digest_length == 48) {
					return new SHA384;
				} else if (options.digest_length == 64) {
					return new SHA512;
				} else {
					options.digest_length = 32;
					return new SHA256;
				}
				break;
			}
			case Hash::sha3:
			{
				if (options.digest_length == 28) {
					return new SHA3_224;
				} else if (options.digest_length == 32) {
					return new SHA3_256;
				} else if (options.digest_length == 48) {
					return new SHA3_384;
				} else if (options.digest_length == 64) {
					return new SHA3_512;
				} else {
					options.digest_length = 32;
					return new SHA3_256;
				}
				break;
			}
			case Hash::sm3:
			{
				options.digest_length = 32;
				return new SM3;
			}
			case Hash::tiger:
			{
				options.digest_length = 24;
				return new Tiger;
			}
			case Hash::whirlpool:
			{
				options.digest_length = 64;
				return new Whirlpool;
			}
			}
		}
		return NULL;
	}

	void calcKey(CryptoPP::SecByteBlock& key, const UserData& password, const UserData& salt, const crypt::Options::Crypt::Key& opt)
	{
		using namespace CryptoPP;
		switch (opt.algorithm)
		{
		case KeyDerivation::pbkdf2:
		{
			std::unique_ptr<PasswordBasedKeyDerivationFunction> pbkdf2(getKeyDerivation(Hash(opt.options[0]), opt.options[1]));
			if (!pbkdf2) {
				throw CExc(CExc::Code::invalid_pbkdf2_hash);
			}
			pbkdf2->DeriveKey(&key[0], key.size(), password.BytePtr(), password.size(),	MakeParameters(Name::Salt(), ConstByteArrayParameter(salt.BytePtr(), salt.size()))("Iterations", opt.options[2]));
			break;
		}
		case KeyDerivation::bcrypt:
		{
			char output[64];
			char settings[32];

			if (_crypt_gensalt_blowfish_rn("$2a$", (unsigned long)opt.options[0], (const char*)salt.BytePtr(), 16, settings, 32) == NULL) {
				throw CExc(CExc::Code::bcrypt_failed);
			}
			memset(output, 0, sizeof(output));
			// _crypt_blowfish_rn needs 0-terminated password...
			std::string temp(password.size() + 1, 0);
			memcpy(&temp[0], password.BytePtr(), password.size());
			if (_crypt_blowfish_rn(temp.c_str(), settings, output, 64) == NULL) {
				throw CExc(CExc::Code::bcrypt_failed);
			}
			byte hashdata[23];
			ArraySource ss((const byte*)output + 29, 31, true, new Base64Decoder(new ArraySink(hashdata, 23)));
			shake128(hashdata, 23, &key[0], key.size());
			memset(output, 0, sizeof(output));
			memset(settings, 0, sizeof(settings));
			memset(hashdata, 0, sizeof(hashdata));
			for (size_t i = 0; i < temp.size(); i++) {
				temp[i] = 0;
			}
			break;
		}
		case KeyDerivation::scrypt:
		{
			if (crypto_scrypt(password.BytePtr(), password.size(), salt.BytePtr(), salt.size(), ipow(2, opt.options[0]), opt.options[1], opt.options[2], &key[0], key.size()) != 0) {
				throw CExc(CExc::Code::scrypt_failed);
			}
			break;
		}
		}
	}

}
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
	if (data.size()) {
		return data.BytePtr();
	} else {
		return NULL;
	}
}

size_t crypt::UserData::size() const
{
	return data.size();
}

size_t crypt::UserData::set(const UserData& s)
{
	data.Assign(s.BytePtr(), s.size());
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
		} else if (enc == Encoding::base32) {
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
		} else if (enc == Encoding::base32) {
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



bool crypt::UserData::random(size_t length, Restriction k, bool blocking)
{
	if (length > 0 && length <= Constants::rand_char_max) {
		data.resize(length);
		switch (k) {
		case Restriction::none:
		{
			CryptoPP::OS_GenerateRandomBlock(blocking, &data[0], length);
			break;
		}
		case Restriction::specials:
		{
			CryptoPP::AutoSeededRandomPool pool;
			for (size_t i = 0; i < length; i++) {
				data[i] = (byte)CryptoPP::Integer(pool, 33, 126).ConvertToLong();
			}
			break;
		}
		case Restriction::alphanum:
		{
			CryptoPP::AutoSeededRandomPool pool;
			for (size_t i = 0; i < length; i++) {
				long temp = CryptoPP::Integer(pool, 0, 61).ConvertToLong();
				if (temp < 10) {
					data[i] = (byte)(48 + temp);
				} else if (temp < 36) {
					data[i] = (byte)(55 + temp);
				} else {
					data[i] = (byte)(61 + temp);
				}
			}
			break;
		}
		case Restriction::digits:
		{
			CryptoPP::AutoSeededRandomPool pool;
			for (size_t i = 0; i < length; i++) {
				data[i] = (byte)CryptoPP::Integer(pool, 48, 57).ConvertToLong();
			}
			break;
		}
		case Restriction::letters:
		{
			CryptoPP::AutoSeededRandomPool pool;
			for (size_t i = 0; i < length; i++) {
				data[i] = (byte)CryptoPP::Integer(pool, 65, 90).ConvertToLong();
			}
			break;
		}
		case Restriction::password:
		{
			CryptoPP::AutoSeededRandomPool pool;
			for (size_t i = 0; i < length; i++) {
				long temp = CryptoPP::Integer(pool, 0, 67).ConvertToLong();
				if (temp < 10) {
					data[i] = (byte)(48 + temp);
				} else if (temp < 36) {
					data[i] = (byte)(55 + temp);
				} else if (temp < 62) {
					data[i] = (byte)(61 + temp); 
				} else {
					static const char password_chars[] = { '-', '_', '?', '!', '$', ':' };
					data[i] = password_chars[temp - 62];
				}
			}
			break;
		}
		}		
		return true;
	}
	return false;
}

bool crypt::UserData::zero(size_t length)
{
	if (length > 0 && length <= 4096) {
		data.Assign(length, 0);
		return true;
	}
	return false;
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
			} else if (enc == Encoding::base32) {
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
			} else if (enc == Encoding::base32) {
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

bool crypt::getCipherInfo(crypt::Cipher cipher, crypt::Mode mode, size_t& key_length, size_t& iv_length, size_t& block_size)
{
	using namespace CryptoPP;
	switch (cipher)
	{
	case Cipher::threeway:
		block_size = iv_length = ThreeWay::BLOCKSIZE;
		key_length = ThreeWay::KEYLENGTH;
		break;
	case Cipher::aria:
		block_size = iv_length = ARIA::BLOCKSIZE;
		key_length = (key_length == 0) ? ARIA::DEFAULT_KEYLENGTH : ARIA::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::blowfish:
		block_size = iv_length = Blowfish::BLOCKSIZE;
		key_length = (key_length == 0) ? Blowfish::DEFAULT_KEYLENGTH : Blowfish::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::camellia:
		block_size = iv_length = Camellia::BLOCKSIZE;
		key_length = (key_length == 0) ? Camellia::DEFAULT_KEYLENGTH : Camellia::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::cast128:
		block_size = iv_length = CAST128::BLOCKSIZE;
		key_length = (key_length == 0) ? CAST128::DEFAULT_KEYLENGTH : CAST128::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::cast256:
		block_size = iv_length = CAST256::BLOCKSIZE;
		key_length = (key_length == 0) ? CAST256::DEFAULT_KEYLENGTH : CAST256::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::chacha20:
		block_size = 0;
		iv_length = ChaCha20::IV_LENGTH;
		key_length = (key_length == 0) ? ChaCha20::DEFAULT_KEYLENGTH : ChaCha20::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::des:
		block_size = iv_length = DES::BLOCKSIZE;
		key_length = DES::KEYLENGTH;
		break;
	case Cipher::des_ede2:
		block_size = iv_length = DES_EDE2::BLOCKSIZE;
		key_length = DES_EDE2::KEYLENGTH;
		break;
	case Cipher::des_ede3:
		block_size = iv_length = DES_EDE3::BLOCKSIZE;
		key_length = DES_EDE3::KEYLENGTH;
		break;
	case Cipher::desx:
		block_size = iv_length = DES_XEX3::BLOCKSIZE;
		key_length = DES_XEX3::KEYLENGTH;
		break;
	case Cipher::gost:
		block_size = iv_length = GOST::BLOCKSIZE;
		key_length = GOST::KEYLENGTH;
		break;
	case Cipher::idea:
		block_size = iv_length = IDEA::BLOCKSIZE;
		key_length = IDEA::KEYLENGTH;
		break;
	case Cipher::kalyna128:
		block_size = iv_length = Kalyna128::BLOCKSIZE;
		key_length = (key_length == 0) ? Kalyna128::DEFAULT_KEYLENGTH : Kalyna128::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::kalyna256:
		block_size = iv_length = Kalyna256::BLOCKSIZE;
		key_length = (key_length == 0) ? Kalyna256::DEFAULT_KEYLENGTH : Kalyna256::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::kalyna512:
		block_size = iv_length = 64;
		key_length = 64;
		break;
	case Cipher::mars:
		block_size = iv_length = MARS::BLOCKSIZE;
		key_length = (key_length == 0) ? MARS::DEFAULT_KEYLENGTH : MARS::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::panama:
		block_size = 0;
		key_length = PanamaCipher<LittleEndian>::KEYLENGTH;
		iv_length = PanamaCipher<LittleEndian>::IV_LENGTH;
		break;
	case Cipher::rc2:
		block_size = iv_length = RC2::BLOCKSIZE;
		key_length = (key_length == 0) ? RC2::DEFAULT_KEYLENGTH : RC2::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::rc4:
		block_size = iv_length = 0;
		key_length = (key_length == 0) ? Weak::ARC4::DEFAULT_KEYLENGTH : Weak::ARC4::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::rc5:
		block_size = iv_length = RC5::BLOCKSIZE;
		key_length = (key_length == 0) ? RC5::DEFAULT_KEYLENGTH : RC5::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::rc6:
		block_size = iv_length = RC6::BLOCKSIZE;
		key_length = (key_length == 0) ? RC6::DEFAULT_KEYLENGTH : RC6::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::rijndael:
		block_size = iv_length = AES::BLOCKSIZE;
		key_length = (key_length == 0) ? 32 : AES::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::saferk:
		block_size = iv_length = SAFER_K::BLOCKSIZE;
		key_length = (key_length == 0) ? SAFER_K::DEFAULT_KEYLENGTH : SAFER_K::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::safersk:
		block_size = iv_length = SAFER_SK::BLOCKSIZE;
		key_length = (key_length == 0) ? SAFER_SK::DEFAULT_KEYLENGTH : SAFER_SK::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::salsa20:
		block_size = 0;
		iv_length = Salsa20::IV_LENGTH;
		key_length = (key_length == 0) ? Salsa20::DEFAULT_KEYLENGTH : Salsa20::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::seal:
		block_size = 0;
		iv_length = SEAL<LittleEndian>::IV_LENGTH;
		key_length = SEAL<LittleEndian>::KEYLENGTH;
		break;
	case Cipher::seed:
		block_size = iv_length = SEED::BLOCKSIZE;
		key_length = SEED::KEYLENGTH;
		break;
	case Cipher::serpent:
		block_size = iv_length = Serpent::BLOCKSIZE;
		key_length = (key_length == 0) ? Serpent::DEFAULT_KEYLENGTH : Serpent::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::shacal2:
		block_size = iv_length = SHACAL2::BLOCKSIZE;
		key_length = (key_length == 0) ? SHACAL2::DEFAULT_KEYLENGTH : SHACAL2::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::shark:
		block_size = iv_length = SHARK::BLOCKSIZE;
		key_length = SHARK::KEYLENGTH;
		break;
	case Cipher::simon128:
		block_size = iv_length = SIMON128::BLOCKSIZE;
		key_length = (key_length == 0) ? SIMON128::DEFAULT_KEYLENGTH : SIMON128::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::skipjack:
		block_size = iv_length = SKIPJACK::BLOCKSIZE;
		key_length = SKIPJACK::KEYLENGTH;
		break;
	case Cipher::sm4:
		block_size = iv_length = SM4::BLOCKSIZE;
		key_length = SM4::KEYLENGTH;
		break;
	case Cipher::sosemanuk:
		block_size = 0;
		iv_length = Sosemanuk::IV_LENGTH;
		key_length = (key_length == 0) ? Sosemanuk::DEFAULT_KEYLENGTH : Sosemanuk::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::speck128:
		block_size = iv_length = SPECK128::BLOCKSIZE;
		key_length = (key_length == 0) ? SPECK128::DEFAULT_KEYLENGTH : SPECK128::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::square:
		block_size = iv_length = Square::BLOCKSIZE;
		key_length = Square::KEYLENGTH;
		break;
	case Cipher::tea:
		block_size = iv_length = TEA::BLOCKSIZE;
		key_length = TEA::KEYLENGTH;
		break;
	case Cipher::threefish256:
		block_size = iv_length = Threefish256::BLOCKSIZE;
		key_length = Threefish256::KEYLENGTH;
		break;
	case Cipher::threefish512:
		block_size = iv_length = 64;
		key_length = 64;
		break;
	case Cipher::threefish1024:
		block_size = iv_length = 128;
		key_length = 128;
		break;
	case Cipher::twofish:
		block_size = iv_length = Twofish::BLOCKSIZE;
		key_length = (key_length == 0) ? Twofish::DEFAULT_KEYLENGTH : Twofish::StaticGetValidKeyLength(key_length);
		break;
	case Cipher::wake:
		block_size = iv_length = 0;
		key_length = WAKE_OFB<LittleEndian>::KEYLENGTH;
		break;
	case Cipher::xsalsa20:
		block_size = 0;
		iv_length = XSalsa20::IV_LENGTH;
		key_length = XSalsa20::KEYLENGTH;
		break;
	case Cipher::xtea:
		block_size = iv_length = XTEA::BLOCKSIZE;
		key_length = XTEA::KEYLENGTH;
		break;
	}
	if (block_size > 0) {
		if (mode == Mode::ccm) {
			iv_length = Constants::ccm_iv_length;
		} else if (mode == Mode::ecb) {
			iv_length = 0;
		}
	}
	return true;
}

bool crypt::getHashInfo(Hash h, size_t& length, size_t& keylength)
{
	using namespace CryptoPP;
	keylength = 0;
	switch (h) {
	case Hash::adler32: length = 4; break;
	case Hash::blake2b:
	{
		if (length < 1 || length > 64) {
			length = 64;
		}
		break;
	}
	case Hash::blake2s:
	{
		if (length < 1 || length > 32) {
			length = 32;
		}
		break;
	}
	case Hash::cmac_aes: length = 16; keylength = 16; break;
	case Hash::crc32: length = 4; break;
	case Hash::keccak:
	{
		if (length != 28 && length != 32 && length != 48 && length != 64) {
			length = 32;
		}
		break;
	}
	case Hash::md2: length = 16; break;
	case Hash::md4: length = 16; break;
	case Hash::md5: length = 16; break;
	case Hash::ripemd:
	{
		if (length != 16 && length != 20 && length != 32 && length != 40) {
			length = 32;
		}
		break;
	}
	case Hash::sha1: length = 20; break;
	case Hash::sha2:
	{
		if (length != 28 && length != 32 && length != 48 && length != 64) {
			length = 32;
		}
		break;
	}
	case Hash::sha3:
	{
		if (length != 28 && length != 32 && length != 48 && length != 64) {
			length = 32;
		}
		break;
	}
	case Hash::siphash24:
	{
		if (length != 8 && length != 16) {
			length = 16;
		}
		keylength = 16;
		break;
	}
	case Hash::siphash48:
	{
		if (length != 8 && length != 16) {
			length = 16;
		}
		keylength = 16;
		break;
	}
	case Hash::sm3: length = 32; break;
	case Hash::tiger:
	{
		if (length != 16 && length != 20 && length != 24) {
			length = 24;
		}
		break;
	}
	case Hash::whirlpool: length = 64; break;
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
	const byte*			ptVec = NULL;
	const byte*			ptSalt = NULL;
	size_t				key_len = options.key.length;
	size_t				block_size, iv_len;

	getCipherInfo(options.cipher, options.mode, key_len, iv_len, block_size);

	// --------------------------- prepare salt vector:
	if (options.key.salt_bytes > 0)	{
		if (options.key.algorithm == KeyDerivation::bcrypt && options.key.salt_bytes != 16) {
			throw CExc(CExc::Code::invalid_bcrypt_saltlength);
		}
		init.salt.random(options.key.salt_bytes);
		ptSalt = init.salt.BytePtr();
	}
	// --------------------------- prepare iv & key vector
	if (options.iv == crypt::IV::keyderivation) {
		tKey.resize(key_len + iv_len);
	} else {
		tKey.resize(key_len);
	}
	if (iv_len > 0) {
		switch (options.iv) {
		case IV::keyderivation:
			ptVec = &tKey[key_len];
			break;
		case IV::random:
			init.iv.random(iv_len);
			ptVec = init.iv.BytePtr();
			break;
		case IV::zero:
			init.iv.zero(iv_len);
			ptVec = init.iv.BytePtr();
			break;
		case IV::custom:
			if (iv_len != init.iv.size()) {
				throw CExc(CExc::Code::invalid_iv);
			}
			ptVec = init.iv.BytePtr();
			break;
		}
	}
	// --------------------------- calculate key
	intern::calcKey(tKey, options.password, init.salt, options.key);

	if (options.iv == IV::keyderivation) {
		init.iv.set(ptVec, iv_len);
	}

	try	{
		if (block_size && (options.mode == Mode::gcm || options.mode == Mode::ccm || options.mode == Mode::eax)) {
			std::unique_ptr<AuthenticatedSymmetricCipher> penc(intern::getAuthenticatedCipher(options.cipher, options.mode, true));
			if (!penc) {
				throw CExc(CExc::Code::invalid_mode);
			}
			int tag_size;
			switch (options.mode)
			{
			case Mode::gcm: tag_size = Constants::gcm_tag_size; break;
			case Mode::ccm: tag_size = Constants::ccm_tag_size;  break;
			case Mode::eax: tag_size = Constants::eax_tag_size;  break;
			}

			penc->SetKeyWithIV(tKey.data(), key_len, ptVec, iv_len);
			if (penc->NeedsPrespecifiedDataLengths()) {
				penc->SpecifyDataLengths(init.salt.size() + init.iv.size(), in_len, 0);
			}

			AuthenticatedEncryptionFilter ef(*penc, NULL, false, tag_size );
			std::basic_string<byte> temp;
			if (options.encoding.enc == Encoding::ascii) {
				ef.Attach(new StringSinkTemplate<std::basic_string<byte>>(buffer));
			} else {
				ef.Attach(new StringSinkTemplate<std::basic_string<byte>>(temp));
			}

			ef.ChannelPut( AAD_CHANNEL, init.salt.BytePtr(), init.salt.size());
			ef.ChannelPut( AAD_CHANNEL, init.iv.BytePtr(), init.iv.size());
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
				if (options.encoding.enc == Encoding::base16) {
					StringSource(temp.data(), temp.size() - tag_size, true, new HexEncoder(new StringSinkTemplate<std::basic_string<byte>>(buffer),
						options.encoding.uppercase, linelength, Strings::eol[(int)options.encoding.eol]));
				} else {
					StringSource(temp.data(), temp.size() - tag_size, true, new Base32Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer),
						options.encoding.uppercase, linelength, Strings::eol[(int)options.encoding.eol]));
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
			std::unique_ptr<SymmetricCipher> pEnc(intern::getSymmetricCipher(options.cipher, options.mode, true));
			if (!pEnc) {
				throw CExc(CExc::Code::invalid_mode);
			}
			if (iv_len == 0) {
				pEnc->SetKey(tKey.data(), key_len);
			} else {
				pEnc->SetKeyWithIV(tKey.data(), key_len, ptVec, iv_len);
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
				if (options.encoding.enc == Encoding::base16) {
					StringSource(in, in_len, true, new StreamTransformationFilter(*pEnc,
						new HexEncoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.encoding.uppercase, linelength, Strings::eol[(int)options.encoding.eol])));
				} else {
					StringSource(in, in_len, true, new StreamTransformationFilter(*pEnc,
							new Base32Encoder(new StringSinkTemplate<std::basic_string<byte>>(buffer), options.encoding.uppercase, linelength, Strings::eol[(int)options.encoding.eol])));
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

void crypt::decrypt(const byte* in, size_t in_len, std::basic_string<byte>& buffer, const Options::Crypt& options, InitData& init)
{
	if (!in || !in_len) {
		throw CExc(CExc::Code::input_null);
	}

	using namespace crypt;
	using namespace	CryptoPP;

	SecByteBlock		tKey;
	const byte*			ptVec = NULL;
	const byte*			ptSalt = NULL;
	size_t				key_len = options.key.length;
	size_t				block_size, iv_len;

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

	// --------------------------- prepare iv vector & key-block:
	tKey.resize(key_len);
	if (iv_len > 0) {
		if (!init.iv.size()) {
			throw CExc(CExc::Code::iv_missing);
		}
		if (init.iv.size() != iv_len) {
			throw CExc(CExc::Code::invalid_iv);
		}
		ptVec = init.iv.BytePtr();
	}

	// --------------------------- calculate key:
	intern::calcKey(tKey, options.password, init.salt, options.key);

	try	{
		if (block_size && (options.mode == Mode::gcm || options.mode == Mode::ccm || options.mode == Mode::eax)) {
			std::unique_ptr<AuthenticatedSymmetricCipher> penc(intern::getAuthenticatedCipher(options.cipher, options.mode, false));

			int tag_size;
			switch (options.mode)
			{
			case Mode::gcm: tag_size = Constants::gcm_tag_size; break;
			case Mode::ccm: tag_size = Constants::ccm_tag_size;  break;
			case Mode::eax: tag_size = Constants::eax_tag_size;  break;
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
			df.ChannelPut( AAD_CHANNEL, init.salt.BytePtr(), init.salt.size());
			df.ChannelPut( AAD_CHANNEL, init.iv.BytePtr(), init.iv.size());
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
			std::unique_ptr<SymmetricCipher> pEnc(intern::getSymmetricCipher(options.cipher, options.mode, false));
			if (!pEnc) {
				throw CExc(CExc::Code::invalid_mode);
			}
			if (iv_len == 0) {
				pEnc->SetKey(tKey.data(), key_len);
			} else {
				pEnc->SetKeyWithIV(tKey.data(), key_len, ptVec, iv_len);
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

void crypt::hash(Options::Hash& options, std::basic_string<byte>& buffer, std::initializer_list<std::pair<const byte*, size_t>> in)
{
	try	{
		using namespace CryptoPP;
		using namespace std;

		size_t keylength;
		if (!getHashInfo(options.algorithm, options.digest_length, keylength)) {
			throw CExc(CExc::Code::invalid_hash);
		}
		if (keylength != 0 && options.use_key && options.key.size() != keylength) {
			throw CExc(CExc::Code::invalid_keylength);
		}

		SecByteBlock digest;
		std::unique_ptr<HashTransformation> phash(intern::getHashTransformation(options));
		if (!phash) {
			throw CExc(CExc::Code::invalid_hash);
		}
		digest.resize(phash->DigestSize());
		for (const std::pair<const byte*, size_t>& i : in) {
			phash->Update(i.first, i.second);
		}
		phash->Final(digest);

		buffer.clear();
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

void crypt::hash(Options::Hash& options, std::basic_string<byte>& buffer, const std::string& path)
{
	try {
		using namespace CryptoPP;
		using namespace std;

		SecByteBlock digest;
		std::unique_ptr<HashTransformation> phash(intern::getHashTransformation(options));
		if (!phash) {
			throw CExc(CExc::Code::invalid_hash);
		}
		digest.resize(phash->DigestSize());

		FileSource f(path.c_str(), true, new HashFilter(*phash, new ArraySink(digest, digest.size())));

		buffer.clear();
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

