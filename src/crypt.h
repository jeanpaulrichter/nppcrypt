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


#ifndef CRYPT_DEFINE_H
#define CRYPT_DEFINE_H

#include <string>
#include <vector>
#include "exception.h"

// -------------------------------------------------------------------------------------------------------------------------

namespace crypt
{
	enum class Cipher : unsigned {
		des=0, des_ede,	des_ede3, desx,	rc2, rc4, rc5, idea, blowfish, cast5, aes128, aes192, aes256, COUNT
	};
	
	enum class Mode : unsigned {
		ecb=0, cbc,	cfb, ofb, ctr, xts,	ccm, gcm, COUNT 
	};

	enum class Hash: unsigned {
		md4=0, md5, mdc2, sha1, sha256, sha512, ripemd160, whirlpool, sha3_256, sha3_384, sha3_512, COUNT
	};

	enum class Encoding : unsigned {
		ascii=0, base16, base64, COUNT
	};

	enum class KeyDerivation : unsigned {
		pbkdf2=0, bcrypt, scrypt, COUNT
	};

	enum class IV : unsigned {
		random=0, keyderivation, zero, COUNT
	};

	enum class Random: unsigned {
		charnum=0, specials, ascii,	base16, base64, COUNT
	};

	namespace Constants
	{
		const int pw_length_max =		50;				// max password characters
		const int salt_bytes_max =		128;			// max salt bytes
		const int pbkdf2_default_hash = 1;				// pbkdf2: default hash ( see enum Hash )
		const int pbkdf2_iter_default = 1000;			// pbkdf2: default iterations
		const int pbkdf2_iter_min =		1;				// pbkdf2: min iterations 
		const int pbkdf2_iter_max =		32000;			// pbkdf2: max iterations
		const int bcrypt_iter_default = 8;				// bcrypt: default iterations (2^x)
		const int bcrypt_iter_min =		4;				// bcrypt: min iterations (2^x)
		const int bcrypt_iter_max =		24;				// bcrypt: max iterations (2^x)
		const int scrypt_N_default =	14;				// scrypt: default N (2^x)
		const int scrypt_N_min =		2;				// scrypt: min N (2^x)
		const int scrypt_N_max =		24;				// scrypt: max N (2^x)
		const int scrypt_r_default =	8;				// scrypt: default r
		const int scrypt_r_min =		1;				// scrypt: min r
		const int scrypt_r_max =		99;				// scrypt: max r
		const int scrypt_p_default =	1;				// scrypt: default p
		const int scrypt_p_min =		1;				// scrypt: min r
		const int scrypt_p_max =		99;				// scrypt: max r
		const int gcm_iv_length =		16;				// IV-Length for gcm mode (aes)
		const int ccm_iv_length =		8;				// IV-Length for ccm mode (aes), possible values: 7-13
		const int rand_char_max =		4096;			// max number of random chars [getRandom()]
		const int rand_char_bufsize =	1024;			// buffersize of getRandom()
	};

	namespace Options
	{
		struct Crypt
		{
			Crypt() : cipher(Cipher::aes256), mode(Mode::gcm), encoding(Encoding::base64), iv(IV::random)
			{
				key.salt_bytes = 16; key.algorithm = KeyDerivation::scrypt; key.option1 = Constants::scrypt_N_default; key.option2 = Constants::scrypt_r_default;
				key.option3 = Constants::scrypt_p_default; hmac.enable = false; hmac.hash = crypt::Hash::sha256;
			};

			crypt::Cipher			cipher;
			crypt::Mode				mode;
			crypt::Encoding			encoding;
			crypt::IV				iv;
			std::string				password;

			struct
			{
				KeyDerivation	algorithm;
				int				salt_bytes;
				int				option1;
				int				option2;
				int				option3;
			} key;

			struct
			{
				bool						enable;
				crypt::Hash					hash;
				std::vector<unsigned char>	key;
				std::string					key_input;
				int							key_id;
			} hmac;
		};

		struct Hash
		{
			Hash() : encoding(Encoding::base16), algorithm(crypt::Hash::md5), use_key(false) {};

			crypt::Hash					algorithm;
			Encoding					encoding;
			bool						use_key;
			std::vector<unsigned char>	key;
			std::string					key_input;
			int							key_id;
		};

		struct Random
		{
			Random() : mode(crypt::Random::specials), length(16) {};

			crypt::Random	mode;
			size_t			length;
		};
	};

	struct InitStrings
	{
		Encoding	encoding;
		std::string iv;
		std::string salt;
		std::string tag;
	};
	
	void encrypt(const unsigned char* in, size_t in_len, std::vector<unsigned char>& buffer, const Options::Crypt& options, InitStrings& init);
	void decrypt(const unsigned char* in, size_t in_len, std::vector<unsigned char>& buffer, const Options::Crypt& options, const InitStrings& init);
	void hash(const unsigned char* in, size_t in_len, std::vector<unsigned char>& buffer, const Options::Hash& options);
	void hmac(const unsigned char* in, size_t in_len, const Options::Hash& options, std::vector<unsigned char>& out);
	void hmac_header(const char* a, size_t a_len, const unsigned char* b, size_t b_len, Hash algo, const unsigned char* key, size_t key_len, std::string& out);
	void shake128(const unsigned char* in, size_t in_len, unsigned char* out, size_t out_len);
	void random(const Options::Random& options, std::vector<unsigned char>& buffer);	
	size_t getHashLength(Hash h);

	class help 
	{
	public:
		static const char* getString(crypt::Cipher cipher);
		static const char* getString(crypt::Mode mode);
		static const char* getString(crypt::Encoding enc);
		static const char* getString(crypt::KeyDerivation k);
		static const char* getString(crypt::IV iv);
		static const char* getString(crypt::Hash h);
		static const char* getString(crypt::Random mode);

		static bool getCipher(const char* s, crypt::Cipher& c);
		static bool getCipherMode(const char* s, crypt::Mode& m);
		static bool getKeyDerivation(const char*s, crypt::KeyDerivation& v);
		static bool getEncoding(const char* s, crypt::Encoding& e);
		static bool getIVMode(const char* s, crypt::IV& iv);
		static bool getHash(const char* s, crypt::Hash& h, bool only_openssl = false);
		static bool getRandomMode(const char* s, crypt::Random& m);

		static crypt::Mode getModeByIndex(crypt::Cipher cipher, int index);
		static int getIndexByMode(crypt::Cipher cipher, crypt::Mode mode);
		static bool validCipherMode(crypt::Cipher cipher, crypt::Mode mode);

		// iteration through cipher/mode/hash-strings
		class Iterator {
		public:
			enum { Cipher, Mode, Hash };
			static void setup(int what, crypt::Cipher cipher);
			static void setup(int what, bool only_openssl = false);
			static bool next();
			static const TCHAR* getString();
		private:
			static int w;
			static int i;
			static int v;
		};
	};
};



#endif