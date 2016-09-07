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

#ifndef CRYPT_H_DEF
#define CRYPT_H_DEF

#include <string>
#include <vector>
#include "exception.h"

namespace crypt
{
	enum class Cipher : unsigned {
		des=0, des_ede,	des_ede3, desx, gost, cast128, cast256, rc2, rc4, rc5, rc6, idea, blowfish, camellia, seed, tea, xtea, shacal2, mars, twofish, serpent, rijndael128, rijndael192, rijndael256, sosemanuk, salsa20, xsalsa20, panama, COUNT
	};
	
	enum class Mode : unsigned {
		ecb, cbc, cbc_cts, cfb, ofb, ctr, eax, ccm, gcm, COUNT
	};

	enum class Hash: unsigned {
		md4=0, md5, sha1, sha256, sha512, ripemd128, ripemd160, ripemd256, whirlpool, tiger, HMAC_COUNT, sha3_224=HMAC_COUNT, sha3_256, sha3_384, sha3_512, COUNT
	};

	enum class Encoding : unsigned {
		ascii=0, base16, base32, base64, COUNT
	};

	enum class KeyDerivation : unsigned {
		pbkdf2=0, bcrypt, scrypt, COUNT
	};

	enum class IV : unsigned {
		random=0, keyderivation, zero, COUNT
	};

	enum class Random: unsigned {
		charnum=0, specials, ascii,	base16, base32, base64, COUNT
	};

	namespace Constants
	{
		const int password_max =		512;			// password: max number of characters
		const int salt_max =			512;			// max salt bytes
		const int pbkdf2_default_hash = 1;				// pbkdf2: default hash ( see enum Hash )
		const int pbkdf2_iter_default = 5000;			// pbkdf2: default iterations
		const int pbkdf2_iter_min =		1;				// pbkdf2: min iterations 
		const int pbkdf2_iter_max =		10000000;		// pbkdf2: max iterations
		const int bcrypt_iter_default = 8;				// bcrypt: default iterations (2^x)
		const int bcrypt_iter_min =		4;				// bcrypt: min iterations (2^x)
		const int bcrypt_iter_max =		32;				// bcrypt: max iterations (2^x)
		const int scrypt_N_default =	14;				// scrypt: default N (2^x)
		const int scrypt_N_min =		2;				// scrypt: min N (2^x)
		const int scrypt_N_max =		32;				// scrypt: max N (2^x)
		const int scrypt_r_default =	8;				// scrypt: default r
		const int scrypt_r_min =		1;				// scrypt: min r
		const int scrypt_r_max =		256;			// scrypt: max r
		const int scrypt_p_default =	1;				// scrypt: default p
		const int scrypt_p_min =		1;				// scrypt: min r
		const int scrypt_p_max =		256;			// scrypt: max r
		const int gcm_iv_length =		16;				// IV-Length for gcm mode (aes)
		const int ccm_iv_length =		8;				// IV-Length for ccm mode (aes), possible values: 7-13
		const int rand_char_max =		4096;			// max number of random chars [getRandom()]
		const int rand_char_bufsize =	1024;			// buffersize of getRandom()
		const int gcm_tag_size =		16;
		const int ccm_tag_size =		16;
		const int eax_tag_size =		16;
	};

	namespace Options
	{
		struct Crypt
		{
			Crypt() : cipher(Cipher::rijndael256), mode(Mode::gcm), iv(IV::random)
			{
				key.salt_bytes = 16; key.algorithm = KeyDerivation::scrypt; key.option1 = Constants::scrypt_N_default; key.option2 = Constants::scrypt_r_default;
				key.option3 = Constants::scrypt_p_default; hmac.enable = false; hmac.hash = crypt::Hash::tiger; hmac.key_id = 0;
				encoding.enc = crypt::Encoding::base64; encoding.linebreaks = true; encoding.linelength = 64; encoding.uppercase = true; encoding.windows = true;
			};

			crypt::Cipher			cipher;
			crypt::Mode				mode;
			crypt::IV				iv;
			std::string				password;

			struct Key
			{
				KeyDerivation	algorithm;
				int				salt_bytes;
				int				option1;
				int				option2;
				int				option3;
			};
			Key key;

			struct HMAC
			{
				HMAC& operator= (const HMAC &src) { 
					enable = src.enable; hash = src.hash; key_input.assign(src.key_input); key_id = src.key_id;	key.resize(src.key.size());
					for (size_t i = 0; i < key.size(); i++)
						key[i] = src.key[i];
					return *this;
				};

				bool						enable;
				crypt::Hash					hash;
				std::vector<unsigned char>	key;
				std::string					key_input;
				int							key_id;
			};			
			HMAC hmac;

			struct Encoding
			{
				crypt::Encoding		enc;
				bool				linebreaks;
				int					linelength;
				bool				windows;
				bool				uppercase;
			};
			Encoding encoding;
		};

		struct Hash
		{
			Hash() : encoding(crypt::Encoding::base16), algorithm(crypt::Hash::md5), use_key(false) {};

			crypt::Hash					algorithm;
			crypt::Encoding				encoding;
			bool						use_key;
			std::vector<byte>			key;
			std::string					key_input;
			int							key_id;
		};

		struct Random
		{
			Random() : mode(crypt::Random::specials), length(16) {};

			crypt::Random	mode;
			size_t			length;
		};

		struct Convert
		{
			Convert() : from(crypt::Encoding::ascii), to(crypt::Encoding::base64), linebreaks(true), windows(false), linelength(64), uppercase(true) {};

			crypt::Encoding	from;
			crypt::Encoding	to;
			bool			linebreaks;
			bool			windows;
			bool			uppercase;
			int				linelength;
		};
	};

	struct InitStrings
	{
		Encoding	encoding;
		std::string iv;
		std::string salt;
		std::string tag;
	};
	
	bool getCipherInfo(crypt::Cipher cipher, crypt::Mode mode, int& key_length, int& iv_length, int& block_size);
	void encrypt(const byte* in, size_t in_len, std::basic_string<byte>& buffer, const Options::Crypt& options, InitStrings& init);
	void decrypt(const byte* in, size_t in_len, std::basic_string<byte>& buffer, const Options::Crypt& options, const InitStrings& init);
	void hash(const byte* in, size_t in_len, std::basic_string<byte>& buffer, const Options::Hash& options);
	void hmac_header(const char* a, size_t a_len, const byte* b, size_t b_len, const Options::Crypt::HMAC& options, std::string& out);
	void shake128(const byte* in, size_t in_len, byte* out, size_t out_len);
	void random(const Options::Random& options, std::basic_string<byte>& buffer);
	void convert(const byte* in, size_t in_len, std::basic_string<byte>& buffer, const Options::Convert& options);
	size_t getHashLength(Hash h);

	class help 
	{
	public:
		enum CipherCat { aes, other, stream, weak, all };

		static const char*	getString(crypt::Cipher cipher);
		static const char*	getString(crypt::Mode mode);
		static const char*	getString(crypt::Encoding enc);
		static const char*	getString(crypt::KeyDerivation k);
		static const char*	getString(crypt::IV iv);
		static const char*	getString(crypt::Hash h);
		static const char*	getString(crypt::Random mode);

		static bool			getCipher(const char* s, crypt::Cipher& c);
		static bool			getCipherMode(const char* s, crypt::Mode& m);
		static bool			getKeyDerivation(const char*s, crypt::KeyDerivation& v);
		static bool			getEncoding(const char* s, crypt::Encoding& e);
		static bool			getIVMode(const char* s, crypt::IV& iv);
		static bool			getHash(const char* s, crypt::Hash& h, bool only_openssl = false);
		static bool			getRandomMode(const char* s, crypt::Random& m);

		static crypt::Mode	getModeByIndex(crypt::Cipher cipher, int index);
		static int			getIndexByMode(crypt::Cipher cipher, crypt::Mode mode);
		static bool			validCipherMode(crypt::Cipher cipher, crypt::Mode mode);
		static bool			canCalcHMAC(crypt::Hash h);
		static int			getCipherCategory(Cipher cipher);
		static Cipher		getCipherByIndex(CipherCat category, int index);
		static int			getCipherIndex(Cipher cipher);

		static const TCHAR* getHelpURL(crypt::Encoding enc);
		static const TCHAR* getHelpURL(crypt::Cipher cipher);
		static const TCHAR* getHelpURL(crypt::Mode m);
		static const TCHAR* getHelpURL(crypt::Hash h);
		static const TCHAR* getHelpURL(crypt::KeyDerivation k);

		// iteration through cipher/mode/hash-strings
		class Iter {
		public:
			static void setup_cipher(CipherCat category);
			static void setup_mode(Cipher cipher);
			static void setup_hash(bool hmac=false);
			static bool next();
			static const TCHAR* getString();
		private:
			static int _what;
			static int _cipher;
			static int _temp;
			static int i;
		};
	};
};

#endif