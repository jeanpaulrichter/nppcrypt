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

#ifndef CRYPT_H_DEF
#define CRYPT_H_DEF

#include <string>
#include <vector>
#include "cryptopp/config.h"
#include "cryptopp/secblock.h"

typedef CryptoPP::byte byte;

namespace crypt
{
	enum CipherProperties { c_aes = 1, c_other = 2, c_stream = 4, c_weak = 8, eax = 16, ccm = 32, gcm = 64, block = 128, stream = 256 };
	/*
		c_aes, c_other, c_stream, c_weak		categories for user interface only
		eax, ccm, gcm							supported cipher mode
		block									block-cipher
		stream									stream-cipher
	*/
	enum HashProperties { weak = 1, hmac_possible = 2, key = 4 };
	/*
		weak									hash more or less broken
		hmac_possible							cryptopp support for hmac
		key										hash supports key
	*/

	enum class Cipher : unsigned {		
		des, des_ede,	des_ede3, desx, gost, cast128, cast256, rc2, rc4, rc5, rc6, idea, blowfish, camellia, seed, tea, xtea, shacal2, mars, twofish, serpent, rijndael128, rijndael192, rijndael256, sosemanuk, salsa20, xsalsa20, chacha20, panama, COUNT
	};
	
	enum class Mode : unsigned {
		ecb, cbc, cfb, ofb, ctr, eax, ccm, gcm, COUNT
	};

	enum class Hash: unsigned {
		md4, md5, sha1, sha256, sha512, ripemd128, ripemd160, ripemd256, whirlpool, tiger128, sha3_224, sha3_256, sha3_384, sha3_512, keccak256, keccak512, blake2s, blake2b, COUNT
	};

	enum class Encoding : unsigned {
		ascii, base16, base32, base64, COUNT
	};

	enum class EOL : unsigned { 
		windows, unix, oldmac, COUNT
	};

	enum class KeyDerivation : unsigned {
		pbkdf2, bcrypt, scrypt, COUNT
	};

	enum class IV : unsigned {
		random, keyderivation, zero, COUNT
	};

	enum class Random: unsigned {
		charnum, specials, ascii, base16, base32, base64, COUNT
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
		const int rand_char_max =		4096;			// max number of random chars [-> getRandom()]
		const int rand_char_bufsize =	1024;			// buffersize of getRandom()
		const int gcm_tag_size =		16;				// gcm tag size in bytes
		const int ccm_tag_size =		16;				// ccm tag size in bytes
		const int eax_tag_size =		16;				// eax tag size in bytes
	};

	typedef std::basic_string<char, std::char_traits<char>, CryptoPP::AllocatorWithCleanup<char> > secure_string;

	class UserData
	{
	public:
		UserData();
		UserData(const char* s, Encoding enc);
		const byte*		BytePtr() const;
		size_t			size() const;
		size_t			set(std::string& s, Encoding enc);
		size_t			set(const char* s, size_t length, Encoding enc);
		size_t			set(const byte* s, size_t length);
		void			get(std::string& s, Encoding enc) const;
		void			get(secure_string& s, Encoding enc) const;
		void			clear();

	private:
		CryptoPP::SecByteBlock	data;
	};

	namespace Options
	{
		struct Crypt
		{
			Crypt() : cipher(Cipher::rijndael256), mode(Mode::gcm), iv(IV::random), password_encoding(crypt::Encoding::ascii) {};

			crypt::Cipher			cipher;
			crypt::Mode				mode;
			crypt::IV				iv;
			crypt::UserData			password;
			crypt::Encoding			password_encoding;

			struct Key
			{
				Key() : algorithm(KeyDerivation::scrypt), salt_bytes(16) { options[0] = Constants::scrypt_N_default; options[1] = Constants::scrypt_r_default; options[2] = Constants::scrypt_p_default; };
				KeyDerivation		algorithm;
				int					salt_bytes;
				int					options[6];
			};
			Key key;

			struct Encoding
 			{				
				Encoding() : enc(crypt::Encoding::base64), linelength(64), linebreaks(true), eol(EOL::windows), uppercase(true) {};
				crypt::Encoding		enc;
				size_t				linelength;
				bool				linebreaks;
				EOL					eol;
				bool				uppercase;
			};
			Encoding encoding;
		};

		struct Hash
		{
			Hash() : encoding(crypt::Encoding::base16), algorithm(crypt::Hash::md5), use_key(false), keypreset_id(-1){};

			crypt::Hash					algorithm;
			crypt::Encoding				encoding;
			int							keypreset_id;
			bool						use_key;
			std::vector<byte>			key;
		};

		struct Random
		{
			Random() : mode(crypt::Random::specials), length(16) {};

			crypt::Random	mode;
			size_t			length;
		};

		struct Convert
		{
			Convert() : from(crypt::Encoding::ascii), to(crypt::Encoding::base64), linebreaks(true), eol(EOL::windows), linelength(64), uppercase(true) {};

			crypt::Encoding	from;
			crypt::Encoding	to;
			bool			linebreaks;
			EOL				eol;
			bool			uppercase;
			int				linelength;
		};
	};

	/* -- used by encrypt() and decrypt() to recieve or return iv/salt/tag data -- */
	struct InitData
	{
		UserData		iv;
		UserData		salt;
		UserData		tag;
	};
	
	bool	getCipherInfo(crypt::Cipher cipher, crypt::Mode mode, int& key_length, int& iv_length, int& block_size);
	bool	getHashInfo(Hash h, int& length);
	void	encrypt(const byte* in, size_t in_len, std::basic_string<byte>& buffer, const Options::Crypt& options, InitData& init);
	void	decrypt(const byte* in, size_t in_len, std::basic_string<byte>& buffer, const Options::Crypt& options, const InitData& init);
	void	hash(const Options::Hash& options, std::basic_string<byte>& buffer, std::initializer_list<std::pair<const byte*, size_t>> in);
	void	hash(const Options::Hash& options, std::basic_string<byte>& buffer, const std::string& path);
	void	shake128(const byte* in, size_t in_len, byte* out, size_t out_len);
	void	random(const Options::Random& options, std::basic_string<byte>& buffer);
	void	convert(const byte* in, size_t in_len, std::basic_string<byte>& buffer, const Options::Convert& options);	

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
		static const char*	getString(crypt::EOL eol);

		static bool			getCipher(const char* s, crypt::Cipher& c);
		static bool			getCipherMode(const char* s, crypt::Mode& m);
		static bool			getKeyDerivation(const char*s, crypt::KeyDerivation& v);
		static bool			getEncoding(const char* s, crypt::Encoding& e);
		static bool			getIVMode(const char* s, crypt::IV& iv);
		static bool			getHash(const char* s, crypt::Hash& h, bool only_openssl = false);
		static bool			getRandomMode(const char* s, crypt::Random& m);
		static bool			getEOL(const char* s, crypt::EOL& eol);

		static crypt::Mode	getModeByIndex(crypt::Cipher cipher, int index);
		static int			getIndexByMode(crypt::Cipher cipher, crypt::Mode mode);
		static bool			validCipherMode(crypt::Cipher cipher, crypt::Mode mode);
		static bool			checkHashProperty(crypt::Hash h, int filter);
		static int			getCipherCategory(Cipher cipher);
		static Cipher		getCipherByIndex(CipherCat category, int index);
		static int			getCipherIndex(Cipher cipher);

		static const char*	getHelpURL(crypt::Encoding enc);
		static const char*	getHelpURL(crypt::Cipher cipher);
		static const char*	getHelpURL(crypt::Mode m);
		static const char*	getHelpURL(crypt::Hash h);
		static const char*	getHelpURL(crypt::KeyDerivation k);

		// iteration through cipher/mode/hash-strings
		class Iter {
		public:
			static void setup_cipher(CipherCat category);
			static void setup_mode(Cipher cipher);
			static void setup_hash(unsigned int filter=0);
			static bool next();
			static const char* getString();
		private:
			static int _what;
			static int _cipher;
			static int _temp;
			static unsigned int _filter;
			static int i;
		};
	};
};

#endif
