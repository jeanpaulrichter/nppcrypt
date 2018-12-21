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

#ifndef CRYPT_H_DEF
#define CRYPT_H_DEF

#include <string>
#include "cryptopp/secblock.h"

namespace crypt
{
	typedef CryptoPP::byte byte;
	typedef std::basic_string<char, std::char_traits<char>, CryptoPP::AllocatorWithCleanup<char> > secure_string;
	typedef std::basic_string<wchar_t, std::char_traits<wchar_t>, CryptoPP::AllocatorWithCleanup<wchar_t> > secure_wstring;

	enum class Cipher : unsigned {		
		threeway, aria, blowfish, camellia, cast128, cast256, chacha20, des, des_ede2, des_ede3, desx, gost, idea, kalyna128, kalyna256, kalyna512, mars, panama, rc2, rc4, rc5, rc6, rijndael, saferk, safersk, salsa20, seal, seed, serpent, shacal2, shark, simon128, skipjack, sm4, sosemanuk, speck128, square, tea, threefish256, threefish512, threefish1024, twofish, wake, xsalsa20, xtea, COUNT
	};
	
	enum class Mode : unsigned {
		ecb, cbc, cfb, ofb, ctr, eax, ccm, gcm, COUNT
	};

	enum class Hash: unsigned {
		adler32, blake2b, blake2s, cmac_aes, crc32, keccak, md2, md4, md5, ripemd, sha1, sha2, sha3, siphash24, siphash48, sm3, tiger, whirlpool, COUNT
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
		random, keyderivation, zero, custom, COUNT
	};

	namespace Constants
	{
		const size_t salt_max =			512;			/* max salt bytes */
		const Hash pbkdf2_default_hash = Hash::sha3;	/* pbkdf2: default hash ( see enum Hash ) */
		const int pbkdf2_default_hash_digest = 32;		/* pbkdf2: hash digest length */
		const int pbkdf2_iter_default = 5000;			/* pbkdf2: default iterations */
		const int pbkdf2_iter_min =		1;				/* pbkdf2: min iterations  */
		const int pbkdf2_iter_max =		10000000;		/* pbkdf2: max iterations */
		const int bcrypt_iter_default = 8;				/* bcrypt: default iterations (2^x) */
		const int bcrypt_iter_min =		4;				/* bcrypt: min iterations (2^x) */
		const int bcrypt_iter_max =		32;				/* bcrypt: max iterations (2^x) */
		const int scrypt_N_default =	14;				/* scrypt: default N (2^x) */
		const int scrypt_N_min =		2;				/* scrypt: min N (2^x) */
		const int scrypt_N_max =		32;				/* scrypt: max N (2^x) */
		const int scrypt_r_default =	8;				/* scrypt: default r */
		const int scrypt_r_min =		1;				/* scrypt: min r */
		const int scrypt_r_max =		256;			/* scrypt: max r */
		const int scrypt_p_default =	1;				/* scrypt: default p */
		const int scrypt_p_min =		1;				/* scrypt: min r */
		const int scrypt_p_max =		256;			/* scrypt: max r */
		const int gcm_iv_length =		16;				/* IV-Length for gcm mode */
		const int ccm_iv_length =		13;				/* IV-Length for ccm mode, possible values: 7-13 */
		const int rand_char_max =		4096;			/* max number of random bytes ( UserData::random() ) */
		const int gcm_tag_size =		16;				/* gcm tag size in bytes */
		const int ccm_tag_size =		16;				/* ccm tag size in bytes */
		const int eax_tag_size =		16;				/* eax tag size in bytes */
	};

	class Exception : public std::exception
	{
	public:
		Exception() noexcept {};
		Exception(const std::string &m) noexcept : msg(m) {};
		const char *what() const noexcept {
			return msg.c_str();
		};
	protected:
		std::string msg;
	};

	class ExceptionError : public Exception
	{
	public:
		ExceptionError(const std::string &m, const char* func, int ln) noexcept;
	private:
		int	line;
	};

	class ExceptionArguments : public Exception
	{
	public:
		ExceptionArguments(const std::string &m) noexcept : Exception(m) {};
	};

	class ExceptionInfo : public Exception
	{
	public:
		ExceptionInfo(const std::string &m) noexcept : Exception(m) {};
	};

	class UserData
	{
	public:
		enum class Restriction : unsigned {
			digits, letters, alphanum, password, specials, none, COUNT
		};

		UserData();
		UserData(const char* s, Encoding enc);
		const byte*		BytePtr() const;
		size_t			size() const;
		size_t			set(const UserData& s);
		size_t			set(std::string& s, Encoding enc);
		size_t			set(const char* s, size_t length, Encoding enc);
		size_t			set(const byte* s, size_t length);
		bool			random(size_t length, Restriction k = Restriction::none, bool blocking = true);
		bool			zero(size_t length);
		void			get(std::string& s, Encoding enc) const;
		void			get(secure_string& s, Encoding enc) const;
		void			clear();

	private:
		CryptoPP::SecByteBlock	data;
	};

	/* used by encrypt() and decrypt() to receive or return iv/salt/tag data */
	struct InitData
	{
		UserData		iv;
		UserData		salt;
		UserData		tag;
	};

	class EncodingAlphabet
	{
	public:
		EncodingAlphabet() : padding(0) {};
		bool setup(const char* alphabet, byte padding = 0);
		const byte* c_str(bool uppercase = false) const {
			if (uppercase) {
				return (upper.size() == 0) ? NULL : &upper[0];
			} else {
				return (lower.size() == 0) ? NULL : &lower[0];
			}
		}
		byte getPadding() const { return padding; };
		const int* getLookup() const { return lookup; };
	private:
		int lookup[256];
		std::vector<byte> lower;
		std::vector<byte> upper;
		byte padding;
	};

	namespace Options
	{
		struct Crypt
		{
			Crypt() : cipher(Cipher::rijndael), mode(Mode::gcm), iv(IV::random), aad(true) {};

			crypt::Cipher			cipher;
			crypt::Mode				mode;
			crypt::IV				iv;
			bool					aad;

			struct Key
			{
				Key() : algorithm(KeyDerivation::scrypt), salt_bytes(16), length(32) { options[0] = Constants::scrypt_N_default; options[1] = Constants::scrypt_r_default; options[2] = Constants::scrypt_p_default; };
				KeyDerivation		algorithm;
				size_t				length;
				size_t				salt_bytes;
				int					options[6];
			};
			Key key;

			struct Encoding
 			{				
				Encoding() : enc(crypt::Encoding::base64), linelength(128), linebreaks(true), eol(EOL::windows), uppercase(true) {};
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
			Hash() : encoding(crypt::Encoding::base16), algorithm(crypt::Hash::md5), use_key(false), digest_length(16) {};

			crypt::Hash					algorithm;
			size_t						digest_length;
			crypt::Encoding				encoding;
			bool						use_key;
			UserData					key;
		};

		struct Convert
		{
			Convert() : from(crypt::Encoding::ascii), to(crypt::Encoding::base64), linebreaks(true), eol(EOL::windows), linelength(64), uppercase(true) {};

			crypt::Encoding	from;
			crypt::Encoding	to;
			bool			linebreaks;
			EOL				eol;
			bool			uppercase;
			size_t			linelength;
		};
	};
	
	/* -- check parameters of cipher or receive default values -- */
	bool	getCipherInfo(crypt::Cipher cipher, crypt::Mode mode, size_t& key_length, size_t& iv_length, size_t& block_size);

	/* -- check parameters of hash or receive default values -- */
	bool	getHashInfo(Hash h, size_t& length, size_t& keylength);

	/* -- encrypt -- */
	void	encrypt(const byte* in, size_t in_len, std::basic_string<byte>& buffer, const Options::Crypt& options, const UserData& password, InitData& init);

	/* -- decrypt -- */
	void	decrypt(const byte* in, size_t in_len, std::basic_string<byte>& buffer, const Options::Crypt& options, const UserData& password, InitData& init);

	/* -- hash data -- */
	void	hash(Options::Hash& options, std::basic_string<byte>& buffer, std::initializer_list<std::pair<const byte*, size_t>> in);

	/* -- hash file -- */
	void	hash(Options::Hash& options, std::basic_string<byte>& buffer, const std::string& path);

	/* -- sha3 shake128 hash -- */
	void	shake128(const byte* in, size_t in_len, byte* out, size_t out_len);

	/* -- convert encoding -- */
	void	convert(const byte* in, size_t in_len, std::basic_string<byte>& buffer, const Options::Convert& options, const EncodingAlphabet* base32_alphabet = NULL, const EncodingAlphabet* base64_alphabet = NULL);
};

#endif
