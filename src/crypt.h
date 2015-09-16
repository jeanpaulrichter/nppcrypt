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

namespace Crypt {

	enum class Operation : unsigned {
		Encryption=0,
		Decryption
	};

	enum class Cipher : unsigned {
		des=0, des_ede,	des_ede3, desx,	rc2, rc4, rc5, idea, blowfish, cast5, aes128, aes192, aes256, COUNT
	};
	
	enum class Mode : unsigned {
		ecb=0, cbc,	cfb, ofb, ctr, xts,	ccm, gcm, COUNT 
	};

	enum class Hash: unsigned {
		md4=0, md5,	sha1, sha256, sha512, ripemd160, whirlpool,	sha3_256, sha3_384,	sha3_512, COUNT
	};

	enum class Encoding : unsigned {
		ascii=0, hex, base64, COUNT
	};

	enum class KeyDerivation : unsigned {
		pbkdf2=0, bcrypt, scrypt, COUNT
	};

	enum class InitVector : unsigned {
		random=0, keyderivation, zero, COUNT
	};

	enum class RandomMode: unsigned {
		charnum=0, specials, ascii,	hex, base64, COUNT
	};

	namespace Constants {
		const int pw_length_max = 50;				// max password characters
		const int salt_bytes_max = 128;				// max salt bytes
		const int pbkdf2_default_hash = 1;			// default hash
		const int pbkdf2_iter_default = 1000;		// default iterations
		const int pbkdf2_iter_min = 1;
		const int pbkdf2_iter_max = 32000;
		const int bcrypt_iter_default = 8;			// default iterations (2^x)
		const int bcrypt_iter_min = 4;
		const int bcrypt_iter_max = 24;
		const int scrypt_N_default = 14;			// N ( 2^x)
		const int scrypt_N_min = 2;
		const int scrypt_N_max = 24;
		const int scrypt_r_default = 8;				// r
		const int scrypt_r_min = 1;
		const int scrypt_r_max = 99;
		const int scrypt_p_default = 1;				// p
		const int scrypt_p_min = 1;
		const int scrypt_p_max = 99;
		const int gcm_iv_length = 16;
		const int ccm_iv_length = 8;				// 7-13
		const int rand_char_max=4096;				// max number of random chars
		const int rand_char_bufsize=1024;
	};

	struct Options {
		Options(): cipher(Cipher::aes256),mode(Mode::cbc),encoding(Encoding::hex),iv(InitVector::random) { 
			key.salt_bytes = 16; key.algorithm = KeyDerivation::pbkdf2; key.option1=1; key.option2=Constants::pbkdf2_iter_default;
			hmac.enable = false; hmac.hash = Hash::sha256;
		};

		Cipher			cipher;
		Mode			mode;
		Encoding		encoding;
		InitVector		iv;
		std::string		password;

		struct {
			KeyDerivation	algorithm;
			int				salt_bytes;
			int				option1;
			int				option2;
			int				option3;
		} key;		

		struct {
			bool						enable;
			Hash						hash;
			std::vector<unsigned char>	key;
			std::string					key_input;
			int							key_id;
		} hmac;
	};

	struct HashOptions {
		HashOptions(): encoding(Encoding::hex),algorithm(Hash::md5),use_key(false) {};

		Hash			algorithm;
		Encoding		encoding;
		bool			use_key;
		std::string		key;
	};

	struct RandOptions {
		RandOptions(): mode(RandomMode::specials),length(16) {};

		RandomMode		mode;
		size_t			length;
	};

	size_t getMDLength(Hash h);
	void doCrypt(Operation op, const unsigned char* in, size_t in_len, std::vector<unsigned char>& buffer, Options* options, std::string& s_iv, std::string& s_salt, std::string& s_tag);
	void doHash(const unsigned char* in, size_t in_len, std::vector<unsigned char>& buffer, const HashOptions* options);
	void hmac(const char* header, unsigned int header_len, const unsigned char* data, unsigned int data_len, Hash algo, const unsigned char* key, size_t key_len, std::string& out);
	void hmac(const unsigned char* data, unsigned int data_len, const Crypt::HashOptions& options, std::vector<unsigned char>& out);
	void getRandom(const RandOptions* options, std::vector<unsigned char>& buffer);
	void shake128(const unsigned char* in, size_t in_len, unsigned char* out, size_t out_len);


	class Strings {
	public:
		static void setup();
		static bool nextCipher();
		static void setCipher(Crypt::Cipher cipher);
		static bool nextMode();
		static const TCHAR* Cipher();
		static const TCHAR* Mode();
		static std::string Mode(Crypt::Mode mode);
		static std::string Cipher(Crypt::Cipher cipher);
		static const char* Encoding(Crypt::Encoding enc);
		static const char* KeyAlgorithm(Crypt::KeyDerivation k);
		static Crypt::Mode getModeByIndex(Crypt::Cipher cipher, int index);
		static int getIndexByMode(Crypt::Cipher cipher, Crypt::Mode mode);
		static bool getCipherByString(const char* s, Crypt::Cipher& c);
		static bool getModeByString(const char* s, Crypt::Mode& m);
		static bool getKeyDerivationByString(const char*s, Crypt::KeyDerivation& v );
		static bool getEncodingByString(const char* s, Crypt::Encoding& e);
		static bool nextHash(bool only_openssl=false);
		static const TCHAR* getHash();
		static std::string getHash(Hash h);
		static bool getHashByString(const char* s, Hash& h);
	private:
		static int cipher_id;
		static int mode_id;
		static int hash_id;
	};
};



#endif