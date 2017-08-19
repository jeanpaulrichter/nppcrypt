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

#ifndef HEADER_H_DEF
#define HEADER_H_DEF

#include "crypt.h"
#include "mdef.h"

class CryptHeader
{
public:

	struct HMAC {
		HMAC() : enable(false), hash(crypt::Hash::sha3_256), keypreset_id(-1) {};
		bool			enable;
		crypt::Hash		hash;
		int				keypreset_id;
		std::string		password;
	};

						CryptHeader() : version(NPPC_VERSION) {};
	int					getVersion() { return version; };

protected:
	crypt::InitData		s_init;
	int					version;
	const byte*			pBody;
	size_t				bodyLength;
};

class CryptHeaderReader : public CryptHeader
{
public:
								CryptHeaderReader(crypt::Options::Crypt& opt, CryptHeader::HMAC& h) : options(opt), hmac(h), pEncryptedData(NULL), encryptedDataLen(0) {};
	bool						parse(const byte* in, size_t in_len);	
	const unsigned char*		encryptedData() { return pEncryptedData; };
	size_t						encryptedDataLength() { return encryptedDataLen; };
	crypt::InitData&			initData() { return s_init; };
	bool						checkHMAC(const std::string& password);
	bool						checkHMAC(const byte* key, size_t key_length);

private:
	crypt::Options::Crypt&		options;
	CryptHeader::HMAC&			hmac;
	const unsigned char* 		pEncryptedData;
	size_t						encryptedDataLen;	
	std::string					hmac_data;
};

class CryptHeaderWriter : public CryptHeader
{
public:

							CryptHeaderWriter(const crypt::Options::Crypt& opt, const HMAC& hmac_opt, const byte* h_key = NULL, size_t h_len = 0);
	void					create(const byte* data, size_t data_length);
	const char*				c_str() { return buffer.c_str(); };
	size_t					size() { return buffer.size(); };
	crypt::InitData&		initData() { return s_init;	};
	void					setHMACKey(const byte* h_key = NULL, size_t h_len = 0);

private:
	size_t					base64length(size_t bin_length, bool linebreaks=false, size_t line_length=0, bool windows=false);

	const CryptHeader::HMAC&		hmac;
	const crypt::Options::Crypt&	options;
	std::vector<byte>				hmac_key;
	std::string						buffer;
};

#endif