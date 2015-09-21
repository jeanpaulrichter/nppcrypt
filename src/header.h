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

#ifndef HEADER_DEFINE_H
#define HEADER_DEFINE_H

#include "crypt.h"
#include "mdef.h"

class DataParser
{
public:
	DataParser(const unsigned char* in, size_t in_len, crypt::Options::Crypt& opt);

	bool readHeader();
	void setupHeader();
	void updateHMAC(const std::string& hmac);
	bool checkHMAC(const std::string& hmac);
	int	getVersion();

	const char*				header();
	const char*				header_c();
	const unsigned char*	data();
	const unsigned char*	crypt_data();

	size_t					header_length();	
	size_t					header_c_length();	
	size_t					data_length();	
	size_t					crypt_data_length();

	crypt::InitStrings&		init();

private:
	void					parse_old_headers();

	crypt::Options::Crypt&		options;

	const unsigned char* const	pData;
	const char*					pHeader;
	const char*					pHeader_c;
	const unsigned char* 		pCryptData;

	size_t					data_len;
	size_t					header_len;
	size_t					header_c_len;
	size_t					crypt_data_len;
	size_t					hmac_start;

	std::string				s_header;
	crypt::InitStrings		s_init;
	std::string				s_hmac;

	int						version;
};

#endif