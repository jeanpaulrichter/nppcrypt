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

class Header
{
public:
	Header() : version(NPPC_VERSION), pContent(NULL), content_len(0) {};

	int				getVersion() { return version; };
	/* returns header-content (<nppcrypt>content</nppcrypt>) */
	const char*		body() { return pContent; };
	/* returns header-content length */
	size_t			body_size() { return content_len; };

protected:
	crypt::InitStrings		s_init;
	int						version;
	const char*				pContent;
	size_t					content_len;
};


class HeaderReader : public Header
{
public:
	HeaderReader(crypt::Options::Crypt& opt) : options(opt), pCData(NULL), cdata_len(0) {};

	/* parses data for header and updates crypt::Options::Crypt, return true if header found */
	bool	parse(const unsigned char* in, size_t in_len);
	/* compares header-hmac with given hmac string, returns true if equal */
	bool	checkHMAC(const std::string& hmac);
	/* returns encrypted data */
	const unsigned char*	cdata() { return pCData; };
	/* returns encrypted data length */
	size_t					cdata_size() { return cdata_len; };
	crypt::InitStrings&		init_strings() { return s_init; };

private:
	void	parse_old(const unsigned char* in, size_t in_len);

	crypt::Options::Crypt&		options;
	std::string					s_hmac;
	const unsigned char* 		pCData;
	size_t						cdata_len;
};

class HeaderWriter : public Header
{
public:
	HeaderWriter(const crypt::Options::Crypt& opt) : options(opt), hmac_offset(0) {};
	/* creates header string from given crypt::Options::Crypt */
	void	create();
	/* updates hmac-string of header */
	void	updateHMAC(const std::string& hmac);

	/* returns header data */
	const char*						c_str() { return s_header.c_str(); };
	/* returns header length */
	size_t							size() { return s_header.size(); };
	crypt::InitStrings&				init_strings() { return s_init;	};

private:
	size_t			base64length(size_t bin_length, bool linebreaks=false, size_t line_length=0, bool windows=false);

	const crypt::Options::Crypt&	options;
	std::string						s_header;
	size_t							hmac_offset;
};

#endif