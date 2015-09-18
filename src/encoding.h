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

#ifndef ENCODING_DEFINE_H
#define ENCODING_DEFINE_H

#include <string>
#include "exception.h"

namespace Encode
{
	struct Options {

		struct Base16 {
			/* case of non-numberic characters in hex-values */
			static enum Case { lower, upper } letter_case;
			/* spaces (ascii-charcter 32) between hex-values? */
			static bool spaces;
			/* number of hex-values (i.e. a4) written before linebreak */
			static unsigned int vpl;
		};

		struct Base64 {
			/* characters (bytes) written before linebreak */
			static unsigned int cpl;
		};

		struct Common {
			/* characters on linebreak: \r\n (13,10) or \n (10) */
			static enum EOL { windows, unix } eol;
		};
	};

	/* encode ascii data as hex. returns number of bytes written. if char*dest=NULL the exspected buffersize is returned (0 on error). */
	size_t bin_to_hex(const unsigned char* src, unsigned int len, char* dest=0);
	/* encode ascii data as base64. returns number of bytes written. if char*dest=NULL the exspected buffersize is returned (0 on error). */
	size_t bin_to_base64(const unsigned char* src, unsigned int len, char* dest=0, bool no_linebreaks=false);
	/* decode data encoded as hex-values. returns number of bytes written. if char*dest=NULL the exspected buffersize is returned (0 on error). */
	size_t hex_to_bin(const char* src, unsigned int len, unsigned char* dest=0);
	/* decode data encoded in base64. returns number of bytes written. if char*dest=NULL the exspected buffersize is returned (0 on error). */
	size_t base64_to_bin(const char* src, unsigned int len, unsigned char* dest=0);

	const char* linebreak();

	void wchar_to_utf8(const wchar_t* i, int i_len, std::string& o);
	void utf8_to_wchar(const char* i, int i_len, std::wstring& o);
}

#endif