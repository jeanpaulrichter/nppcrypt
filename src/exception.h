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

#ifndef EXCEPTION_H_DEF
#define EXCEPTION_H_DEF

#include <windows.h>
#include <string.h>
#include <tchar.h>
#include <exception>
#include <vector>
#include "unicode.h"

class CExc: public std::exception
{
public:
	enum class File : unsigned 
	{
		nppcrypt = 0,
		crypt,
		cryptheader,
		help,
		unicode,
		preferences,
		dlg_about,
		dlg_auth,
		dlg_convert,
		dlg_crypt,
		dlg_hash,
		dlg_initdata,
		dlg_preferences,
		dlg_random
	};

	enum class Code : unsigned 
	{
		unexpected = 0,	
		encrypt, 
		decrypt,
		decode_base16,
		decode_base64,
		file_empty,
		parse_header,
		authentication,
		utf8conversion,
		nppfile1009,
		nppfile1007,
		header_version,
		header_hmac_data, 
		header_hmac_hash, 
		header_hmac_key, 
		header_salt, 
		header_iv, 
		header_cipher, 
		header_mode, 
		header_encoding, 
		header_tag, 
		header_keyderi, 
		header_pbkdf2, 
		header_bcrypt, 
		header_scrypt,
		decrypt_nosalt,
		decrypt_badsalt,
		decrypt_noiv,
		decrypt_badiv,
		decrypt_notag,
		decrypt_badtag,
		input_too_long,
		bcrypt_salt,
		preffile_missing,
		preffile_corrupted
	};

	CExc(Code err_code=Code::unexpected);
	CExc(File file, int line, Code err_code=Code::unexpected);
	~CExc() throw();
						
	const char*			what() const throw() { return NULL; };
	const TCHAR*		getMsg() const throw();
	Code				getCode() const throw() { return code; };

private:
	Code				code;
	string				msg;
};

#endif