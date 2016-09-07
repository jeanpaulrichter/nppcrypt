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

#include "exception.h"

static const TCHAR* error_msgs[] = 
{ 
/* unexpected		*/	TEXT("Unexspected exception."), 
/* encrypt			*/	TEXT("Failed to encrypt."),
/* decrypt			*/	TEXT("Failed to decrypt."),
/* decode_base16	*/	TEXT("Failed to decode base16."),
/* decode_base64	*/	TEXT("Failed to decode base64."),
/* file_empty		*/	TEXT("File is empty."),
/* parse_header		*/	TEXT("Failed to parse header."),
/* authentication	*/	TEXT("Data authentication failed."),
/* utf8conversion	*/	TEXT("String-conversion to utf8 failed."),
/* nppfile1009		*/	TEXT("Sorry, this file is no longer supported.\nPlease download v1.009 at www.cerberus-design.de/downloads."),
/* nppfile1007		*/	TEXT("Sorry, this file is no longer supported.\nPlease download v1.007 at www.cerberus-design.de/downloads."),
/* header_version	*/	TEXT("Header: version missing."),
/* header_hmac_data */	TEXT("Header: hmac data corrupted."),
/* header_hmac_hash */	TEXT("Header: invalid hmac-hash."),
/* header_hmac_key	*/	TEXT("Header: invalid auth-key-id."),
/* header_salt		*/	TEXT("Header: salt data corrupted."),
/* header_iv		*/	TEXT("Header: iv data corrupted."),
/* header_cipher	*/	TEXT("Header: invalid cipher."),
/* header_mode		*/	TEXT("Header: invalid mode."),
/* header_encoding	*/	TEXT("Header: invalid encoding."),
/* header_tag		*/	TEXT("Header: tag data corrupted."),
/* header_keyderi	*/	TEXT("Header: invalid key-derivation"),
/* header_pbkdf2	*/	TEXT("Header: invalid options for pbkdf2."),
/* header_bcrypt	*/	TEXT("Header: invalid options for bcrypt."),
/* header_scrypt	*/	TEXT("Header: invalid options for scrypt."),
/* decrypt_nosalt	*/	TEXT("Decryption: salt missing."),
/* decrypt_badsalt	*/	TEXT("Decryption: salt corrupted."),
/* decrypt_noiv		*/	TEXT("Decryption: iv missing."),
/* decrypt_badiv	*/	TEXT("Decryption: iv corrupted."),
/* decrypt_notag	*/	TEXT("Decryption: tag missing."),
/* decrypt_badtag	*/	TEXT("Decryption: tag corrupted."),
/* input_too_long	*/	TEXT("Input too long."),
/* bcrypt_salt		*/	TEXT("Bcrypt only supports 16-byte salt."),
/* preffile_missing	*/	TEXT("Cannot open preferences-file."),
/* preffile_corrupted*/	TEXT("Preferences file corrupted.")
};

const TCHAR* CExc::getMsg() const throw()
{
	if (msg.size())	{
		return msg.c_str();
	} else {
		return error_msgs[unsigned(code)];
	}
}

CExc::~CExc() throw()
{
}

CExc::CExc(Code err_code) : code(err_code)
{
}

CExc::CExc(File file, int line, Code err_code)
{
	code = err_code;
	msg.resize(11+lstrlen(error_msgs[unsigned(code)]));
	lstrcpy(&msg[10], error_msgs[unsigned(code)]);

	msg[0] = '('; msg[3] = '/'; msg[8] = ')'; msg[9] = ' ';
	msg[1] = 48+(TCHAR(file)/10);
	msg[2] = 48+(TCHAR(file)%10);
	msg[7] = TCHAR(line % 10) + '0';  line /= 10;
    msg[6] = TCHAR(line % 10) + '0';  line /= 10;
    msg[5] = TCHAR(line % 10) + '0';  line /= 10;
    msg[4] = TCHAR(line % 10) + '0';
}