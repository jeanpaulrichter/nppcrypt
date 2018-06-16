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

#include "exception.h"

static const char* error_msgs[] =
{
	/* unexpected = 0				*/ "Unexspected exception.",
	/* input_null					*/ "Input is empty.",
	/* invalid_bcrypt_saltlength	*/ "Invalid bcrypt salt-length (only 16-byte allowed).",
	/* invalid_pbkdf2_hash			*/ "Invalid hash algorithm for pbkdf2.",
	/* invalid_hash					*/ "Invalid hash algorithm.",
	/* bcrypt_failed				*/ "Bcrypt failed.",
	/* scrypt_failed				*/ "Scrypt failed.",
	/* keccak_shake_failed			*/ "Keccak shake128 failed.",
	/* cryptopp_not_implemented		*/ "Cryptopp: feature not implemented.",
	/* cryptopp_invalid_argument	*/ "Cryptopp: invalid argument.",
	/* cryptopp_cannot_flush		*/ "Cryptopp: cannot flush.",
	/* cryptopp_bad_integrity		*/ "Integrity check failed.",
	/* cryptopp_invalid_data		*/ "Cryptopp: invalid data.",
	/* cryptopp_io_error			*/ "Cryptopp: I/O-Error.",
	/* cryptopp_other				*/ "Cryptopp: unknown error.",
	/* salt_missing					*/ "Salt-data missing.",
	/* iv_missing					*/ "IV-data missing.",
	/* keylength_missing            */ "Key-length missing.",
	/* authentication_failed		*/ "Authentication failed.",
	/* hmac_auth_failed				*/ "HMAC Authentication failed.",
	/* decode_base16				*/ "Failed to decode base16.",
	/* decode_base64				*/ "Failed to decode base64.",
	/* utf8conversion				*/ "String-conversion to utf8 failed.",
	/* header_not_found				*/ "No Header found.",
	/* invalid_header				*/ "Invalid header.",
	/* invalid_header_version		*/ "Invalid header verson.",
	/* invalid_hmac_data			*/ "Invalid hmac data.",
	/* invalid_hmac_hash			*/ "Invalid hmac-hash.",
	/* invalid_presetkey			*/ "Invalid preset-key.",
	/* invalid_salt					*/ "Invalid salt data.",
	/* invalid_iv					*/ "Invalid IV data.",
	/* invalid_iv_mode				*/ "Invalid IV Mode.",
	/* invalid_cipher				*/ "Invalid cipher.",
	/* invalid_mode					*/ "Invalid cipher mode.",
	/* invalid_encoding				*/ "Invalid encoding.",
	/* invalid_eol					*/ "Invalid EOL",
	/* invalid_linelength			*/ "Invalid linelength.",
	/* invalid_uppercase			*/ "Invalid uppercase (true|false)",
	/* invalid_tag					*/ "Invalid tag data.",
	/* invalid_keyderivation		*/ "Invalid key-derivation",
	/* invalid_pbkdf2				*/ "Invalid options for pbkdf2.",
	/* invalid_bcrypt				*/ "Invalid options for bcrypt.",
	/* invalid_scrypt				*/ "Invalid options for scrypt.",
	/* invalid_crypt_action			*/ "Invalid crypt action.",
	/* invalid_keylength			*/ "Invalid key-length.",
	/* passwords_dont_match			*/ "Password do not match.",
	/* password_missing				*/ "Password missing.",
	/* preffile_read_fail			*/ "Failed to open preferences-file.",
	/* preffile_corrupted			*/ "Preferences file corrupted.",
	/* inputfile_read_fail			*/ "Failed to read input-file.",
	/* outputfile_write_fail		*/ "Failed to write output-file.",
	/* only_utf8_decrypt			*/ "utf16/utf32 bom present: nppcrypt creates only utf8 files.",
	/* password_decode				*/ "Failed to decode password"
};

const char* CExc::what() const throw()
{
	return error_msgs[unsigned(code)];
}

CExc::~CExc() throw()
{
}

CExc::CExc(Code err_code) : code(err_code)
{
}
