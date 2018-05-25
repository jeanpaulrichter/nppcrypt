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

#ifndef EXCEPTION_H_DEF
#define EXCEPTION_H_DEF

#include <string>
#include <exception>
#include <vector>

class CExc: public std::exception
{
public:
	enum class Code : unsigned 
	{
		unexpected = 0,
		input_null,
		invalid_bcrypt_saltlength,
		invalid_pbkdf2_hash,
		invalid_hash,
		bcrypt_failed,
		scrypt_failed,
		keccak_shake_failed,
		cryptopp_not_implemented,
		cryptopp_invalid_argument,
		cryptopp_cannot_flush,
		cryptopp_bad_integrity,
		cryptopp_invalid_data,
		cryptopp_io_error,
		cryptopp_other,
		salt_missing,
		iv_missing,
		authentication_failed,
		hmac_auth_failed,
		decode_base16,
		decode_base64,
		utf8conversion,
		header_not_found,
		invalid_header,
		invalid_header_version,
		invalid_hmac_data,
		invalid_hmac_hash,
		invalid_presetkey,
		invalid_salt,
		invalid_iv,
		invalid_iv_mode,
		invalid_cipher, 
		invalid_mode,
		invalid_encoding,
		invalid_eol,
		invalid_linelength,
		invalid_uppercase,
		invalid_tag,
		invalid_keyderivation,
		invalid_pbkdf2,
		invalid_bcrypt,
		invalid_scrypt,
		invalid_crypt_action,
		passwords_dont_match,
		password_missing,
		preffile_read_fail,
		preffile_corrupted,
		inputfile_read_fail,
		outputfile_write_fail,
		only_utf8_decrypt,
		password_decode
	};

	CExc(Code err_code=Code::unexpected);
	~CExc() throw();
						
	const char*			what() const throw();
	Code				getCode() const throw() { return code; };

private:
	Code				code;
};

#endif
