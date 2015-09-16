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

#ifndef EXCEPTION_DEFINE_H
#define EXCEPTION_DEFINE_H

#include <windows.h>
#include <string.h>
#include <tchar.h>
#include <exception>
#include <vector>

class CExc: public std::exception
{
public:
	enum File {
		nppcrypt = 0,
		crypt,
		preferences,
		encoding,
		dlg_about,
		dlg_auth,
		dlg_config,
		dlg_crypt,
		dlg_hash,
		dlg_random
	};

	enum ErrCode {
		unexspected,
		encrypt,
		decrypt,
		readhex,
		file_empty,
		parse_header,
		authentication,
		utf8conversion,
		nppfile1009,
		nppfile1007
	};

	CExc(const TCHAR* what);
	CExc(ErrCode err_code=unexspected);
	CExc(File file, int line, const TCHAR* what);
	CExc(File file, int line, ErrCode err_code=unexspected);
	~CExc() throw();

	const char* what() const throw() { return NULL; };
	const TCHAR* getErrorMsg() const throw();

private:
	ErrCode				code;
	std::vector<TCHAR>	msg;
};

#endif