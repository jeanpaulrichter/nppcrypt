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

#include "unicode.h"
#include "exception.h"

void unicode::wchar_to_utf8(const wchar_t* i, int i_len, std::string& o)
{
	if (i_len < -1) {
		i_len = -1;
	}
	int bytelen = WideCharToMultiByte(CP_UTF8, 0, i, i_len, NULL, 0, NULL, false);
	if (bytelen < 1) {
		throw CExc(CExc::Code::utf8conversion);
	}
	o.resize((size_t)bytelen);
	if (!WideCharToMultiByte(CP_UTF8, 0, i, i_len, &o[0], bytelen, NULL, false)) {
		throw CExc(CExc::Code::utf8conversion);
	}
	if (o.size() > 0 && i_len == -1) {
		o.pop_back();
	}
}

void unicode::utf8_to_wchar(const char* i, int i_len, std::wstring& o)
{
	if (i_len < -1) {
		i_len = -1;
	}
	int charlen = ::MultiByteToWideChar(CP_UTF8, 0, i, i_len, NULL, 0);
	if (charlen < 1) {
		throw CExc(CExc::Code::utf8conversion);
	}
	o.resize((size_t)charlen);
	if (!MultiByteToWideChar(CP_UTF8, 0, i, i_len, &o[0], charlen)) {
		throw CExc(CExc::Code::utf8conversion);
	}
	if (o.size() > 0 && i_len == -1) {
		o.pop_back();
	}
}