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

#ifndef UNICODE_H_DEF
#define UNICODE_H_DEF

#include <string>

#ifdef UNICODE
typedef std::wstring string;
#else
typedef std::string string;
#endif

namespace unicode
{
	void				wchar_to_utf8(const wchar_t* i, int i_len, std::string& o);
	void				utf8_to_wchar(const char* i, int i_len, std::wstring& o);
}

#endif