/*
This file is part of the nppcrypt
(http://www.github.com/jeanpaulrichter/nppcrypt)
a plugin for notepad++ [ Copyright (C)2003 Don HO <don.h@free.fr> ]
(https://notepad-plus-plus.org)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
*/

#ifndef HELP_H_DEF
#define HELP_H_DEF

#include <string>
#include "npp\Scintilla.h"
#include "npp\PluginInterface.h"
#include "crypt.h"

namespace helper
{
	namespace Scintilla
	{
		HWND			getCurrent();
		void			replaceSelection(const std::basic_string<byte>& buffer);
		size_t			getSelectionLength();
		bool			getSelection(const byte** pdata, size_t* length, size_t* start = NULL, size_t* end = NULL);
	};

	namespace Buffer
	{
		uptr_t			getCurrent();
		bool			is8Bit(uptr_t);
		bool			isCurrent8Bit();
		void			getPath(uptr_t bufferid, std::wstring& path, std::wstring& filename, std::wstring& extension);
	};

	namespace Windows
	{
		void			copyToClipboard(const std::basic_string<byte>& buffer);
		void			wchar_to_utf8(const wchar_t* i, int i_len, std::string& o);
		void			wchar_to_utf8(const wchar_t* i, int i_len, crypt::secure_string& o);
		void			utf8_to_wchar(const char* i, int i_len, std::wstring& o);
		void			utf8_to_wchar(const char* i, int i_len, crypt::secure_wstring& o);
		void			error(HWND hwnd, const char* msg);
	};

	namespace NPP
	{
		HINSTANCE		getDLLHandle();
		HWND			getWindow();
		bool			setCommand(size_t index, TCHAR *cmdName, PFUNCPLUGINCMD pFunc, ShortcutKey *sk, bool check0nInit = false);
	};
};

#endif