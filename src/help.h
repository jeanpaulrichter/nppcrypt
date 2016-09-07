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

#ifndef HELP_H_DEF
#define HELP_H_DEF

#include "unicode.h"
#include "npp\Scintilla.h"
#include "npp\PluginInterface.h"
#include "crypt.h"

namespace helper
{
	namespace Scintilla
	{
		HWND			getCurrent();
		void			replaceSelection(const std::basic_string<byte>& buffer);
		bool			getSelection(const byte** pdata, size_t* length, size_t* start = NULL, size_t* end = NULL);
	};

	namespace Buffer
	{
		uptr_t			getCurrent();
		bool			is8Bit(uptr_t);
		bool			isCurrent8Bit();
		void			getPath(uptr_t bufferid, string& path, string& filename, string& extension);
	};

	namespace Windows
	{
		void			copyToClipboard(const std::basic_string<byte>& buffer);
	};

	namespace NPP
	{
		HINSTANCE		getDLLHandle();
		HWND			getWindow();
		bool			setCommand(size_t index, TCHAR *cmdName, PFUNCPLUGINCMD pFunc, ShortcutKey *sk, bool check0nInit = false);
	};

	namespace BC
	{
		void			prepareHMAC(crypt::Options::Crypt::HMAC& hmac, int header_version);
		void			preparePassword(std::string& password, int header_version);
	};
};

#endif