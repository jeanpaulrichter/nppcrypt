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

#ifndef MDEF_DEFINE_H
#define MDEF_DEFINE_H

#include <Windows.h>



const TCHAR NPP_PLUGIN_NAME[] = TEXT("NppCrypt");
const int	NPPCRYPT_VERSION = 1011;

#define		NPPC_ABOUT_TEXT			"nppcrypt v1.0.1.1"
#define		NPPC_ABOUT_LINK			"www.cerberus-design.de/nppcrypt/readme"
#define		NPPC_ABOUT_URL			"http://www.cerberus-design.de/nppcrypt/readme.v1011.txt"

#define		NPPC_DEF_HMAC_KEY		"bJmX/AokoOlC}my."
#define		NPPC_DEF_HMAC_LABEL		"nppcrypt default"

#define		NPPC_HMAC_INPUT_MAX		32

#define		NPPC_DEF_FILE_EXT		"nppcrypt"
#define		NPPC_FILE_EXT_MAXLENGTH	32

#define		NPPC_HASH_KEY_HELP_URL	"http://www.cerberus-design.de/nppcrypt/hashkey.txt"


#ifdef UNICODE
typedef std::wstring string;
#else
typedef std::string string;
#endif

#endif
