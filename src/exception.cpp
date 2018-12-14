/*
This file is part of nppcrypt
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

#include "exception.h"

ExcError::ExcError(ID id, const char* func, unsigned int line) noexcept : id(id), line(line)
{
	std::ostringstream o;
	o << "[" << func << ":" << line << "] " << messages[(unsigned)id];
	msg.assign(o.str());
};

const char* ExcError::messages[] = { 
	"unexpected error.", 
	"failed to get scintilla character pointer.", 
	"failed to get scintilla handle.", 
	"failed to get file path.", 
	"conversion to utf8 failed.", 
	"conversion to wchar failed.", 
	"failed to read preferences-files.", 
	"failed to parse preferences-file."
};

const char* ExcInvalid::messages[] = { 
	"no header found.", 
	"invalid key-preset id.", 
	"invalid cipher mode.", 
	"invalid key-length.", 
	"invalid pbkdf2 parameters.", 
	"invalid bcrypt parameters.", 
	"invalid scrypt parameters.", 
	"invalid salt-length.", 
	"invalid bcrypt salt-length (must be 16 bytes).", 
	"invalid line-length.", 
	"hash does not support this digest-length.", 
	"hash does not support key.", 
	"hash requires key.", 
	"cannot convert encoding.", 
	"invalid header.", 
	"failed to parse header version.", 
	"invalid hmac-data.", 
	"invalid hmac-hash.", 
	"invalid cipher.", 
	"missing key-length.", 
	"missing cipher-mode.", 
	"invalid encoding.", 
	"invalid keyderivation.", 
	"failed to parse salt-vector.", 
	"failed to parse IV.", 
	"failed to parse tag-vector"
};

const char* ExcInfo::messages[] = { 
	"the file is empty.", 
	"hmac authentification failed.", 
	"wrong header version.", 
};