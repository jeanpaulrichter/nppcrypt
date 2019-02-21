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
    "failed to parse preferences-file.",
    "failed to create header.",
    "failed to write to output file.",
    "failed to read input file."
};

const char* ExcInvalid::messages[] = {
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
    "invalid header.",    
    "failed to parse header version.",
    "invalid hmac-data.",
    "invalid hmac-hash.",
    "invalid cipher.",
    "invalid encoding.",
    "invalid keyderivation.",
    "failed to parse salt-vector.",
    "failed to parse IV.",
    "failed to parse tag-vector",
    "failed to parse aad flag",
    "invalid hash.",
    "failed to parse hash-key.",
    "invalid action parameter.",
    "cannot convert to same encoding.",
    "invalid eol.",
    "failed to parse case."
    "no header found.",
    "missing key-length.",
    "missing cipher-mode.",
    "missing hmac-key.",
    "missing IV.",
    "missing Salt.",
    "missing password.",
    "hash does not support key.",
    "hash requires key.",
    "only decryption of utf8 file possible."
};

const char* ExcInfo::messages[] = {
    "the file is empty.",
    "HMAC authentification failed.",
    "Sadly this header version is no longer supported.",
    "Please select the text you want to encrypt/decrypt. If you want to encrypt the entire file see 'nppcrypt-files' under 'preferences'.",
    "Please select the text you want to convert!"
};

const char* ExcInfo::urls[] = {
    NULL,
    "https://github.com/jeanpaulrichter/nppcrypt#faq_5",
    "https://github.com/jeanpaulrichter/nppcrypt#faq_4",
    "https://github.com/jeanpaulrichter/nppcrypt#faq_2",
    NULL
};

const char* ExcInfo::url_captions[] = {
    NULL,
    "more information",
    "help me!",
    "more information",
    NULL
};