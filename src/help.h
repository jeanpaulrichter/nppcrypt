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
        HWND            getCurrent();
        void            replaceSelection(const std::basic_string<byte>& buffer);
        void            replaceSelection(const char* s, size_t len);
        size_t          getSelectionLength();
        bool            getSelection(const byte** pdata, size_t* length, size_t* start = NULL, size_t* end = NULL);
    };

    namespace Buffer
    {
        uptr_t          getCurrent();
        bool            is8Bit(uptr_t);
        bool            isCurrent8Bit();
        void            getPath(uptr_t bufferid, std::wstring& path, std::wstring& filename, std::wstring& extension);
    };

    namespace Windows
    {
        void            copyToClipboard(const unsigned char* s, size_t len);
        void            copyToClipboard(const std::basic_string<byte>& buffer);
        void            wchar_to_utf8(const wchar_t* i, int i_len, std::string& o);
        void            wchar_to_utf8(const wchar_t* i, int i_len, crypt::secure_string& o);
        void            utf8_to_wchar(const char* i, int i_len, std::wstring& o);
        void            utf8_to_wchar(const char* i, int i_len, crypt::secure_wstring& o);
        void            error(HWND hwnd, const char* msg);

        class ToWCHAR
        {
        public:
            ToWCHAR(const char* s, int len = -1) {
                if (len < -1) {
                    len = -1;
                }
                if (s && len) {
                    int charlen = ::MultiByteToWideChar(CP_UTF8, 0, s, len, NULL, 0);
                    if (charlen >= 1) {
                        buf.resize((size_t)charlen);
                        if (MultiByteToWideChar(CP_UTF8, 0, s, len, &buf[0], charlen)) {
                            if (buf.size() > 0 && len == -1) {
                                buf.pop_back();
                            }
                        }
                    }
                }
            }
            ~ToWCHAR() {
                buf = L"FUCK";
            }
            const wchar_t* c_str() {
                return buf.c_str();
            }
        private:
            std::wstring buf;
        };

    };

    namespace NPP
    {
        HINSTANCE       getDLLHandle();
        HWND            getWindow();
        bool            setCommand(size_t index, TCHAR *cmdName, PFUNCPLUGINCMD pFunc, ShortcutKey *sk, bool check0nInit = false);
    };
};

#endif