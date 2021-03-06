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

#include "help.h"
#include "exception.h"
#include "mdef.h"
#include "preferences.h"
#include "npp/PluginInterface.h"
#include "npp/Definitions.h"
#include "messagebox.h"

extern NppData      nppData;
extern HINSTANCE    m_hInstance;
extern FuncItem     funcItem[NPPC_FUNC_COUNT];

HWND help::scintilla::getCurrent()
{
    int which = -1;
    ::SendMessage(nppData._nppHandle, NPPM_GETCURRENTSCINTILLA, 0, (LPARAM)&which);
    if (which == 0) {
        return nppData._scintillaMainHandle;
    } else if (which == 1) {
        return nppData._scintillaSecondHandle;
    } else {
        throwError(no_scintilla_handle);
    }
}

size_t help::scintilla::getSelectionLength()
{
    HWND hCurScintilla = help::scintilla::getCurrent();
    size_t selStart = ::SendMessage(hCurScintilla, SCI_GETSELECTIONSTART, 0, 0);
    size_t selEnd = ::SendMessage(hCurScintilla, SCI_GETSELECTIONEND, 0, 0);
    return selEnd - selStart;
}

bool help::scintilla::getSelection(const byte** pdata, size_t* length, size_t* start, size_t* end)
{
    if (pdata == NULL || length == NULL) {
        return false;
    }
    *pdata = NULL;
    *length = 0;

    HWND hCurScintilla = help::scintilla::getCurrent();
    size_t selStart = ::SendMessage(hCurScintilla, SCI_GETSELECTIONSTART, 0, 0);
    size_t selEnd = ::SendMessage(hCurScintilla, SCI_GETSELECTIONEND, 0, 0);
    size_t data_length = selEnd - selStart;

    if (start != NULL) {
        *start = selStart;
    }
    if (end != NULL) {
        *end = selEnd;
    }
    if (data_length <= 0) {
        return false;
    }

    *pdata = (const byte*)::SendMessage(hCurScintilla, SCI_GETRANGEPOINTER, selStart, selEnd);
    if (pdata == NULL) {
        return false;
    }
    *length = data_length;

    return true;
}

void help::scintilla::replaceSelection(const std::basic_string<byte>& buffer)
{
    HWND hCurScintilla = help::scintilla::getCurrent();
    size_t selStart = ::SendMessage(hCurScintilla, SCI_GETSELECTIONSTART, 0, 0);
    ::SendMessage(hCurScintilla, SCI_BEGINUNDOACTION, 0, 0);
    ::SendMessage(hCurScintilla, SCI_TARGETFROMSELECTION, 0, 0);
    ::SendMessage(hCurScintilla, SCI_REPLACETARGET, buffer.size(), (LPARAM)&buffer[0]);
    ::SendMessage(hCurScintilla, SCI_SETSEL, selStart, selStart + buffer.size());
    ::SendMessage(hCurScintilla, SCI_ENDUNDOACTION, 0, 0);
}

void help::scintilla::replaceSelection(const char* s, size_t len)
{
    HWND hCurScintilla = help::scintilla::getCurrent();
    size_t selStart = ::SendMessage(hCurScintilla, SCI_GETSELECTIONSTART, 0, 0);
    ::SendMessage(hCurScintilla, SCI_BEGINUNDOACTION, 0, 0);
    ::SendMessage(hCurScintilla, SCI_TARGETFROMSELECTION, 0, 0);
    ::SendMessage(hCurScintilla, SCI_REPLACETARGET, len, (LPARAM)s);
    ::SendMessage(hCurScintilla, SCI_SETSEL, selStart, selStart + len);
    ::SendMessage(hCurScintilla, SCI_ENDUNDOACTION, 0, 0);
}

// ---------------------------------------------------------------------------------------------------------------------

uptr_t help::buffer::getCurrent()
{
    return ::SendMessage(nppData._nppHandle, NPPM_GETCURRENTBUFFERID, 0, 0);
}

bool help::buffer::is8Bit(uptr_t id)
{
    int cur_buffer_enc = (int)::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, id, 0);
    return (cur_buffer_enc == uni8Bit || cur_buffer_enc == uniUTF8 || cur_buffer_enc == uniCookie);
}

bool help::buffer::isCurrent8Bit()
{
    int cur_buffer_enc = (int)::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, ::SendMessage(nppData._nppHandle, NPPM_GETCURRENTBUFFERID, 0, 0), 0);
    return (cur_buffer_enc == uni8Bit || cur_buffer_enc == uniUTF8 || cur_buffer_enc == uniCookie);
}

void help::buffer::getPath(uptr_t bufferid, std::wstring& path, std::wstring& filename, std::wstring& extension)
{
    int path_length = (int)::SendMessage(nppData._nppHandle, NPPM_GETFULLPATHFROMBUFFERID, bufferid, NULL);
    if (path_length <= 0) {
        throwError(no_file_path);
    }
    path.resize(path_length + 1);
    ::SendMessage(nppData._nppHandle, NPPM_GETFULLPATHFROMBUFFERID, bufferid, (LPARAM)&path[0]);
    path.pop_back();
    size_t x = path.find_last_of('/');
    size_t x2 = path.find_last_of('\\');
    if (x2 > x || x == std::string::npos) {
        x = x2;
    }
    filename = path.substr(x + 1);
    x = filename.find_last_of('.');
    if (x != std::string::npos && filename.size() > x) {
        extension = filename.substr(x + 1);
    }
}

// ---------------------------------------------------------------------------------------------------------------------

void help::windows::copyToClipboard(const unsigned char* s, size_t len)
{
    if (!OpenClipboard(NULL)) {
        return;
    }
    EmptyClipboard();

    HGLOBAL hglbCopy = GlobalAlloc(GMEM_MOVEABLE, (len + 1) * sizeof(byte));
    if (hglbCopy == NULL) {
        CloseClipboard();
        return;
    }

    unsigned char *lpucharCopy = (unsigned char *)GlobalLock(hglbCopy);
    memcpy(lpucharCopy, s, len * sizeof(char));
    lpucharCopy[len] = 0;
    GlobalUnlock(hglbCopy);

    SetClipboardData(CF_TEXT, hglbCopy);

    HGLOBAL hglbLenCopy = GlobalAlloc(GMEM_MOVEABLE, sizeof(unsigned long));
    if (hglbLenCopy == NULL) {
        CloseClipboard();
        return;
    }

    unsigned long *lpLenCopy = (unsigned long *)GlobalLock(hglbLenCopy);
    *lpLenCopy = (unsigned long)len;
    GlobalUnlock(hglbLenCopy);

    UINT f = RegisterClipboardFormat(CF_NPPTEXTLEN);
    SetClipboardData(f, hglbLenCopy);

    CloseClipboard();
}

void help::windows::copyToClipboard(const std::basic_string<byte>& buffer)
{
    copyToClipboard(buffer.c_str(), buffer.size());
}

void help::windows::wchar_to_utf8(const wchar_t* i, int i_len, std::string& o)
{
    if (i_len < -1) {
        i_len = -1;
    }
    int bytelen = WideCharToMultiByte(CP_UTF8, 0, i, i_len, NULL, 0, NULL, false);
    if (bytelen < 1) {
        throwError(utf8conversion);
    }
    o.resize((size_t)bytelen);
    if (!WideCharToMultiByte(CP_UTF8, 0, i, i_len, &o[0], bytelen, NULL, false)) {
        throwError(utf8conversion);
    }
    if (o.size() > 0 && i_len == -1) {
        o.pop_back();
    }
}

void help::windows::wchar_to_utf8(const wchar_t* i, int i_len, nppcrypt::secure_string& o)
{
    if (i_len < -1) {
        i_len = -1;
    }
    int bytelen = WideCharToMultiByte(CP_UTF8, 0, i, i_len, NULL, 0, NULL, false);
    if (bytelen < 1) {
        throwError(utf8conversion);
    }
    o.resize((size_t)bytelen);
    if (!WideCharToMultiByte(CP_UTF8, 0, i, i_len, &o[0], bytelen, NULL, false)) {
        throwError(utf8conversion);
    }
    if (o.size() > 0 && i_len == -1) {
        o.pop_back();
    }
}

void help::windows::utf8_to_wchar(const char* i, int i_len, std::wstring& o)
{
    if (i_len < -1) {
        i_len = -1;
    }
    int charlen = ::MultiByteToWideChar(CP_UTF8, 0, i, i_len, NULL, 0);
    if (charlen < 1) {
        throwError(wchar_conversion);
    }
    o.resize((size_t)charlen);
    if (!MultiByteToWideChar(CP_UTF8, 0, i, i_len, &o[0], charlen)) {
        throwError(wchar_conversion);
    }
    if (o.size() > 0 && i_len == -1) {
        o.pop_back();
    }
}

void help::windows::utf8_to_wchar(const char* i, int i_len, nppcrypt::secure_wstring& o)
{
    if (i_len < -1) {
        i_len = -1;
    }
    int charlen = ::MultiByteToWideChar(CP_UTF8, 0, i, i_len, NULL, 0);
    if (charlen < 1) {
        throwError(wchar_conversion);
    }
    o.resize((size_t)charlen);
    if (!MultiByteToWideChar(CP_UTF8, 0, i, i_len, &o[0], charlen)) {
        throwError(wchar_conversion);
    }
    if (o.size() > 0 && i_len == -1) {
        o.pop_back();
    }
}

void help::windows::error(HWND hwnd, const char* msg)
{
    std::wstring temp;
    try {
        help::windows::utf8_to_wchar(msg, -1, temp);
    } catch (...) {}
    ::MessageBox(hwnd, temp.c_str(), TEXT("Error"), MB_OK);
}

// ---------------------------------------------------------------------------------------------------------------------

HINSTANCE help::npp::getDLLHandle()
{
    return m_hInstance;
}

HWND help::npp::getWindow()
{
    return nppData._nppHandle;
}

bool help::npp::setCommand(size_t index, TCHAR *cmdName, PFUNCPLUGINCMD pFunc, ShortcutKey *sk, bool check0nInit)
{
    if (index >= NPPC_FUNC_COUNT) {
        return false;
    }
    if (!pFunc) {
        return false;
    }

    lstrcpy(funcItem[index]._itemName, cmdName);
    funcItem[index]._pFunc = pFunc;
    funcItem[index]._init2Check = check0nInit;
    funcItem[index]._pShKey = sk;

    return true;
}