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

#include "help.h"
#include "exception.h"
#include "mdef.h"
#include "preferences.h"
#include "npp/PluginInterface.h"
#include "npp/Definitions.h"

extern NppData		nppData;
extern HINSTANCE	m_hInstance;
extern FuncItem		funcItem[NPPC_FUNC_COUNT];

HWND helper::Scintilla::getCurrent()
{
	int which = -1;
	::SendMessage(nppData._nppHandle, NPPM_GETCURRENTSCINTILLA, 0, (LPARAM)&which);
	if (which == 0)	{
		return nppData._scintillaMainHandle;
	} else if (which == 1) {
		return nppData._scintillaSecondHandle;
	} else {
		throw CExc(CExc::Code::unexpected);
	}
}

size_t helper::Scintilla::getSelectionLength()
{
	HWND hCurScintilla = helper::Scintilla::getCurrent();
	size_t selStart = ::SendMessage(hCurScintilla, SCI_GETSELECTIONSTART, 0, 0);
	size_t selEnd = ::SendMessage(hCurScintilla, SCI_GETSELECTIONEND, 0, 0);
	return selEnd - selStart;
}

bool helper::Scintilla::getSelection(const byte** pdata, size_t* length, size_t* start, size_t* end)
{
	if (pdata == NULL || length == NULL) {
		return false;
	}
	*pdata = NULL;
	*length = 0;

	HWND hCurScintilla = helper::Scintilla::getCurrent();
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

void helper::Scintilla::replaceSelection(const std::basic_string<byte>& buffer)
{
	HWND hCurScintilla = helper::Scintilla::getCurrent();
	size_t selStart = ::SendMessage(hCurScintilla, SCI_GETSELECTIONSTART, 0, 0);
	::SendMessage(hCurScintilla, SCI_BEGINUNDOACTION, 0, 0);
	::SendMessage(hCurScintilla, SCI_TARGETFROMSELECTION, 0, 0);
	::SendMessage(hCurScintilla, SCI_REPLACETARGET, buffer.size(), (LPARAM)&buffer[0]);
	::SendMessage(hCurScintilla, SCI_SETSEL, selStart, selStart + buffer.size());
	::SendMessage(hCurScintilla, SCI_ENDUNDOACTION, 0, 0);
}

// ---------------------------------------------------------------------------------------------------------------------

uptr_t helper::Buffer::getCurrent()
{
	return ::SendMessage(nppData._nppHandle, NPPM_GETCURRENTBUFFERID, 0, 0);
}

bool helper::Buffer::is8Bit(uptr_t id)
{
	int cur_buffer_enc = (int)::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, id, 0);
	return (cur_buffer_enc == uni8Bit || cur_buffer_enc == uniUTF8 || cur_buffer_enc == uniCookie);
}

bool helper::Buffer::isCurrent8Bit()
{
	int cur_buffer_enc = (int)::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, ::SendMessage(nppData._nppHandle, NPPM_GETCURRENTBUFFERID, 0, 0), 0);
	return (cur_buffer_enc == uni8Bit || cur_buffer_enc == uniUTF8 || cur_buffer_enc == uniCookie);
}

void helper::Buffer::getPath(uptr_t bufferid, std::wstring& path, std::wstring& filename, std::wstring& extension)
{
	int path_length = (int)::SendMessage(nppData._nppHandle, NPPM_GETFULLPATHFROMBUFFERID, bufferid, NULL);
	if (path_length <= 0) {
		throw CExc(CExc::Code::unexpected);
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

void helper::Windows::copyToClipboard(const std::basic_string<byte>& buffer)
{
	if (!OpenClipboard(NULL)) {
		return;
	}
	EmptyClipboard();

	HGLOBAL hglbCopy = GlobalAlloc(GMEM_MOVEABLE, (buffer.size() + 1) * sizeof(byte));
	if (hglbCopy == NULL) {
		CloseClipboard();
		return;
	}

	unsigned char *lpucharCopy = (unsigned char *)GlobalLock(hglbCopy);
	memcpy(lpucharCopy, buffer.c_str(), buffer.size() * sizeof(byte));
	lpucharCopy[buffer.size()] = 0;
	GlobalUnlock(hglbCopy);

	SetClipboardData(CF_TEXT, hglbCopy);

	HGLOBAL hglbLenCopy = GlobalAlloc(GMEM_MOVEABLE, sizeof(unsigned long));
	if (hglbLenCopy == NULL) {
		CloseClipboard();
		return;
	}

	unsigned long *lpLenCopy = (unsigned long *)GlobalLock(hglbLenCopy);
	*lpLenCopy = (unsigned long)buffer.size();
	GlobalUnlock(hglbLenCopy);

	UINT f = RegisterClipboardFormat(CF_NPPTEXTLEN);
	SetClipboardData(f, hglbLenCopy);

	CloseClipboard();
}

void helper::Windows::wchar_to_utf8(const wchar_t* i, int i_len, std::string& o)
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

void helper::Windows::utf8_to_wchar(const char* i, int i_len, std::wstring& o)
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

void helper::Windows::error(HWND hwnd, const char* msg)
{
	std::wstring temp;
	helper::Windows::utf8_to_wchar(msg, -1, temp);
	::MessageBox(hwnd, temp.c_str(), TEXT("Error"), MB_OK);
}

// ---------------------------------------------------------------------------------------------------------------------

HINSTANCE helper::NPP::getDLLHandle()
{
	return m_hInstance;
}

HWND helper::NPP::getWindow()
{
	return nppData._nppHandle;
}

bool helper::NPP::setCommand(size_t index, TCHAR *cmdName, PFUNCPLUGINCMD pFunc, ShortcutKey *sk, bool check0nInit)
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