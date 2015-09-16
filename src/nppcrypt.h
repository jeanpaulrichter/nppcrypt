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

#ifndef NPPCRYPT_DEFINE_H
#define NPPCRYPT_DEFINE_H

#include "npp/PluginInterface.h"
#include "exception.h"
#include "encoding.h"
#include "preferences.h"
#include "crypt.h"
#include "dlg_crypt.h"
#include "dlg_hash.h"
#include "dlg_random.h"
#include "dlg_about.h"
#include "dlg_config.h"
#include "dlg_auth.h"

#include "tinyxml2\tinyxml2.h"
#include <string>
#include <fstream>
#include <sstream>
#include <map>

const TCHAR NPP_PLUGIN_NAME[] = TEXT("NppCrypt");
const int NPPCRYPT_VERSION = 101;

// -------------------------------------------------------

BOOL APIENTRY DllMain( HANDLE hModule, DWORD  reasonForCall, LPVOID lpReserved );
extern "C" __declspec(dllexport) void setInfo(NppData notpadPlusData);
extern "C" __declspec(dllexport) const TCHAR * getName();
extern "C" __declspec(dllexport) FuncItem * getFuncsArray(int *nbF);
extern "C" __declspec(dllexport) void beNotified(SCNotification *notifyCode);
extern "C" __declspec(dllexport) LRESULT messageProc(UINT Message, WPARAM wParam, LPARAM lParam);
extern "C" __declspec(dllexport) BOOL isUnicode();

// ---- menu-functions -----------------------------------

void EncryptDlg();
void DecryptDlg();
void HashDlg();
void RandomDlg();
void PreferencesDlg();
void AboutDlg();

// -------------------------------------------------------

struct HeaderInfo {
	std::string s_salt;
	std::string s_iv;
	std::string s_tag;
	std::string s_hmac;
	size_t length;
	size_t body_start;
	size_t body_end;
	size_t hmac_start;
};

void writeHeader(std::string& header, HeaderInfo& info, const Crypt::Options& opt);
bool readHeader(const unsigned char* in, unsigned int in_len, Crypt::Options& opt, HeaderInfo& info);

// ---- help functions -----------------------------------

bool setCommand(size_t index, TCHAR *cmdName, PFUNCPLUGINCMD pFunc, ShortcutKey *sk = NULL, bool check0nInit = false);
HWND getCurScintilla();
void getFilename(const TCHAR* path, TCHAR* filename, int buf_size);

#endif