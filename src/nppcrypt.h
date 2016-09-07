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

#ifndef NPPCRYPT_H_DEF
#define NPPCRYPT_H_DEF

#include "mdef.h"
#include "npp/PluginInterface.h"

BOOL APIENTRY									DllMain( HANDLE hModule, DWORD  reasonForCall, LPVOID lpReserved );
extern "C" __declspec(dllexport) void			setInfo(NppData notpadPlusData);
extern "C" __declspec(dllexport) BOOL			isUnicode();
extern "C" __declspec(dllexport) const TCHAR *	getName();
extern "C" __declspec(dllexport) FuncItem *		getFuncsArray(int *nbF);
extern "C" __declspec(dllexport) LRESULT		messageProc(UINT Message, WPARAM wParam, LPARAM lParam);
extern "C" __declspec(dllexport) void			beNotified(SCNotification *notifyCode);

void EncryptDlg();
void DecryptDlg();
void HashDlg();
void RandomDlg();
void ConvertDlg();
void PreferencesDlg();
void AboutDlg();

#endif