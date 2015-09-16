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

#ifndef DLG_CRYPT_DEFINE_H
#define DLG_CRYPT_DEFINE_H

#ifndef _WIN32_IE
#define _WIN32_IE 0x0500
#endif
#include <windows.h>
#include <commctrl.h>
#include <vector>

#include "resource.h"
#include "npp/Window.h"
#include "crypt.h"


class DlgCrypt : public Window
{
public:

	DlgCrypt();
    void init(HINSTANCE hInst, HWND parent);
    virtual void destroy();
	static DlgCrypt& Instance() { static DlgCrypt single; return single; }
   	bool doDialog(Crypt::Operation op, Crypt::Options* opt, const TCHAR* filename=NULL);

private:
	static BOOL CALLBACK dlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam);
	BOOL CALLBACK run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam);
	DlgCrypt(DlgCrypt const&);
	DlgCrypt& operator=(DlgCrypt const&);

	void enableKeyDeriControls();
	bool updateOptions();
	
	Crypt::Operation	operation;
	Crypt::Options*		options;

	const TCHAR*		filename;
	bool				confirm_password;

	struct {
		Crypt::Cipher			cipher;
		Crypt::KeyDerivation	key_derivation;
		TCHAR					password[Crypt::Constants::pw_length_max+1];
	} temp;

	HWND hwnd_basic;
	HWND hwnd_auth;
	HWND hwnd_key;
	HWND hwnd_iv;

	HINSTANCE mHinstance;
};


#endif