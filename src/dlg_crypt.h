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

#ifndef DLG_CRYPT_H_DEF
#define DLG_CRYPT_H_DEF

#ifndef _WIN32_IE
#define _WIN32_IE 0x0500
#endif
#include <windows.h>
#include <commctrl.h>

#include "npp/ModalDialog.h"
#include "npp/URLCtrl.h"
#include "crypt.h"
#include "unicode.h"

class DlgCrypt : public ModalDialog
{
public:
	enum class Operation { Enc, Dec };

						DlgCrypt();
    void				destroy();
	bool				doDialog(Operation operation, crypt::Options::Crypt* options, bool no_bin_output = false, const string* filename = NULL);

private:
	INT_PTR CALLBACK	run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam);

	void				initDialog();
	void				checkSpinControlValue(int ctrlID);
	void				changeActiveTab(int id);	
	void				setCipherInfo(crypt::Cipher cipher, crypt::Mode mode);
	void				enableKeyDeriControls();
	bool				updateOptions();
	bool				OnClickOK();
	void				OnCipherChange();	
	void				OnCipherCategoryChange(int category, bool change_cipher=false);
	void				OnEncodingChange(crypt::Encoding enc);
	
	
	Operation				operation;
	const string*			filename;
	bool					no_bin_output;
	crypt::Options::Crypt*	options;

	bool					confirm_password;	
	crypt::Cipher			t_cipher;
	crypt::KeyDerivation	t_key_derivation;
	string					t_password;

	HWND					hwnd_basic;
	HWND					hwnd_auth;
	HWND					hwnd_key;
	HWND					hwnd_iv;
	HWND					hwnd_encoding;

	URLCtrl					url_help[7];
	enum HelpURL { encoding, cipher, mode, salt, keyalgo, hmac, iv };
};


#endif