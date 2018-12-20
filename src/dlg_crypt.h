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

#ifndef DLG_CRYPT_H_DEF
#define DLG_CRYPT_H_DEF

#ifndef _WIN32_IE
#define _WIN32_IE 0x0500
#endif
#include <windows.h>
#include <commctrl.h>

#include "modaldialog.h"
#include "ctl_help.h"
#include "crypt.h"
#include "cryptheader.h"
#include "preferences.h"

class DlgCrypt : public ModalDialog
{
public:
		 DlgCrypt();
    void destroy();
	bool encryptDialog(CryptInfo* crypt, crypt::UserData* iv, const std::wstring* filename = NULL);
	bool decryptDialog(CryptInfo* crypt, crypt::UserData* iv, const std::wstring* filename = NULL, bool disable_easymode = false);

private:
	enum class Operation { Encryption, Decryption };

	/* global message callback */
	INT_PTR CALLBACK run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam);

	bool setup(CryptInfo* crypt, crypt::UserData* iv, const std::wstring* filename);
	void setupDialog();
	void changeActiveTab(int id);
	void setModus(CryptInfo::Modus modus);

	bool prepareOptionsAdvanced();
	bool prepareOptionsEasy();
	bool OnClickOKAdvanced();
	bool OnClickOKEasy();

	/* methods to validate user-input: */
	void checkSpinControlValue(int ctrlID);
	bool checkPassword(crypt::secure_string& s, bool strict);
	bool checkCustomIV(crypt::UserData& data, bool reencode);
	bool checkHMACKey(crypt::UserData& data, bool reencode);
	
	/* methods to change controls based on current selection */
	void updateEncodingControls(crypt::Encoding enc);
	void updateHashDigestControl(crypt::Hash h, HWND hwnd, int ctrlID);
	void updateKeyDerivationControls();
	void updateCipherControls();
	void updateHMACKeyControls();
	void updateCipherInfo();
	void updateIVControls();	
	
	Operation				operation;
	const std::wstring*		filename;
	CryptInfo*				crypt;
	crypt::UserData*		ivdata;
	bool					confirm_password;
	bool					no_easymode;

	struct CurStatus
	{
		CurStatus() : tab(-1), iv_length(0), key_length(0) {};

		CryptInfo::Modus		modus;
		crypt::Cipher			cipher;
		crypt::Mode				mode;
		crypt::KeyDerivation	key_derivation;
		crypt::secure_string	password;
		int						tab;
		size_t					iv_length;
		size_t					key_length;
	} current;

	struct InvalidInput
	{
		InvalidInput() : password(false), iv(false), hmac_key(false), brush(NULL) {};

		bool	password;
		bool	iv;
		bool	hmac_key;
		HBRUSH	brush;
	} invalid;

	struct MainDialogs
	{
		HWND tab;
		HWND easy;
	} dialogs;

	struct TabDialogs
	{
		TabDialogs() : basic(NULL), encoding(NULL), key(NULL), iv(NULL), auth(NULL){};

		HWND basic;
		HWND encoding;
		HWND key;
		HWND iv;
		HWND auth;		
	} tab;

	struct HelpControls
	{
		HelpCtrl cipher;
		HelpCtrl mode;
		HelpCtrl encoding;
		HelpCtrl salt;
		HelpCtrl keyalgorithm;
		HelpCtrl iv;
		HelpCtrl auth;
		HelpCtrl easymode;
	} help;
};


#endif