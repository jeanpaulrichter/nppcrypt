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

#include "dlg_preferences.h"
#include "unicode.h"
#include "preferences.h"
#include "resource.h"
#include "commctrl.h"
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>

INT_PTR CALLBACK DlgPreferences::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message) 
	{
    case WM_INITDIALOG:
	{
		::SendDlgItemMessage(_hSelf, IDC_PREF_FILES_ENABLE, BM_SETCHECK, preferences.files.enable, 0);
		::SendDlgItemMessage(_hSelf, IDC_PREF_FILES_ASK, BM_SETCHECK, preferences.files.askonsave, 0);
		::SendDlgItemMessage(_hSelf, IDC_PREF_FILES_EXT, EM_LIMITTEXT, NPPC_FILE_EXT_MAXLENGTH, 0);
		::SetDlgItemText(_hSelf, IDC_PREF_FILES_EXT, preferences.files.extension.c_str());

		::SendDlgItemMessage(_hSelf, IDC_PREF_KEYS_VALUE, EM_LIMITTEXT, 24, 0);
		::SendDlgItemMessage(_hSelf, IDC_PREF_KEYS_LABEL, EM_LIMITTEXT, 30, 0);
		for (size_t i = 0; i< preferences.getKeyNum(); i++)
			::SendDlgItemMessage(_hSelf, IDC_PREF_KEYS_LIST, LB_ADDSTRING, 0, (LPARAM)preferences.getKeyLabel(i));

		url_help.init(_hInst, _hSelf);
		url_help.create(::GetDlgItem(_hSelf, IDC_PREF_HELP), TEXT(NPPC_PREFERENCES_HELP_URL));

		goToCenter();
		return TRUE;
	}
	case WM_COMMAND: 
	{
		switch (LOWORD(wParam))
		{
		case IDC_PREF_OK: 
		{
			preferences.files.enable = !!::SendDlgItemMessage(_hSelf, IDC_PREF_FILES_ENABLE, BM_GETCHECK, 0, 0);
			preferences.files.askonsave = !!::SendDlgItemMessage(_hSelf, IDC_PREF_FILES_ASK, BM_GETCHECK, 0, 0);

			TCHAR tstr[NPPC_FILE_EXT_MAXLENGTH + 1];
			::GetDlgItemText(_hSelf, IDC_PREF_FILES_EXT, tstr, NPPC_FILE_EXT_MAXLENGTH + 1);
			preferences.files.extension.assign(tstr);

			EndDialog(_hSelf, IDC_OK);
			return TRUE;
		}
		case IDC_CANCEL : case IDCANCEL:
		{
			EndDialog(_hSelf, IDC_CANCEL);
			return TRUE;
		}
		case IDC_PREF_KEYS_ADD:
		{
			if (HIWORD(wParam) == BN_CLICKED) {
				if (preferences.getKeyNum() >= 20) {
					::MessageBox(_hSelf, TEXT("20 presets should be enough..."), TEXT("Error"), MB_OK);
					return FALSE;
				}
				CPreferences::KeyPreset temp;
				::GetDlgItemText(_hSelf, IDC_PREF_KEYS_LABEL, temp.label, 31);
				if (!lstrlen(temp.label)) {
					::MessageBox(_hSelf, TEXT("Please enter key-label."), TEXT("Error"), MB_OK);
					return FALSE;
				}
				TCHAR	tvalue[25];
				byte	tstr[24];
				size_t	i;
				memset(temp.data, 0, 16);
				::GetDlgItemText(_hSelf, IDC_PREF_KEYS_VALUE, tvalue, 25);
				for (i = 0; i < 24; i++)
					tstr[i] = static_cast<byte>(tvalue[i]);

				using namespace CryptoPP;
				StringSource((const byte*)tstr, 24, true, new Base64Decoder(new ArraySink(temp.data, 16)));

				for (i = 0; i < 16; i++) {
					if (temp.data[i] != 0)
						break;
				}
				if (i == 16) {
					::MessageBox(_hSelf, TEXT("The key value must be 16 bytes encoded as base64."), TEXT("Error"), MB_OK); break;
				}

				preferences.addKey(temp);
				::SendDlgItemMessage(_hSelf, IDC_PREF_KEYS_LIST, LB_ADDSTRING, 0, (LPARAM)temp.label);
				::SendDlgItemMessage(_hSelf, IDC_PREF_KEYS_LIST, LB_SETCURSEL, preferences.getKeyNum() - 1, 0);
			}
			break;
		}
		case IDC_PREF_KEYS_DEL:
		{
			if (HIWORD(wParam) == BN_CLICKED) {
				int sel = (int)::SendDlgItemMessage(_hSelf, IDC_PREF_KEYS_LIST, LB_GETCURSEL, 0, 0);
				if (sel > 0 && preferences.delKey((size_t)sel)) {
					::SendDlgItemMessage(_hSelf, IDC_PREF_KEYS_LIST, LB_DELETESTRING, sel, 0);
					::SetDlgItemText(_hSelf, IDC_PREF_KEYS_LABEL, TEXT(""));
					::SetDlgItemText(_hSelf, IDC_PREF_KEYS_VALUE, TEXT(""));
				}
			}
			break;
		}
		case IDC_PREF_KEYS_RANDOM:
		{
			if (HIWORD(wParam) == BN_CLICKED) {
				using namespace CryptoPP;
				unsigned char t_rand[16];
				OS_GenerateRandomBlock(true, t_rand, 16);
				TCHAR tvalue[25];
				char t_rand_s[24];
				ArraySource(t_rand, 16, true, new Base64Encoder(new ArraySink((byte*)t_rand_s, 24)));
				for (size_t i = 0; i < 24; i++) {
					tvalue[i] = static_cast<TCHAR>(t_rand_s[i]);
				}
				tvalue[24] = 0;
				::SetDlgItemText(_hSelf, IDC_PREF_KEYS_VALUE, tvalue);
			}
			break;
		}
		case IDC_PREF_KEYS_LIST:
		{
			if (HIWORD(wParam) == LBN_SELCHANGE) {
				int sel = (int)::SendDlgItemMessage(_hSelf, IDC_PREF_KEYS_LIST, LB_GETCURSEL, 0, 0);
				if (sel >= 0) {
					using namespace CryptoPP;
					char tstr[24];
					TCHAR tvalue[25];
					ArraySource(preferences.getKey((size_t)sel), 16, true, new Base64Encoder(new ArraySink((byte*)tstr, 24)));
					for (size_t i = 0; i < 24; i++) {
						tvalue[i] = tstr[i];
					}
					tvalue[24] = 0;
					::SetDlgItemText(_hSelf, IDC_PREF_KEYS_VALUE, tvalue);
					::SetDlgItemText(_hSelf, IDC_PREF_KEYS_LABEL, preferences.getKeyLabel((size_t)sel));
				}
			}
			break;
		}
		}
		break;
	}
	}
	return FALSE;
}

