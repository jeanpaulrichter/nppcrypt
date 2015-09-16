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

#include "encoding.h"
#include "preferences.h"
#include "dlg_config.h"
#include "resource.h"
#include "commctrl.h"

#include <openssl/rand.h>

DlgConfig::DlgConfig(): Window()
{
};

void DlgConfig::init(HINSTANCE hInst, HWND parent)
{
	Window::init(hInst, parent);
};

bool DlgConfig::doDialog()
{
	if(DialogBoxParam(_hInst, MAKEINTRESOURCE(IDD_PREFERENCES), _hParent,  (DLGPROC)dlgProc, (LPARAM)this)==IDC_OK)
		return true;
	return false;
}

BOOL CALLBACK DlgConfig::dlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam) 
{
	switch (Message) 
	{
		case WM_INITDIALOG :
		{
			DlgConfig *pDlgConfig = (DlgConfig *)(lParam);
			pDlgConfig->_hSelf = hWnd;
			::SetWindowLongPtr(hWnd, GWL_USERDATA, (long)lParam);
			pDlgConfig->run_dlgProc(Message, wParam, lParam);
			return TRUE;
		}

		default :
		{
			DlgConfig *pDlgConfig = reinterpret_cast<DlgConfig *>(::GetWindowLong(hWnd, GWL_USERDATA));
			if (!pDlgConfig)
				return FALSE;
			return pDlgConfig->run_dlgProc(Message, wParam, lParam);
		}

	}
	return FALSE;
}

BOOL CALLBACK DlgConfig::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message) 
	{
        case WM_INITDIALOG :
		{
			// output/encoding-options:
			::SendDlgItemMessage(_hSelf, IDC_PREF_EOL_WINDOWS, BM_SETCHECK, Encode::Options::win_line_endings, 0);
			::SendDlgItemMessage(_hSelf, IDC_PREF_EOL_UNIX, BM_SETCHECK, !Encode::Options::win_line_endings, 0);
			::SendDlgItemMessage(_hSelf, IDC_PREF_HEX_SPACES, BM_SETCHECK, Encode::Options::hex_spaces, 0);
			::SendDlgItemMessage(_hSelf, IDC_PREF_HEX_LOWERCASE, BM_SETCHECK, Encode::Options::hex_lowercase, 0);
			::SendDlgItemMessage(_hSelf, IDC_PREF_HEX_UPPERCASE, BM_SETCHECK, !Encode::Options::hex_lowercase, 0);
			::SendDlgItemMessage(_hSelf, IDC_PREF_HEX_LV_SPIN, UDM_SETRANGE, true, (LPARAM)MAKELONG(9999, 0));
			::SendDlgItemMessage(_hSelf, IDC_PREF_HEX_LV_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(_hSelf,IDC_PREF_HEX_LV), 0);
			::SendDlgItemMessage(_hSelf, IDC_PREF_HEX_LV_SPIN, UDM_SETPOS32, 0, Encode::Options::hex_values_p_line);
			::SendDlgItemMessage(_hSelf, IDC_PREF_BASE64_LV_SPIN, UDM_SETRANGE, true, (LPARAM)MAKELONG(9999, 0));
			::SendDlgItemMessage(_hSelf, IDC_PREF_BASE64_LV_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(_hSelf,IDC_PREF_BASE64_LV), 0);
			::SendDlgItemMessage(_hSelf, IDC_PREF_BASE64_LV_SPIN, UDM_SETPOS32, 0, Encode::Options::base64_chars_p_line);
			// nppcrypt-files:
			::SendDlgItemMessage(_hSelf, IDC_PREF_FILES_ENABLE, BM_SETCHECK, preferences.files.enable, 0);
			::SendDlgItemMessage(_hSelf, IDC_PREF_FILES_ASK, BM_SETCHECK, preferences.files.askonsave, 0);
			::SendDlgItemMessage(_hSelf, IDC_PREF_FILES_EXT, EM_LIMITTEXT, 30, 0);
			::SetDlgItemText(_hSelf, IDC_PREF_FILES_EXT, preferences.files.extension);
			// key-presets:
			::SendDlgItemMessage(_hSelf, IDC_PREF_KEYS_VALUE, EM_LIMITTEXT, 24, 0);
			::SendDlgItemMessage(_hSelf, IDC_PREF_KEYS_LABEL, EM_LIMITTEXT, 30, 0);
			for(size_t i=0; i< preferences.getKeyNum(); i++)
				::SendDlgItemMessage(_hSelf, IDC_PREF_KEYS_LIST, LB_ADDSTRING, 0, (LPARAM)preferences.getKeyLabel(i));

			return TRUE;
		}
		case WM_COMMAND : 
	    {
		    switch (LOWORD(wParam))
		    {
				case IDC_PREF_OK: {
					
					Encode::Options::win_line_endings = !!::SendDlgItemMessage(_hSelf, IDC_PREF_EOL_WINDOWS, BM_GETCHECK, 0, 0);
					Encode::Options::hex_spaces = !!::SendDlgItemMessage(_hSelf, IDC_PREF_HEX_SPACES, BM_GETCHECK, 0, 0);
					Encode::Options::hex_lowercase  = !!::SendDlgItemMessage(_hSelf, IDC_PREF_HEX_LOWERCASE, BM_GETCHECK, 0, 0);
					Encode::Options::hex_values_p_line = ::SendDlgItemMessage(_hSelf, IDC_PREF_HEX_LV_SPIN, UDM_GETPOS32, 0, 0);
					Encode::Options::base64_chars_p_line = ::SendDlgItemMessage(_hSelf, IDC_PREF_BASE64_LV_SPIN, UDM_GETPOS32, 0, 0);

					preferences.files.enable = !!::SendDlgItemMessage(_hSelf, IDC_PREF_FILES_ENABLE, BM_GETCHECK, 0, 0);
					preferences.files.askonsave = !!::SendDlgItemMessage(_hSelf, IDC_PREF_FILES_ASK, BM_GETCHECK, 0, 0);
					::GetDlgItemText(_hSelf, IDC_PREF_FILES_EXT, preferences.files.extension, 31);
					preferences.files.ext_length = lstrlen(preferences.files.extension);

					EndDialog(_hSelf, IDC_OK);
					return TRUE; }
				case IDC_CANCEL :
				    EndDialog(_hSelf, IDC_CANCEL);
					return TRUE;

				case IDC_PREF_KEYS_ADD:
					if(HIWORD( wParam ) == BN_CLICKED) {
						if(preferences.getKeyNum() >= 20) {
							::MessageBox(_hSelf, TEXT("20 presets should be enough..."), TEXT("Error"), MB_OK); break;
						}
						CPreferences::KeyPreset temp;
						::GetDlgItemText(_hSelf, IDC_PREF_KEYS_LABEL, temp.label, 31);
						if(!lstrlen(temp.label)) {
							::MessageBox(_hSelf, TEXT("Please enter key-label."), TEXT("Error"), MB_OK); break;
						}
						TCHAR tvalue[25];
						char  tstr[24];
						::GetDlgItemText(_hSelf, IDC_PREF_KEYS_VALUE, tvalue, 25);
						for(size_t i=0; i<24; i++)
							tstr[i] = static_cast<char>(tvalue[i]);
						if(Encode::base64_to_bin(tstr,24,NULL) != 16) {
							::MessageBox(_hSelf, TEXT("The key value must be 16 bytes encoded as base64."), TEXT("Error"), MB_OK); break;
						} else {
							Encode::base64_to_bin(tstr,24,temp.data);
							preferences.addKey(temp);
							::SendDlgItemMessage(_hSelf, IDC_PREF_KEYS_LIST, LB_ADDSTRING, 0, (LPARAM)temp.label);
							::SendDlgItemMessage(_hSelf, IDC_PREF_KEYS_LIST, LB_SETCURSEL, preferences.getKeyNum()-1, 0);
						}
					}
					break;
				case IDC_PREF_KEYS_DEL:
					if(HIWORD( wParam ) == BN_CLICKED) {
						int sel = ::SendDlgItemMessage(_hSelf, IDC_PREF_KEYS_LIST, LB_GETCURSEL, 0, 0);
						if(sel > 0 && preferences.delKey((size_t)sel)) {
							::SendDlgItemMessage(_hSelf, IDC_PREF_KEYS_LIST, LB_DELETESTRING, sel, 0);
							::SetDlgItemText(_hSelf, IDC_PREF_KEYS_LABEL, TEXT(""));
							::SetDlgItemText(_hSelf, IDC_PREF_KEYS_VALUE, TEXT(""));
						}
					}
					break;
				case IDC_PREF_KEYS_RANDOM:
					if(HIWORD( wParam ) == BN_CLICKED) {
						unsigned char t_rand[16];
						if(RAND_bytes(t_rand, 16) == 1) {
							TCHAR tvalue[25];
							char t_rand_s[24];
							Encode::bin_to_base64(t_rand, 16, t_rand_s, true);
							for(size_t i=0; i<24; i++)
								tvalue[i] = t_rand_s[i];
							tvalue[24]=0;
							::SetDlgItemText(_hSelf, IDC_PREF_KEYS_VALUE, tvalue);
						} else {
							::MessageBox(_hSelf, TEXT("Failed to generate random bytes!"), TEXT("Error"), MB_OK);
						}
					}
					break;
				case IDC_PREF_KEYS_LIST:
					if(HIWORD( wParam ) == LBN_SELCHANGE) {
						int sel = ::SendDlgItemMessage(_hSelf, IDC_PREF_KEYS_LIST, LB_GETCURSEL, 0, 0);
						if(sel >= 0) {
							char tstr[24];
							TCHAR tvalue[25];
							Encode::bin_to_base64(preferences.getKey((size_t)sel), 16, tstr, true);
							for(size_t i=0; i<24; i++)
								tvalue[i] = tstr[i];
							tvalue[24]=0;
							::SetDlgItemText(_hSelf, IDC_PREF_KEYS_VALUE, tvalue);
							::SetDlgItemText(_hSelf, IDC_PREF_KEYS_LABEL, preferences.getKeyLabel((size_t)sel));
						}
					}
					break;
			    default :
				    break;
		    }
		    break;
	    }
	}
	return FALSE;
}

