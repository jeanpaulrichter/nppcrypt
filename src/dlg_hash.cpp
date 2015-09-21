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

#include "resource.h"
#include "dlg_hash.h"
#include "preferences.h"

DlgHash::DlgHash() : Window(), no_ascii(false)
{}

DlgHash::~DlgHash()
{}

void DlgHash::init(HINSTANCE hInst, HWND parent, crypt::Options::Hash* opt)
{
	Window::init(hInst, parent);
	options = opt;
};

bool DlgHash::doDialog(bool no_ascii)
{
	if(!options)
		return false;
	this->no_ascii = no_ascii;
	if(DialogBoxParam(_hInst, MAKEINTRESOURCE(IDD_HASH), _hParent,  (DLGPROC)dlgProc, (LPARAM)this)==IDC_OK)
		return true;
	return false;
}

BOOL CALLBACK DlgHash::dlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam) 
{
	switch (Message) 
	{
		case WM_INITDIALOG :
		{
			DlgHash *pHashDialog = (DlgHash *)(lParam);
			pHashDialog->_hSelf = hWnd;
			::SetWindowLongPtr(hWnd, GWL_USERDATA, (long)lParam);
			pHashDialog->run_dlgProc(Message, wParam, lParam);
			return TRUE;
		}

		default :
		{
			DlgHash *pHashDialog = reinterpret_cast<DlgHash *>(::GetWindowLong(hWnd, GWL_USERDATA));
			if (!pHashDialog)
				return FALSE;
			return pHashDialog->run_dlgProc(Message, wParam, lParam);
		}

	}
	return FALSE;
}

BOOL CALLBACK DlgHash::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message) 
	{
	case WM_INITDIALOG :
	{
		if(no_ascii)
		{
			if(options->encoding == crypt::Encoding::ascii) 
				options->encoding = crypt::Encoding::base16;
			::EnableWindow(::GetDlgItem(_hSelf,IDC_HASH_ENC_ASCII),false);
		}
		::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_ASCII, BM_SETCHECK, (options->encoding == crypt::Encoding::ascii), 0);
		::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE16, BM_SETCHECK, (options->encoding == crypt::Encoding::base16), 0);
		::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE64, BM_SETCHECK, (options->encoding == crypt::Encoding::base64), 0);

		crypt::help::Iterator::setup(crypt::help::Iterator::Hash);
		while (crypt::help::Iterator::next()) {
			::SendDlgItemMessage(_hSelf, IDC_HASH_ALGO, CB_ADDSTRING, 0, (LPARAM)crypt::help::Iterator::getString());
		}
		::SendDlgItemMessage(_hSelf, IDC_HASH_ALGO, CB_SETCURSEL, (int)options->algorithm, 0);
			
		::SendDlgItemMessage(_hSelf, IDC_HASH_USE_KEY, BM_SETCHECK, options->use_key, 0);
		::SendDlgItemMessage(_hSelf, IDC_HASH_KEYEDIT, EM_LIMITTEXT, NPPC_HMAC_INPUT_MAX, 0);

		for (size_t i = 0; i < preferences.getKeyNum(); i++) {
			::SendDlgItemMessage(_hSelf, IDC_HASH_KEYLIST, CB_ADDSTRING, 0, (LPARAM)preferences.getKeyLabel(i));
		}			
		if (options->key_id >= 0) {
			::SendDlgItemMessage(_hSelf, IDC_HASH_KEYLIST, CB_SETCURSEL, options->key_id, 0);
			::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO1, BM_SETCHECK, true, 0);
		}
		else {
			string tstr;
			#ifdef UNICODE
			Encode::utf8_to_wchar(options->key_input.c_str(), options->key_input.size(), tstr);
			#else
			tstr.assign(options->key_input);
			#endif
			::SetDlgItemText(_hSelf, IDC_HASH_KEYEDIT, tstr.c_str());
			::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO1, BM_SETCHECK, true, 0);
		}
		if (!crypt::help::IsOpenSSLHash(options->algorithm))
		{
			enableKeyControls(false);
			::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_USE_KEY), false);
		}
		else {
			::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_USE_KEY), true);
			enableKeyControls(options->use_key);
		}

		url_help_enc.init(_hInst, _hSelf);
		url_help_enc.create(::GetDlgItem(_hSelf, IDC_HASH_HELP_ENC), crypt::help::getHelpURL(options->encoding));
		url_help_hash.init(_hInst, _hSelf);
		url_help_hash.create(::GetDlgItem(_hSelf, IDC_HASH_HELP_HASH), crypt::help::getHelpURL(options->algorithm));
		url_help_key.init(_hInst, _hSelf);
		url_help_key.create(::GetDlgItem(_hSelf, IDC_HASH_HELP_KEY), TEXT(NPPC_HASH_KEY_HELP_URL));

		return TRUE;
	} break;

	case WM_COMMAND : 
	{
		switch (HIWORD(wParam))
		{
		case BN_CLICKED:
		{
			switch (LOWORD(wParam))
			{
			case IDC_OK:
			{
				options->algorithm = (crypt::Hash)::SendDlgItemMessage(_hSelf, IDC_HASH_ALGO, CB_GETCURSEL, 0, 0);
				if (::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_ASCII, BM_GETCHECK, 0, 0))
					options->encoding = crypt::Encoding::ascii;
				else if (::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE16, BM_GETCHECK, 0, 0))
					options->encoding = crypt::Encoding::base16;
				else
					options->encoding = crypt::Encoding::base64;
				if (IsWindowEnabled(::GetDlgItem(_hSelf, IDC_HASH_USE_KEY)))
				{
					options->use_key = !!::SendDlgItemMessage(_hSelf, IDC_HASH_USE_KEY, BM_GETCHECK, 0, 0);
					options->key_id = ::SendDlgItemMessage(_hSelf, IDC_HASH_KEY, CB_GETCURSEL, 0, 0);
				}
				else {
					options->use_key = false;
				}				

				if (options->use_key)
				{
					if (options->key_id < 0)
					{
						TCHAR temp_key[NPPC_HMAC_INPUT_MAX + 1];
						::GetDlgItemText(_hSelf, IDC_HASH_KEY, temp_key, NPPC_HMAC_INPUT_MAX + 1);
						if (!lstrlen(temp_key))
						{
							::MessageBox(_hSelf, TEXT("Please enter a key."), TEXT("Error"), MB_OK);
							return FALSE;
						}
						try {
							#ifdef UNICODE
							Encode::wchar_to_utf8(temp_key, -1, options->key_input);
							#else
							options->key.assign(temp_key);
							#endif
						}
						catch (CExc& exc) {
							::MessageBox(_hSelf, exc.getErrorMsg(), TEXT("Error"), MB_OK);
							return false;
						}
					}
				}

				EndDialog(_hSelf, IDC_OK);
				return TRUE;
			} break;

			case IDC_CANCEL:
			{
				EndDialog(_hSelf, IDC_CANCEL);
				return TRUE;
			} break;

			case IDC_HASH_USE_KEY:
			{
				bool use_key = !!::SendDlgItemMessage(_hSelf, IDC_HASH_USE_KEY, BM_GETCHECK, 0, 0);
				enableKeyControls(use_key);
			} break;

			case IDC_HASH_ENC_ASCII:
			{
				url_help_enc.changeURL(crypt::help::getHelpURL(crypt::Encoding::ascii));
			} break;

			case IDC_HASH_ENC_BASE16:
			{
				url_help_enc.changeURL(crypt::help::getHelpURL(crypt::Encoding::base16));
			} break;

			case IDC_HASH_ENC_BASE64:
			{
				url_help_enc.changeURL(crypt::help::getHelpURL(crypt::Encoding::base64));
			} break;

			default:
				break;
			}
		} break;
		case CBN_SELCHANGE:
		{
			switch (LOWORD(wParam))
			{
			case IDC_HASH_KEYLIST:
			{
				::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO1, BM_SETCHECK, true, 0);
				::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO2, BM_SETCHECK, false, 0);
			} break;

			case IDC_HASH_ALGO:
			{
				crypt::Hash cur_sel = crypt::Hash(::SendDlgItemMessage(_hSelf, IDC_HASH_ALGO, CB_GETCURSEL, 0, 0));
				if (!crypt::help::IsOpenSSLHash(cur_sel))
				{
					enableKeyControls(false);
					::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_USE_KEY), false);
				}
				else {
					::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_USE_KEY), true);
					bool use_key = !!::SendDlgItemMessage(_hSelf, IDC_HASH_USE_KEY, BM_GETCHECK, 0, 0);
					enableKeyControls(use_key);
				}
				url_help_hash.changeURL(crypt::help::getHelpURL(cur_sel));
			} break;
			}
		}
		break;

		case EN_SETFOCUS:
		{
			if (LOWORD(wParam) == IDC_HASH_KEYEDIT) {
				::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO1, BM_SETCHECK, false, 0);
				::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO2, BM_SETCHECK, true, 0);
			}
		} break;
		}

	} break;
	}
	return FALSE;
}

void DlgHash::enableKeyControls(bool v)
{
	::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEYLIST), v);
	::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEYEDIT), v);
	::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEYRADIO1), v);
	::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEYRADIO2), v);
}