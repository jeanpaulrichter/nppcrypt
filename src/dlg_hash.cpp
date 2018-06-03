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

#include "resource.h"
#include "dlg_hash.h"
#include "preferences.h"
#include "npp/PluginInterface.h"
#include "npp/Definitions.h"
#include "help.h"

DlgHash::DlgHash(crypt::Options::Hash& opt) : ModalDialog(), options(opt)
{
}

void DlgHash::destroy()
{
	if (brush_red) {
		DeleteObject(brush_red);
	}
	ModalDialog::destroy();
};

INT_PTR CALLBACK DlgHash::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message) 
	{
	case WM_INITDIALOG:
	{
		if (!brush_red) {
			brush_red = CreateSolidBrush(RGB(255, 0, 0));
		}
		invalid_password = false;
		if(!helper::Buffer::isCurrent8Bit()) {
			if (options.encoding == crypt::Encoding::ascii) {
				options.encoding = crypt::Encoding::base16;
				::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_ENC_ASCII), false);
			}
		}
		::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_ASCII, BM_SETCHECK, (options.encoding == crypt::Encoding::ascii), 0);
		::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE16, BM_SETCHECK, (options.encoding == crypt::Encoding::base16), 0);
		::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE32, BM_SETCHECK, (options.encoding == crypt::Encoding::base32), 0);
		::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE64, BM_SETCHECK, (options.encoding == crypt::Encoding::base64), 0);

		std::wstring temp_str;
		crypt::help::Iter::setup_hash();
		while (crypt::help::Iter::next()) {
			helper::Windows::utf8_to_wchar(crypt::help::Iter::getString(), -1, temp_str);
			::SendDlgItemMessage(_hSelf, IDC_HASH_ALGO, CB_ADDSTRING, 0, (LPARAM)temp_str.c_str());
		}
		::SendDlgItemMessage(_hSelf, IDC_HASH_ALGO, CB_SETCURSEL, (int)options.algorithm, 0);
			
		::SendDlgItemMessage(_hSelf, IDC_HASH_USE_KEY, BM_SETCHECK, options.use_key, 0);
		::SendDlgItemMessage(_hSelf, IDC_HASH_PASSWORD, EM_LIMITTEXT, NPPC_HMAC_INPUT_MAX, 0);
		::SendDlgItemMessage(_hSelf, IDC_HASH_PASSWORD, EM_SETPASSWORDCHAR, '*', 0);

		for (size_t i = 0; i < preferences.getKeyNum(); i++) {			
			::SendDlgItemMessage(_hSelf, IDC_HASH_KEYLIST, CB_ADDSTRING, 0, (LPARAM)preferences.getKeyLabel(i));
		}
		::SendDlgItemMessage(_hSelf, IDC_HASH_KEYLIST, CB_SETCURSEL, 0, 0);
		::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO1, BM_SETCHECK, true, 0);

		if (crypt::help::checkHashProperty(options.algorithm, crypt::HashProperties::hmac_possible) || crypt::help::checkHashProperty(options.algorithm, crypt::HashProperties::key)) {
			::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_USE_KEY), true);
			enableKeyControls(options.use_key); 
			if (crypt::help::checkHashProperty(options.algorithm, crypt::HashProperties::hmac_possible)) {
				::SetDlgItemText(_hSelf, IDC_HASH_USE_KEY, TEXT("with key (hmac):"));
			} else {
				::SetDlgItemText(_hSelf, IDC_HASH_USE_KEY, TEXT("with key:"));
			}
		} else {
			enableKeyControls(false);
			::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_USE_KEY), false);
		}

		::SendDlgItemMessage(_hSelf, IDC_HASH_PASSWORD_ENC, CB_ADDSTRING, 0, (LPARAM)TEXT("utf8"));
		::SendDlgItemMessage(_hSelf, IDC_HASH_PASSWORD_ENC, CB_ADDSTRING, 0, (LPARAM)TEXT("base16"));
		::SendDlgItemMessage(_hSelf, IDC_HASH_PASSWORD_ENC, CB_ADDSTRING, 0, (LPARAM)TEXT("base32"));
		::SendDlgItemMessage(_hSelf, IDC_HASH_PASSWORD_ENC, CB_ADDSTRING, 0, (LPARAM)TEXT("base64"));
		::SendDlgItemMessage(_hSelf, IDC_HASH_PASSWORD_ENC, CB_SETCURSEL, 0, 0);

 		url_help_hash.init(_hInst, _hSelf);
		url_help_hash.create(::GetDlgItem(_hSelf, IDC_HASH_HELP_HASH), crypt::help::getHelpURL(options.algorithm));

		goToCenter();
		return TRUE;
	}
	case WM_COMMAND: 
	{
		switch (HIWORD(wParam))
		{
		case BN_CLICKED:
		{
			switch (LOWORD(wParam))
			{
			case IDC_CANCEL: case IDCANCEL:
			{
				EndDialog(_hSelf, IDC_CANCEL);
				return TRUE;
			}
			case IDC_OK: case IDC_HASH_TOCLIPBOARD:
			{
				try {
					const byte*				pdata;
					size_t					data_length;
					std::basic_string<byte>	buffer;

					if (!updateOptions()) {
						return TRUE;
					}
					helper::Scintilla::getSelection(&pdata, &data_length);
					crypt::hash(options, buffer, { { pdata, data_length} });
					if (LOWORD(wParam) == IDC_OK) {
						helper::Scintilla::replaceSelection(buffer);
					} else {
						helper::Windows::copyToClipboard(buffer);
					}
					options.key.clear();
					EndDialog(_hSelf, IDC_OK);
				} catch (CExc& exc) {
					helper::Windows::error(_hSelf, exc.what());
				} catch (...) {
					::MessageBox(_hSelf, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
				}
				break;
			}
			case IDC_HASH_USE_KEY:
			{
				bool use_key = !!::SendDlgItemMessage(_hSelf, IDC_HASH_USE_KEY, BM_GETCHECK, 0, 0);
				enableKeyControls(use_key);
				break;
			}
			case IDC_HASH_KEYRADIO1: case IDC_HASH_KEYRADIO2:
			{
				enableKeyControls(true);
				break;
			}
			case IDC_HASH_PASSWORD_SHOW:
			{
				bool show = !!::SendDlgItemMessage(_hSelf, IDC_HASH_PASSWORD_SHOW, BM_GETCHECK, 0, 0);
				::SendDlgItemMessage(_hSelf, IDC_HASH_PASSWORD, EM_SETPASSWORDCHAR, show ? 0 : '*', 0);
				InvalidateRect(::GetDlgItem(_hSelf, IDC_HASH_PASSWORD), 0, TRUE);
				::SetFocus(::GetDlgItem(_hSelf, IDC_HASH_PASSWORD));
				break;
			}
			}
			break;
		}
		case CBN_SELCHANGE:
		{
			switch (LOWORD(wParam))
			{
			case IDC_HASH_ALGO:
			{
				crypt::Hash cur_sel = crypt::Hash(::SendDlgItemMessage(_hSelf, IDC_HASH_ALGO, CB_GETCURSEL, 0, 0));
				if (crypt::help::checkHashProperty(cur_sel, crypt::HashProperties::hmac_possible) || crypt::help::checkHashProperty(cur_sel, crypt::HashProperties::key)) {
					if (crypt::help::checkHashProperty(cur_sel, crypt::HashProperties::hmac_possible)) {
						::SetDlgItemText(_hSelf, IDC_HASH_USE_KEY, TEXT("with key (hmac):"));
					} else {
						::SetDlgItemText(_hSelf, IDC_HASH_USE_KEY, TEXT("with key:"));
					}
					::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_USE_KEY), true);
					bool use_key = !!::SendDlgItemMessage(_hSelf, IDC_HASH_USE_KEY, BM_GETCHECK, 0, 0);
					enableKeyControls(use_key);
				} else {
					enableKeyControls(false);
					::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_USE_KEY), false);
				}
				url_help_hash.changeURL(crypt::help::getHelpURL(cur_sel));
				break;
			}
			case IDC_HASH_PASSWORD_ENC:
			{
				checkPassword(false);
				InvalidateRect(::GetDlgItem(_hSelf, IDC_HASH_PASSWORD), 0, TRUE);
				::SetFocus(::GetDlgItem(_hSelf, IDC_HASH_PASSWORD));
				break;
			}
			}
			break;
		}
		case EN_CHANGE:
		{
			if (LOWORD(wParam) == IDC_HASH_PASSWORD) {
				checkPassword(false);
				InvalidateRect(::GetDlgItem(_hSelf, IDC_HASH_PASSWORD), 0, TRUE);
			}
			break;
		}
		}
		break;
	}
	case WM_CTLCOLOREDIT:
	{
		if (invalid_password && (HWND)lParam == GetDlgItem(_hSelf, IDC_HASH_PASSWORD)) {
			SetBkMode((HDC)wParam, TRANSPARENT);
			return (INT_PTR)brush_red;
		}
		break;
	}
	}
	return FALSE;
}

bool DlgHash::updateOptions()
{
	options.algorithm = (crypt::Hash)::SendDlgItemMessage(_hSelf, IDC_HASH_ALGO, CB_GETCURSEL, 0, 0);
	if (::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_ASCII, BM_GETCHECK, 0, 0)) {
		options.encoding = crypt::Encoding::ascii;
	} else if (::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE16, BM_GETCHECK, 0, 0)) {
		options.encoding = crypt::Encoding::base16;
	} else if (::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE32, BM_GETCHECK, 0, 0)) {
		options.encoding = crypt::Encoding::base32;
	} else {
		options.encoding = crypt::Encoding::base64;
	}

	if (IsWindowEnabled(::GetDlgItem(_hSelf, IDC_HASH_USE_KEY))) {
		options.use_key = !!::SendDlgItemMessage(_hSelf, IDC_HASH_USE_KEY, BM_GETCHECK, 0, 0);
	} else {
		options.use_key = false;
	}

	if (options.use_key) {
		if (!!::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO2, BM_GETCHECK, 0, 0)) {
			if (!checkPassword(true)) {
				InvalidateRect(::GetDlgItem(_hSelf, IDC_HASH_PASSWORD), 0, TRUE);
				::SetFocus(::GetDlgItem(_hSelf, IDC_HASH_PASSWORD));
				return false;
			}
		} else {
			size_t keyid = (size_t)::SendDlgItemMessage(_hSelf, IDC_HASH_KEYLIST, CB_GETCURSEL, 0, 0);
			options.key.set(preferences.getKey(keyid), 16);
		}
	}
	return true;
}

void DlgHash::enableKeyControls(bool v)
{
	::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEYRADIO1), v);
	::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEYRADIO2), v);
	if (v) {
		bool password = !!::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO2, BM_GETCHECK, 0, 0);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEYLIST), !password);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_PASSWORD), password);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_PASSWORD_ENC), password);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_PASSWORD_SHOW), password);
		if (password) {
			checkPassword(false);
			InvalidateRect(::GetDlgItem(_hSelf, IDC_HASH_PASSWORD), 0, TRUE);
			::SetFocus(::GetDlgItem(_hSelf, IDC_HASH_PASSWORD));
		}
	} else {
		::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEYLIST), false);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_PASSWORD), false);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_PASSWORD_ENC), false);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_PASSWORD_SHOW), false);
	}
}

bool DlgHash::checkPassword(bool updatedata)
{
	int len = GetWindowTextLength(::GetDlgItem(_hSelf, IDC_HASH_PASSWORD));
	if (len <= 0) {
		invalid_password = true;
	} else {
		crypt::secure_string	temp;
		crypt::UserData			data;
		crypt::Encoding			enc;

		enc = (crypt::Encoding)::SendDlgItemMessage(_hSelf, IDC_HASH_PASSWORD_ENC, CB_GETCURSEL, 0, 0);
		getText(IDC_HASH_PASSWORD, temp);
		data.set(temp.c_str(), temp.size(), enc);
		invalid_password = (data.size() == 0);
		if (!invalid_password && updatedata) {
			options.key.set(data);
		}
	}
	return !invalid_password;
}