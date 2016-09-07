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
#include "npp/PluginInterface.h"
#include "npp/Definitions.h"
#include "help.h"

DlgHash::DlgHash(crypt::Options::Hash& opt) : DockingDlgInterface(IDD_HASH), options(opt)
{
}

void DlgHash::display(bool toShow) const
{
	DockingDlgInterface::display(toShow);
};

INT_PTR CALLBACK DlgHash::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message) 
	{
	case WM_INITDIALOG:
	{
		if(!helper::Buffer::isCurrent8Bit()) {
			if(options.encoding == crypt::Encoding::ascii)
				options.encoding = crypt::Encoding::base16;
		}
		::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_ASCII, BM_SETCHECK, (options.encoding == crypt::Encoding::ascii), 0);
		::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE16, BM_SETCHECK, (options.encoding == crypt::Encoding::base16), 0);
		::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE32, BM_SETCHECK, (options.encoding == crypt::Encoding::base32), 0);
		::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE64, BM_SETCHECK, (options.encoding == crypt::Encoding::base64), 0);

		crypt::help::Iter::setup_hash();
		while (crypt::help::Iter::next()) {
			::SendDlgItemMessage(_hSelf, IDC_HASH_ALGO, CB_ADDSTRING, 0, (LPARAM)crypt::help::Iter::getString());
		}
		::SendDlgItemMessage(_hSelf, IDC_HASH_ALGO, CB_SETCURSEL, (int)options.algorithm, 0);
			
		::SendDlgItemMessage(_hSelf, IDC_HASH_USE_KEY, BM_SETCHECK, options.use_key, 0);
		::SendDlgItemMessage(_hSelf, IDC_HASH_KEYEDIT, EM_LIMITTEXT, NPPC_HMAC_INPUT_MAX, 0);

		for (size_t i = 0; i < preferences.getKeyNum(); i++) {
			::SendDlgItemMessage(_hSelf, IDC_HASH_KEYLIST, CB_ADDSTRING, 0, (LPARAM)preferences.getKeyLabel(i));
		}			
		if (options.key_id >= 0) {
			::SendDlgItemMessage(_hSelf, IDC_HASH_KEYLIST, CB_SETCURSEL, options.key_id, 0);
			::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO1, BM_SETCHECK, true, 0);
		} else {
			string tstr;
			#ifdef UNICODE
			unicode::utf8_to_wchar(options.key_input.c_str(), (int)options.key_input.size(), tstr);
			#else
			tstr.assign(options.key_input);
			#endif
			::SetDlgItemText(_hSelf, IDC_HASH_KEYEDIT, tstr.c_str());
			::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO2, BM_SETCHECK, true, 0);
		}
		if (!crypt::help::canCalcHMAC(options.algorithm))	{
			enableKeyControls(false);
			::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_USE_KEY), false);
		} else {
			::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_USE_KEY), true);
			enableKeyControls(options.use_key);
		}

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
			case IDC_OK: case IDC_COPY:
			{
				try {
					const byte*				pdata;
					size_t					data_length;
					std::basic_string<byte>	buffer;

					HWND test1 = _hParent;
					HWND test2 = helper::NPP::getWindow();
					HWND test3 = GetWindow(_hSelf, GW_OWNER);

					if (!updateOptions()) {
						return TRUE;
					}
					helper::Scintilla::getSelection(&pdata, &data_length);
					crypt::hash(pdata, data_length, buffer, options);
					if (LOWORD(wParam) == IDC_OK) {
						helper::Scintilla::replaceSelection(buffer);
					} else {
						helper::Windows::copyToClipboard(buffer);
					}
				} catch (CExc& exc) {
					::MessageBox(_hSelf, exc.getMsg(), TEXT("Error"), MB_OK);
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
			}
			break;
		}
		case CBN_SELCHANGE:
		{
			switch (LOWORD(wParam))
			{
			case IDC_HASH_KEYLIST:
			{
				::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO1, BM_SETCHECK, true, 0);
				::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO2, BM_SETCHECK, false, 0);
				break;
			}
			case IDC_HASH_ALGO:
			{
				crypt::Hash cur_sel = crypt::Hash(::SendDlgItemMessage(_hSelf, IDC_HASH_ALGO, CB_GETCURSEL, 0, 0));
				if (!crypt::help::canCalcHMAC(cur_sel))
				{
					enableKeyControls(false);
					::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_USE_KEY), false);
				} else {
					::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_USE_KEY), true);
					bool use_key = !!::SendDlgItemMessage(_hSelf, IDC_HASH_USE_KEY, BM_GETCHECK, 0, 0);
					enableKeyControls(use_key);
				}
				url_help_hash.changeURL(crypt::help::getHelpURL(cur_sel));
				break;
			}
			}
			break;
		}
		case EN_SETFOCUS:
		{
			if (LOWORD(wParam) == IDC_HASH_KEYEDIT) {
				::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO1, BM_SETCHECK, false, 0);
				::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO2, BM_SETCHECK, true, 0);
			}
			break;
		}
		}
		break;
	} 
	}
	return FALSE;
}

bool DlgHash::updateOptions()
{
	options.algorithm = (crypt::Hash)::SendDlgItemMessage(_hSelf, IDC_HASH_ALGO, CB_GETCURSEL, 0, 0);
	if (::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_ASCII, BM_GETCHECK, 0, 0))
		options.encoding = crypt::Encoding::ascii;
	else if (::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE16, BM_GETCHECK, 0, 0))
		options.encoding = crypt::Encoding::base16;
	else if (::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE32, BM_GETCHECK, 0, 0))
		options.encoding = crypt::Encoding::base32;
	else
		options.encoding = crypt::Encoding::base64;

	// ---------- make sure no binary output for UCS-2 encoding:
	if (!helper::Buffer::isCurrent8Bit() && options.encoding == crypt::Encoding::ascii) {
		options.encoding = crypt::Encoding::base16;
		::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_ASCII, BM_SETCHECK, (options.encoding == crypt::Encoding::ascii), 0);
		::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE16, BM_SETCHECK, (options.encoding == crypt::Encoding::base16), 0);
		::MessageBox(_hSelf, TEXT("No binary output for UCS-2 encoding!"), TEXT("Error"), MB_OK);
		return false;
	}

	if (IsWindowEnabled(::GetDlgItem(_hSelf, IDC_HASH_USE_KEY))) {
		options.use_key = !!::SendDlgItemMessage(_hSelf, IDC_HASH_USE_KEY, BM_GETCHECK, 0, 0);
	} else {
		options.use_key = false;
	}

	if (options.use_key) {
		if (!!::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO2, BM_GETCHECK, 0, 0)) {
			TCHAR temp_key[NPPC_HMAC_INPUT_MAX + 1];
			::GetDlgItemText(_hSelf, IDC_HASH_KEYEDIT, temp_key, NPPC_HMAC_INPUT_MAX + 1);
			if (!lstrlen(temp_key))	{
				::MessageBox(_hSelf, TEXT("Please enter a key."), TEXT("Error"), MB_OK);
				return false;
			}
			#ifdef UNICODE
			unicode::wchar_to_utf8(temp_key, -1, options.key_input);
			#else
			options.key.assign(temp_key);
			#endif
			options.key_id = -1;
		} else {
			options.key_id = (int)::SendDlgItemMessage(_hSelf, IDC_HASH_KEYLIST, CB_GETCURSEL, 0, 0);
		}
		if (options.key_id >= 0) {
			options.key.resize(16);
			const unsigned char* tkey = preferences.getKey(options.key_id);
			options.key.assign(tkey, tkey + 16);
		}
		else {
			// hash input?
			options.key.resize(options.key_input.size());
			for (size_t i = 0; i < options.key.size(); i++)
				options.key[i] = (byte)options.key_input[i];
		}
	}
	return true;
}

void DlgHash::enableKeyControls(bool v)
{
	::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEYLIST), v);
	::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEYEDIT), v);
	::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEYRADIO1), v);
	::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEYRADIO2), v);
}