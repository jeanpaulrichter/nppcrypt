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

#include "dlg_initdata.h"
#include "exception.h"
#include "resource.h"
#include "unicode.h"

DlgInitdata::DlgInitdata() : ModalDialog()
{
};

bool DlgInitdata::doDialog(crypt::InitStrings* data, bool salt, bool iv, bool tag)
{
	_data = data;
	_salt = salt;
	_iv = iv;
	_tag = tag;
	if (!_data) {
		return false;
	}
	return ModalDialog::doDialog();
}

INT_PTR CALLBACK DlgInitdata::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_INITDIALOG:
	{
		::SendDlgItemMessage(_hSelf, IDC_INITDATA_SALT, EM_LIMITTEXT, 1024, 0);
		::SendDlgItemMessage(_hSelf, IDC_INITDATA_IV, EM_LIMITTEXT, 1024, 0);
		::SendDlgItemMessage(_hSelf, IDC_INITDATA_TAG, EM_LIMITTEXT, 1024, 0);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_INITDATA_SALT), _salt);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_INITDATA_IV), _iv);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_INITDATA_TAG), _tag);

		goToCenter();
		return TRUE;
	}
	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case IDC_OK:
		{
			if (_salt) {
				int len = GetWindowTextLength(::GetDlgItem(_hSelf, IDC_INITDATA_SALT));
				if (len <= 0) {
					::MessageBox(_hSelf, TEXT("Please enter a salt-value!"), TEXT("Error"), MB_OK); break;
					return FALSE;
				}
				else {
					std::vector<TCHAR> tstr(len + 1);
					::GetDlgItemText(_hSelf, IDC_INITDATA_SALT, tstr.data(), (int)tstr.size());
					tstr.pop_back();
					unicode::wchar_to_utf8(tstr.data(), (int)tstr.size(), _data->salt);
				}
			}
			if (_iv) {
				int len = GetWindowTextLength(::GetDlgItem(_hSelf, IDC_INITDATA_IV));
				if (len <= 0) {
					::MessageBox(_hSelf, TEXT("Please enter a iv-value!"), TEXT("Error"), MB_OK); break;
					return FALSE;
				}
				else {
					std::vector<TCHAR> tstr(len + 1);
					::GetDlgItemText(_hSelf, IDC_INITDATA_IV, tstr.data(), (int)tstr.size());
					tstr.pop_back();
					unicode::wchar_to_utf8(tstr.data(), (int)tstr.size(), _data->iv);
				}
			}
			if (_tag) {
				int len = GetWindowTextLength(::GetDlgItem(_hSelf, IDC_INITDATA_TAG));
				if (len <= 0) {
					::MessageBox(_hSelf, TEXT("Please enter a tag-value!"), TEXT("Error"), MB_OK); break;
					return FALSE;
				}
				else {
					std::vector<TCHAR> tstr(len + 1);
					::GetDlgItemText(_hSelf, IDC_INITDATA_TAG, tstr.data(), (int)tstr.size());
					tstr.pop_back();
					unicode::wchar_to_utf8(tstr.data(), (int)tstr.size(), _data->tag);
				}
			}
			EndDialog(_hSelf, IDC_OK);
			return TRUE;
		}
		case IDC_CANCEL: case IDCANCEL:
		{
			EndDialog(_hSelf, IDC_CANCEL);
			return TRUE;
		}
		}
		break;
	}
	}
	return FALSE;
}
