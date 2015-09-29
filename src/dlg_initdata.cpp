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

DlgInitdata::DlgInitdata() : Window()
{
};

void DlgInitdata::init(HINSTANCE hInst, HWND parent)
{
	Window::init(hInst, parent);
};

bool DlgInitdata::doDialog(crypt::InitStrings* data, bool salt, bool iv, bool tag)
{
	_data = data;
	_salt = salt;
	_iv = iv;
	_tag = tag;
	if (!_data)
		return false;
	if (DialogBoxParam(_hInst, MAKEINTRESOURCE(IDD_INITDATA), _hParent, (DLGPROC)dlgProc, (LPARAM)this) == IDC_OK)
		return true;
	return false;
}

BOOL CALLBACK DlgInitdata::dlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
	switch (Message)
	{
	case WM_INITDIALOG:
	{
		DlgInitdata *pDlgInitdata = (DlgInitdata *)(lParam);
		pDlgInitdata->_hSelf = hWnd;
		::SetWindowLongPtr(hWnd, GWL_USERDATA, (long)lParam);
		pDlgInitdata->run_dlgProc(Message, wParam, lParam);
		return TRUE;
	}

	default:
	{
		DlgInitdata *pDlgInitdata = reinterpret_cast<DlgInitdata *>(::GetWindowLong(hWnd, GWL_USERDATA));
		if (!pDlgInitdata)
			return FALSE;
		return pDlgInitdata->run_dlgProc(Message, wParam, lParam);
	}

	}
	return FALSE;
}

BOOL CALLBACK DlgInitdata::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
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
		return TRUE;
	} break;

	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case IDC_OK:
		{
			if (_salt)
			{
				int len = GetWindowTextLength(::GetDlgItem(_hSelf, IDC_INITDATA_SALT));
				if (len <= 0) {
					::MessageBox(_hSelf, TEXT("Please enter a salt-value!"), TEXT("Error"), MB_OK); break;
					return FALSE;
				}
				else {
					std::vector<TCHAR> tstr(len + 1);
					::GetDlgItemText(_hSelf, IDC_INITDATA_SALT, tstr.data(), tstr.size());
					tstr.pop_back();
					unicode::wchar_to_utf8(tstr.data(), tstr.size(), _data->salt);
				}
			}
			if (_iv)
			{
				int len = GetWindowTextLength(::GetDlgItem(_hSelf, IDC_INITDATA_IV));
				if (len <= 0) {
					::MessageBox(_hSelf, TEXT("Please enter a iv-value!"), TEXT("Error"), MB_OK); break;
					return FALSE;
				}
				else {
					std::vector<TCHAR> tstr(len + 1);
					::GetDlgItemText(_hSelf, IDC_INITDATA_IV, tstr.data(), tstr.size());
					tstr.pop_back();
					unicode::wchar_to_utf8(tstr.data(), tstr.size(), _data->iv);
				}
			}
			if (_tag)
			{
				int len = GetWindowTextLength(::GetDlgItem(_hSelf, IDC_INITDATA_TAG));
				if (len <= 0) {
					::MessageBox(_hSelf, TEXT("Please enter a tag-value!"), TEXT("Error"), MB_OK); break;
					return FALSE;
				}
				else {
					std::vector<TCHAR> tstr(len + 1);
					::GetDlgItemText(_hSelf, IDC_INITDATA_TAG, tstr.data(), tstr.size());
					tstr.pop_back();
					unicode::wchar_to_utf8(tstr.data(), tstr.size(), _data->tag);
				}
			}
			EndDialog(_hSelf, IDC_OK);
			return TRUE;
		} break;

		case IDC_CANCEL: case IDCANCEL:
		{
			EndDialog(_hSelf, IDC_CANCEL);
			return TRUE;
		} break;

		default:
			break;
		}
	} break;
	}
	return FALSE;
}
