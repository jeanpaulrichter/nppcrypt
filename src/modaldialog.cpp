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

#include <stdio.h>
#include "modaldialog.h"
#include "help.h"
#include "exception.h"

void ModalDialog::init(HINSTANCE hInst, HWND parent, int dialogID, INT_PTR returnID)
{
	_hInst = hInst;
	_hParent = parent;
	_dlgID = dialogID;
	_returnID = returnID;
}

bool ModalDialog::doDialog()
{
	INT_PTR ret = DialogBoxParam(_hInst, MAKEINTRESOURCE(_dlgID), _hParent, dlgProc, reinterpret_cast<LPARAM>(this));

	if (ret == _returnID) {
		return true;
	}
	if (ret == 0 || ret == -1) {
		DWORD err = GetLastError();
		LPTSTR Error = 0;
		if (!::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL,	err, 0,	(LPTSTR)&Error,	0, NULL) == 0) {
			MessageBox(_hParent, Error, _T("Error: failed to create dialog"), MB_OK | MB_ICONWARNING);
		}
		if (Error) {
			::LocalFree(Error);
			Error = 0;
		}
	}
	return false;
}

void ModalDialog::destroy()
{
	if (_hSelf != NULL) {
		::SetWindowLongPtr(_hSelf, GWLP_USERDATA, (long)NULL);
		::DestroyWindow(_hSelf);
		_hSelf = NULL;
	}
};

void ModalDialog::goToCenter()
{
	RECT rc;
	::GetClientRect(_hParent, &rc);
	POINT center;
	center.x = rc.left + (rc.right - rc.left) / 2;
	center.y = rc.top + (rc.bottom - rc.top) / 2;
	::ClientToScreen(_hParent, &center);

	int x = center.x - (_rc.right - _rc.left) / 2;
	int y = center.y - (_rc.bottom - _rc.top) / 2;

	::SetWindowPos(_hSelf, HWND_TOP, x, y, _rc.right - _rc.left, _rc.bottom - _rc.top, SWP_SHOWWINDOW);
}

void ModalDialog::getText(int id, crypt::secure_string& str, HWND hwnd)
{
	if (hwnd == NULL) {
		hwnd = _hSelf;
	}
	int length = GetWindowTextLength(::GetDlgItem(hwnd, id));
	if (length <= 0) {
		str.clear();
	} else {
		try {
			crypt::secure_wstring temp;
			temp.resize((size_t)length + 1);
			::GetDlgItemText(hwnd, id, &temp[0], length + 1);
			helper::Windows::wchar_to_utf8(temp.c_str(), length, str);
		} catch (CExc& exc) {
			helper::Windows::error(_hSelf, exc.what());
		}
	}
}

void ModalDialog::setText(int id, const crypt::secure_string& str, HWND hwnd)
{
	if (hwnd == NULL) {
		hwnd = _hSelf;
	}
	if (str.size() == 0) {
		::SetDlgItemText(hwnd, id, TEXT(""));
	} else {
		try {
			crypt::secure_wstring temp;
			helper::Windows::utf8_to_wchar(str.c_str(), (int)str.size(), temp);
			::SetDlgItemText(hwnd, id, temp.c_str());
		} catch (CExc& exc) {
			helper::Windows::error(_hSelf, exc.what());
		}
	}
}

void ModalDialog::setupInputEncodingSelect(HWND hwnd, int id)
{
	::SendDlgItemMessage(hwnd, id, CB_ADDSTRING, 0, (LPARAM)TEXT("utf8"));
	::SendDlgItemMessage(hwnd, id, CB_ADDSTRING, 0, (LPARAM)TEXT("base16"));
	::SendDlgItemMessage(hwnd, id, CB_ADDSTRING, 0, (LPARAM)TEXT("base32"));
	::SendDlgItemMessage(hwnd, id, CB_ADDSTRING, 0, (LPARAM)TEXT("base64"));
	::SendDlgItemMessage(hwnd, id, CB_SETCURSEL, 0, 0);
}

INT_PTR CALLBACK ModalDialog::dlgProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_INITDIALOG:
	{
		if (!lParam) {
			return FALSE;
		}
		ModalDialog *pModalDlg = reinterpret_cast<ModalDialog *>(lParam);
		::SetWindowLongPtr(hwnd, GWLP_USERDATA, static_cast<LONG_PTR>(lParam));

		if (pModalDlg->_hSelf == NULL) {
			pModalDlg->_hSelf = hwnd;
			::GetWindowRect(hwnd, &(pModalDlg->_rc));
			pModalDlg->run_dlgProc(message, wParam, lParam);
		}
		return TRUE;
	}
	case WM_DESTROY:
	{
		ModalDialog *pModalDlg = reinterpret_cast<ModalDialog *>(::GetWindowLongPtr(hwnd, GWLP_USERDATA));
		if (pModalDlg) {
			pModalDlg->_hSelf = NULL;
		}
		return TRUE;
	}
	default:
	{
		ModalDialog *pModalDlg = reinterpret_cast<ModalDialog *>(::GetWindowLongPtr(hwnd, GWLP_USERDATA));
		if (!pModalDlg) {
			return FALSE;
		}
		return pModalDlg->run_dlgProc(message, wParam, lParam);
	}
	}
}
