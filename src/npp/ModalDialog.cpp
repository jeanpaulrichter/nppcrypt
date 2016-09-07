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

#include <stdio.h>
#include "ModalDialog.h"

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
		DWORD err = ::GetLastError();
		char errMsg[256];
		sprintf(errMsg, "CreateDialogParam() return NULL.\rGetLastError() == %u", err);
		::MessageBoxA(NULL, errMsg, "In StaticDialog::create()", MB_OK);
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
