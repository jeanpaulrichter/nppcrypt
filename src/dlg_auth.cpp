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

#include "dlg_auth.h"
#include "mdef.h"
#include "resource.h"
#include "exception.h"

bool DlgAuth::doDialog(const TCHAR* filename)
{
	if (filename == NULL) {
		caption = TEXT("authentication");
	} else {
		caption = TEXT("authentication (") + string(filename) + TEXT(")");
	}
	return ModalDialog::doDialog();
}

INT_PTR CALLBACK DlgAuth::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_INITDIALOG:
	{
		SetWindowText(_hSelf, caption.c_str());
		::SendDlgItemMessage(_hSelf, IDC_AUTH_KEY, EM_SETPASSWORDCHAR, '*', 0);
		::SendDlgItemMessage(_hSelf, IDC_AUTH_KEY, EM_LIMITTEXT, NPPC_HMAC_INPUT_MAX, 0);
		PostMessage(_hSelf, WM_NEXTDLGCTL, (WPARAM)::GetDlgItem(_hSelf, IDC_AUTH_KEY), TRUE);
		goToCenter();
		return TRUE;
	}
	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case IDC_OK:
		{
			TCHAR temp_key[NPPC_HMAC_INPUT_MAX + 1];
			::GetDlgItemText(_hSelf, IDC_AUTH_KEY, temp_key, NPPC_HMAC_INPUT_MAX + 1);

			try {
				#ifdef UNICODE
				unicode::wchar_to_utf8(temp_key, -1, keystring);
				#else
				keystring.assign(temp_key);
				#endif
			} catch (CExc& exc) {
				::MessageBox(_hSelf, exc.getMsg(), TEXT("Error"), MB_OK);
				break;
			}

			EndDialog(_hSelf, IDC_OK);
			return TRUE;
		}
		case IDC_CANCEL: case IDCANCEL:
		{
			EndDialog(_hSelf, IDC_CANCEL);
			return TRUE;
		}
		case IDC_AUTH_SHOW:
		{
			char c = ::SendDlgItemMessage(_hSelf, IDC_AUTH_SHOW, BM_GETCHECK, 0, 0) ? 0 : '*';
			::SendDlgItemMessage(_hSelf, IDC_AUTH_KEY, EM_SETPASSWORDCHAR, c, 0);
			InvalidateRect(::GetDlgItem(_hSelf, IDC_AUTH_KEY), 0, TRUE);
			break;
		}
		}
		break;
	}
	}
	return FALSE;
}

void DlgAuth::getKeyString(std::string& out)
{
	out.assign(keystring);
	keystring.clear();
}