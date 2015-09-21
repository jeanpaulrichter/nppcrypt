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
#include "exception.h"
#include "resource.h"
#include "crypt.h"
#include <string>

DlgAuth::DlgAuth(): Window()
{
};

void DlgAuth::init(HINSTANCE hInst, HWND parent)
{
	Window::init(hInst, parent);
};

bool DlgAuth::doDialog(const TCHAR* filename)
{
	if (filename == NULL) {
		caption = TEXT("authentication");
	}
	else {
		caption = TEXT("authentication (") + string(filename) + TEXT(")");
	}
	if(DialogBoxParam(_hInst, MAKEINTRESOURCE(IDD_AUTH), _hParent,  (DLGPROC)dlgProc, (LPARAM)this)==IDC_OK)
		return true;
	return false;
}

BOOL CALLBACK DlgAuth::dlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam) 
{
	switch (Message) 
	{
		case WM_INITDIALOG :
		{
			DlgAuth *pDlgAuth = (DlgAuth *)(lParam);
			pDlgAuth->_hSelf = hWnd;
			::SetWindowLongPtr(hWnd, GWL_USERDATA, (long)lParam);
			pDlgAuth->run_dlgProc(Message, wParam, lParam);
			return TRUE;
		}

		default :
		{
			DlgAuth *pDlgAuth = reinterpret_cast<DlgAuth *>(::GetWindowLong(hWnd, GWL_USERDATA));
			if (!pDlgAuth)
				return FALSE;
			return pDlgAuth->run_dlgProc(Message, wParam, lParam);
		}

	}
	return FALSE;
}

BOOL CALLBACK DlgAuth::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message) 
	{
	case WM_INITDIALOG:
	{
		SetWindowText(_hSelf, caption.c_str());
		::SendDlgItemMessage(_hSelf, IDC_AUTH_KEY, EM_SETPASSWORDCHAR, '*', 0);
		::SendDlgItemMessage(_hSelf, IDC_AUTH_KEY, EM_LIMITTEXT, NPPC_HMAC_INPUT_MAX, 0);
		PostMessage(_hSelf, WM_NEXTDLGCTL, (WPARAM)::GetDlgItem(_hSelf, IDC_AUTH_KEY), TRUE);
		return TRUE;
	} break;

	case WM_COMMAND : 
	{
		switch (LOWORD(wParam))
		{
		case IDC_OK:
		{
			TCHAR temp_key[NPPC_HMAC_INPUT_MAX+1];
			::GetDlgItemText(_hSelf, IDC_AUTH_KEY, temp_key, NPPC_HMAC_INPUT_MAX+1);

			try {
				#ifdef UNICODE
				Encode::wchar_to_utf8(temp_key, -1, keystring);
				#else
				keystring.assign(temp_key);
				#endif

			} catch(CExc& exc) {
				::MessageBox(_hSelf, exc.getErrorMsg(), TEXT("Error"), MB_OK);
				break;
			}

			EndDialog(_hSelf, IDC_OK);
			return TRUE;
		} break;

		case IDC_CANCEL:
		{
			EndDialog(_hSelf, IDC_CANCEL);
			return TRUE;
		} break;

		case IDC_CRYPT_AUTH_KEY_SHOW:
		{
			char c = ::SendDlgItemMessage(_hSelf, IDC_AUTH_SHOW, BM_GETCHECK, 0, 0) ? 0 : '*';
			::SendDlgItemMessage(_hSelf, IDC_AUTH_KEY, EM_SETPASSWORDCHAR, c, 0);
			InvalidateRect(::GetDlgItem(_hSelf, IDC_AUTH_KEY), 0, TRUE);
		} break;

		default:
			break;
		}
	} break;
	}
	return FALSE;
}

void DlgAuth::getKeyString(std::string& s)
{
	s.assign(keystring);
	keystring.clear();
}