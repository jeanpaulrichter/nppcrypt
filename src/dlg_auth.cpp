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
	this->filename = filename;
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
        case WM_INITDIALOG :
		{
			if(filename) {
				SetWindowText (_hSelf, filename);
			} else {
				SetWindowText (_hSelf, TEXT("authentication"));
			}

			::SendDlgItemMessage(_hSelf, IDC_AUTH_KEY, EM_SETPASSWORDCHAR, '*', 0);
			::SendDlgItemMessage(_hSelf, IDC_AUTH_KEY, EM_LIMITTEXT, 32, 0);
			PostMessage( _hSelf, WM_USER+1, 0, 0);
			return true;
		}
		case WM_USER+1:
			::SetFocus(::GetDlgItem(_hSelf, IDC_AUTH_KEY));
			break;
		case WM_COMMAND : 
	    {
			if(LOWORD(wParam) == IDC_AUTH_KEY) {
				bool fuck = true;
			}
		    switch (LOWORD(wParam))
		    {
			case IDC_OK: {
					TCHAR temp_key[33];
					std::string temp_key_s;
					::GetDlgItemText(_hSelf, IDC_AUTH_KEY, temp_key, 33);		

					try {
						#ifdef UNICODE
						
						int tpw_buf_size = WideCharToMultiByte(CP_UTF8, 0, temp_key, -1, NULL,0,NULL,false);
						if(tpw_buf_size < 1)
							throw CExc(CExc::dlg_auth,__LINE__, CExc::utf8conversion);
						temp_key_s.resize((size_t)tpw_buf_size);
						if(!WideCharToMultiByte(CP_UTF8, 0, temp_key, -1, &temp_key_s[0], tpw_buf_size, NULL, false))
							throw CExc(CExc::dlg_auth,__LINE__, CExc::utf8conversion);
						#else
						temp_key_s(temp_key);
						#endif

						Crypt::shake128((unsigned char*)temp_key_s.c_str(), temp_key_s.size(), key, 16);

					} catch(CExc& exc) {
						::MessageBox(_hSelf, exc.getErrorMsg(), TEXT("Error"), MB_OK);
						break;
					}

					EndDialog(_hSelf, IDC_OK);
					return TRUE; }
				case IDC_CANCEL :
				    EndDialog(_hSelf, IDC_CANCEL);
					return TRUE;

				case IDC_CRYPT_AUTH_KEY_SHOW: {
					char c = ::SendDlgItemMessage(_hSelf, IDC_AUTH_SHOW, BM_GETCHECK, 0, 0) ? 0 : '*';
					::SendDlgItemMessage(_hSelf, IDC_AUTH_KEY, EM_SETPASSWORDCHAR, c, 0);
					InvalidateRect(::GetDlgItem(_hSelf, IDC_AUTH_KEY), 0, TRUE);
					break; }
			    default :
				    break;
		    }
		    break;
	    }
	}
	return FALSE;
}

const unsigned char* DlgAuth::getKey()
{
	return key;
}

void DlgAuth::clearKey()
{
	memset(key,0,16);
}
