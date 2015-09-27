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

#include "dlg_about.h"
#include "mdef.h"
#include "resource.h"


void DlgAbout::init(HINSTANCE hInst, HWND parent)
{
	Window::init(hInst, parent);
};

bool DlgAbout::doDialog()
{
	if(DialogBoxParam(_hInst, MAKEINTRESOURCE(IDD_ABOUT), _hParent,  (DLGPROC)dlgProc, (LPARAM)this)==IDC_OK)
		return true;
	return false;
}

BOOL CALLBACK DlgAbout::dlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam) 
{
	switch (Message) 
	{
		case WM_INITDIALOG :
		{
			DlgAbout *pDlgAbout = (DlgAbout *)(lParam);
			pDlgAbout->_hSelf = hWnd;
			::SetWindowLongPtr(hWnd, GWL_USERDATA, (long)lParam);
			pDlgAbout->run_dlgProc(Message, wParam, lParam);
			return TRUE;
		}

		default :
		{
			DlgAbout *pDlgAbout = reinterpret_cast<DlgAbout *>(::GetWindowLong(hWnd, GWL_USERDATA));
			if (!pDlgAbout)
				return FALSE;
			return pDlgAbout->run_dlgProc(Message, wParam, lParam);
		}

	}
	return FALSE;
}

BOOL CALLBACK DlgAbout::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message) 
	{
        case WM_INITDIALOG :
		{
			SetDlgItemText(_hSelf, IDC_ABOUT_TEXT, TEXT(NPPC_ABOUT_TEXT));
			SetDlgItemText(_hSelf, IDC_ABOUT_CERBERUS_URL, TEXT(NPPC_ABOUT_LINK));

            cerberus.init(_hInst, _hSelf);
            cerberus.create(::GetDlgItem(_hSelf, IDC_ABOUT_CERBERUS_URL), TEXT(NPPC_ABOUT_URL));

			return TRUE;
		}
		case WM_COMMAND : 
	    {
		    switch (LOWORD(wParam))
		    {
				case IDC_OK: 
					EndDialog(_hSelf, IDC_OK);
				    return TRUE;
				case IDC_CANCEL : case IDCANCEL:
				    EndDialog(_hSelf, IDC_CANCEL);
					return TRUE;
			    default :
				    break;
		    }
		    break;
	    }
	}
	return FALSE;
}