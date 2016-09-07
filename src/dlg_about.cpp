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

INT_PTR CALLBACK DlgAbout::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message) 
	{
        case WM_INITDIALOG :
		{
			SetDlgItemText(_hSelf, IDC_ABOUT_TEXT, TEXT(NPPC_ABOUT_TEXT));
			SetDlgItemText(_hSelf, IDC_ABOUT_CERBERUS_URL, TEXT(NPPC_ABOUT_LINK));

            cerberus.init(_hInst, _hSelf);
            cerberus.create(::GetDlgItem(_hSelf, IDC_ABOUT_CERBERUS_URL), TEXT(NPPC_ABOUT_URL));

			goToCenter();

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