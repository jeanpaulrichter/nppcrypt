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

#include "dlg_about.h"
#include "mdef.h"
#include "resource.h"

INT_PTR CALLBACK DlgAbout::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message) 
    {
        case WM_INITDIALOG :
        {
            SetDlgItemText(_hSelf, IDC_ABOUT_VERSION, TEXT(NPPC_ABOUT_VERSION));

            github.init(_hInst, _hSelf);
            github.create(::GetDlgItem(_hSelf, IDC_ABOUT_GITHUB), NPPC_ABOUT_GITHUB);
            cryptopp.init(_hInst, _hSelf);
            cryptopp.create(::GetDlgItem(_hSelf, IDC_ABOUT_CRYPTOPP), NPPC_ABOUT_CRYPTOPP);
            tinyxml2.init(_hInst, _hSelf);
            tinyxml2.create(::GetDlgItem(_hSelf, IDC_ABOUT_TINYXML2), NPPC_ABOUT_TINYXML2);
            bcrypt.init(_hInst, _hSelf);
            bcrypt.create(::GetDlgItem(_hSelf, IDC_ABOUT_BCRYPT), NPPC_ABOUT_BCRYPT);
            scrypt.init(_hInst, _hSelf);
            scrypt.create(::GetDlgItem(_hSelf, IDC_ABOUT_SCRYPT), NPPC_ABOUT_SCRYPT);
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