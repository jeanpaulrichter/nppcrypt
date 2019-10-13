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

#include "dlg_auth.h"
#include "mdef.h"
#include "resource.h"
#include "exception.h"

bool DlgAuth::doDialog(const TCHAR* filename)
{
    if (filename == NULL) {
        caption = TEXT("authentication");
    } else {
        if (lstrlen(filename) > 25) {
            caption = TEXT("authentication (") + std::wstring(filename, 25) + TEXT("...)");
        } else {
            caption = TEXT("authentication (") + std::wstring(filename) + TEXT(")");
        }
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
        ::SendDlgItemMessage(_hSelf, IDC_AUTH_KEY, EM_LIMITTEXT, NPPC_MAX_HMAC_KEYLENGTH, 0);
        setupInputEncodingSelect(_hSelf, IDC_AUTH_KEY_ENC);
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
            nppcrypt::secure_string temp;
            getText(IDC_AUTH_KEY, temp);
            if (temp.size()) {
                nppcrypt::Encoding enc = (nppcrypt::Encoding)::SendDlgItemMessage(_hSelf, IDC_AUTH_KEY_ENC, CB_GETCURSEL, 0, 0);
                input.set(temp.c_str(), temp.size(), enc);
            } else {
                input.clear();
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
            ::SetFocus(::GetDlgItem(_hSelf, IDC_AUTH_KEY));
            break;
        }
        case CBN_SELCHANGE:
        {
            ::SetFocus(::GetDlgItem(_hSelf, IDC_AUTH_KEY));
            break;
        }
        }
        break;
    }
    }
    return FALSE;
}

nppcrypt::UserData& DlgAuth::getInput()
{
    return input;
}