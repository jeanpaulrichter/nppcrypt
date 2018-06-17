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

#include "dlg_initdata.h"
#include "exception.h"
#include "resource.h"
#include "help.h"

DlgInitdata::DlgInitdata() : ModalDialog()
{
};

void DlgInitdata::destroy()
{
	if (brush_red) {
		DeleteObject(brush_red);
	}
	ModalDialog::destroy();
};

bool DlgInitdata::doDialog(crypt::InitData* data, size_t saltlen, size_t taglen)
{
	pdata = data;
	saltlength = saltlen;
	taglength = taglen;
	invalid_salt = (saltlength > 0);
	invalid_tag = (taglength > 0);
	if (!pdata) {
		return false;
	}
	if (!brush_red) {
		brush_red = CreateSolidBrush(RGB(255, 0, 0));
	}
	return ModalDialog::doDialog();
}

INT_PTR CALLBACK DlgInitdata::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_INITDIALOG:
	{
		setupInputEncodingSelect(_hSelf, IDC_INITDATA_SALT_ENC);
		setupInputEncodingSelect(_hSelf, IDC_INITDATA_TAG_ENC);

		::SendDlgItemMessage(_hSelf, IDC_INITDATA_SALT, EM_LIMITTEXT, 1024, 0);
		::SendDlgItemMessage(_hSelf, IDC_INITDATA_TAG, EM_LIMITTEXT, 1024, 0);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_INITDATA_SALT), (saltlength > 0));
		::EnableWindow(::GetDlgItem(_hSelf, IDC_INITDATA_SALT_ENC), (saltlength > 0));
		::EnableWindow(::GetDlgItem(_hSelf, IDC_INITDATA_TAG), (taglength > 0));
		::EnableWindow(::GetDlgItem(_hSelf, IDC_INITDATA_TAG_ENC), (taglength > 0));

		goToCenter();
		return TRUE;
	}
	case WM_COMMAND:
	{
		switch (HIWORD(wParam))
		{
		case BN_CLICKED:
		{
			switch (LOWORD(wParam))
			{
			case IDC_OK:
			{
				if (saltlength > 0) {
					if (!checkSalt(true)) {
						return FALSE;
					}
				}
				if (taglength > 0) {
					if (!checkTag(true)) {
						return FALSE;
					}
				}
				EndDialog(_hSelf, IDC_OK);
				return TRUE;
			}
			case IDC_CANCEL: case IDCANCEL:
			{
				EndDialog(_hSelf, IDC_CANCEL);
				return TRUE;
			}
			}
			break;
		}
		case EN_CHANGE:
		{
			if (saltlength > 0 && LOWORD(wParam) == IDC_INITDATA_SALT) {
				checkSalt(false);
				InvalidateRect(::GetDlgItem(_hSelf, IDC_INITDATA_SALT), NULL, NULL);
			} else if (taglength > 0 && LOWORD(wParam) == IDC_INITDATA_TAG) {
				checkTag(false);
				InvalidateRect(::GetDlgItem(_hSelf, IDC_INITDATA_TAG), NULL, NULL);
			}
			break;
		}
		case CBN_SELCHANGE:
		{
			switch (LOWORD(wParam))
			{
			case IDC_INITDATA_SALT_ENC:
			{
				checkSalt(false);
				InvalidateRect(::GetDlgItem(_hSelf, IDC_INITDATA_SALT), NULL, NULL);
				::SetFocus(::GetDlgItem(_hSelf, IDC_INITDATA_SALT));
				break;
			}
			case IDC_INITDATA_TAG_ENC:
			{
				checkTag(false);
				InvalidateRect(::GetDlgItem(_hSelf, IDC_INITDATA_TAG), NULL, NULL);
				::SetFocus(::GetDlgItem(_hSelf, IDC_INITDATA_TAG));
				break;
			}
			}
			break;
		}
		}
		break;
	}
	case WM_CTLCOLOREDIT:
	{
		if (invalid_salt && (HWND)lParam == GetDlgItem(_hSelf, IDC_INITDATA_SALT)) {
			SetBkMode((HDC)wParam, TRANSPARENT);
			return (INT_PTR)brush_red;
		} else if (invalid_tag && (HWND)lParam == GetDlgItem(_hSelf, IDC_INITDATA_TAG)) {
			SetBkMode((HDC)wParam, TRANSPARENT);
			return (INT_PTR)brush_red;
		}
		break;
	}
	}
	return FALSE;
}

bool DlgInitdata::checkTag(bool updatedata)
{
	crypt::secure_string	temp;
	getText(IDC_INITDATA_TAG, temp);
	if (!temp.size()) {
		invalid_tag = true;
	} else {
		crypt::UserData			data;
		crypt::Encoding			enc;
		
		enc = (crypt::Encoding)::SendDlgItemMessage(_hSelf, IDC_INITDATA_TAG_ENC, CB_GETCURSEL, 0, 0);
		data.set(temp.c_str(), temp.size(), enc);
		invalid_tag = (data.size() != taglength);
		if (!invalid_salt && updatedata) {
			pdata->tag.set(data);
		}
	}
	return !invalid_tag;
}

bool DlgInitdata::checkSalt(bool updatedata)
{
	crypt::secure_string	temp;
	getText(IDC_INITDATA_SALT, temp);
	if (!temp.size()) {
		invalid_salt = true;
	} else {
		crypt::UserData			data;
		crypt::Encoding			enc;
		
		enc = (crypt::Encoding)::SendDlgItemMessage(_hSelf, IDC_INITDATA_SALT_ENC, CB_GETCURSEL, 0, 0);
		data.set(temp.c_str(), temp.size(), enc);
		invalid_salt = (data.size() != saltlength);
		if (!invalid_salt && updatedata) {
			pdata->salt.set(data);
		}
	}
	return !invalid_salt;
}