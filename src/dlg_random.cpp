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

#include "dlg_random.h"
#include "resource.h"
#include "commctrl.h"
#include "preferences.h"

DlgRandom::DlgRandom() : Window(), no_ascii(false)
{};

DlgRandom::~DlgRandom()
{};

void DlgRandom::init(HINSTANCE hInst, HWND parent, crypt::Options::Random* opt)
{
	Window::init(hInst, parent);
	options = opt;
};

bool DlgRandom::doDialog(bool no_ascii)
{
	if(!options)
		return false;
	this->no_ascii = no_ascii;
	if(DialogBoxParam(_hInst, MAKEINTRESOURCE(IDD_RANDOM), _hParent,  (DLGPROC)dlgProc, (LPARAM)this)==IDC_OK)
		return true;
	return false;
}

BOOL CALLBACK DlgRandom::dlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam) 
{
	switch (Message) 
	{
		case WM_INITDIALOG :
		{
			DlgRandom *pDlgRandom = (DlgRandom *)(lParam);
			pDlgRandom->_hSelf = hWnd;
			::SetWindowLongPtr(hWnd, GWL_USERDATA, (long)lParam);
			pDlgRandom->run_dlgProc(Message, wParam, lParam);
			return TRUE;
		}

		default :
		{
			DlgRandom *pDlgRandom = reinterpret_cast<DlgRandom *>(::GetWindowLong(hWnd, GWL_USERDATA));
			if (!pDlgRandom)
				return FALSE;
			return pDlgRandom->run_dlgProc(Message, wParam, lParam);
		}

	}
	return FALSE;
}

BOOL CALLBACK DlgRandom::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message) 
	{
        case WM_INITDIALOG :
		{
			::SendDlgItemMessage(_hSelf, IDC_RANDOM_SPIN, UDM_SETRANGE, true, (LPARAM)MAKELONG(crypt::Constants::rand_char_max, 1));
			::SendDlgItemMessage(_hSelf, IDC_RANDOM_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(_hSelf,IDC_RANDOM_EDIT), 0);		
			if(options->length == 0 || options->length > crypt::Constants::rand_char_max)
				options->length = 16;
			::SendDlgItemMessage(_hSelf, IDC_RANDOM_SPIN, UDM_SETPOS32, 0, options->length);

			if(no_ascii)
			{
				if(options->mode == crypt::Random::ascii) 
					options->mode = crypt::Random::base16;
				::EnableWindow(::GetDlgItem(_hSelf,IDC_RANDOM_R3),false);
			}

			switch(options->mode) {
			case crypt::Random::charnum: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_R1, BM_SETCHECK, BST_CHECKED, 0); break;
			case crypt::Random::specials: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_R2, BM_SETCHECK, BST_CHECKED, 0); break;
			case crypt::Random::ascii: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_R3, BM_SETCHECK, BST_CHECKED, 0); break;
			case crypt::Random::base16: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_R4, BM_SETCHECK, BST_CHECKED, 0); break;
			case crypt::Random::base32: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_R5, BM_SETCHECK, BST_CHECKED, 0); break;
			case crypt::Random::base64: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_R6, BM_SETCHECK, BST_CHECKED, 0); break;
			}

			return TRUE;
		}
		case WM_COMMAND : 
	    {
		    switch (LOWORD(wParam))
		    {
				case IDC_OK: 
					{
					if(::SendDlgItemMessage(_hSelf, IDC_RANDOM_R1, BM_GETCHECK, 0, 0)==BST_CHECKED)
						options->mode = crypt::Random::charnum;
					else if(::SendDlgItemMessage(_hSelf, IDC_RANDOM_R2, BM_GETCHECK, 0, 0)==BST_CHECKED)
						options->mode = crypt::Random::specials;
					else if(::SendDlgItemMessage(_hSelf, IDC_RANDOM_R3, BM_GETCHECK, 0, 0)==BST_CHECKED)
						options->mode = crypt::Random::ascii;
					else if(::SendDlgItemMessage(_hSelf, IDC_RANDOM_R4, BM_GETCHECK, 0, 0)==BST_CHECKED)
						options->mode = crypt::Random::base16;
					else if (::SendDlgItemMessage(_hSelf, IDC_RANDOM_R5, BM_GETCHECK, 0, 0) == BST_CHECKED)
						options->mode = crypt::Random::base32;
					else
						options->mode = crypt::Random::base64;

					options->length = ::SendDlgItemMessage(_hSelf, IDC_RANDOM_SPIN, UDM_GETPOS32, 0, 0);

					EndDialog(_hSelf, IDC_OK);
				    return TRUE;
					}
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