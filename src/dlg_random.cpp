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

DlgRandom::DlgRandom() : Window()
{};

DlgRandom::~DlgRandom()
{
};

void DlgRandom::init(HINSTANCE hInst, HWND parent, Crypt::RandOptions* opt)
{
	Window::init(hInst, parent);
	options = opt;
};

bool DlgRandom::doDialog()
{
	if(!options)
		return false;
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
			::SendDlgItemMessage(_hSelf, IDC_RANDOM_SPIN, UDM_SETRANGE, true, (LPARAM)MAKELONG(Crypt::Constants::rand_char_max, 1));
			::SendDlgItemMessage(_hSelf, IDC_RANDOM_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(_hSelf,IDC_RANDOM_EDIT), 0);		
			if(options->length == 0 || options->length > Crypt::Constants::rand_char_max)
				options->length = 16;
			::SendDlgItemMessage(_hSelf, IDC_RANDOM_SPIN, UDM_SETPOS32, 0, options->length);

			if(preferences.no_ascii) {
				if(options->mode == Crypt::RandomMode::ascii) 
					options->mode = Crypt::RandomMode::hex;
				::EnableWindow(::GetDlgItem(_hSelf,IDC_RANDOM_R3),false);
			}

			switch(options->mode) {
			case Crypt::RandomMode::charnum: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_R1, BM_SETCHECK, BST_CHECKED, 0); break;
			case Crypt::RandomMode::specials: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_R2, BM_SETCHECK, BST_CHECKED, 0); break;
			case Crypt::RandomMode::ascii: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_R3, BM_SETCHECK, BST_CHECKED, 0); break;
			case Crypt::RandomMode::hex: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_R4, BM_SETCHECK, BST_CHECKED, 0); break;
			case Crypt::RandomMode::base64: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_R5, BM_SETCHECK, BST_CHECKED, 0); break;
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
						options->mode = Crypt::RandomMode::charnum;
					else if(::SendDlgItemMessage(_hSelf, IDC_RANDOM_R2, BM_GETCHECK, 0, 0)==BST_CHECKED)
						options->mode = Crypt::RandomMode::specials;
					else if(::SendDlgItemMessage(_hSelf, IDC_RANDOM_R3, BM_GETCHECK, 0, 0)==BST_CHECKED)
						options->mode = Crypt::RandomMode::ascii;
					else if(::SendDlgItemMessage(_hSelf, IDC_RANDOM_R4, BM_GETCHECK, 0, 0)==BST_CHECKED)
						options->mode = Crypt::RandomMode::hex;
					else
						options->mode = Crypt::RandomMode::base64;

					options->length = ::SendDlgItemMessage(_hSelf, IDC_RANDOM_SPIN, UDM_GETPOS32, 0, 0);

					EndDialog(_hSelf, IDC_OK);
				    return TRUE;
					}
				case IDC_CANCEL :
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