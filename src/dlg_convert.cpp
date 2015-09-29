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

#include "dlg_convert.h"
#include "exception.h"
#include "resource.h"
#include <commctrl.h>

DlgConvert::DlgConvert(crypt::Options::Convert& opt) : Window(), options(opt)
{
};

void DlgConvert::init(HINSTANCE hInst, HWND parent)
{
	Window::init(hInst, parent);
};

bool DlgConvert::doDialog(bool no_ascii)
{
	this->no_ascii = no_ascii;
	if (DialogBoxParam(_hInst, MAKEINTRESOURCE(IDD_CONVERT), _hParent, (DLGPROC)dlgProc, (LPARAM)this) == IDC_OK)
		return true;
	return false;
}

BOOL CALLBACK DlgConvert::dlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
	switch (Message)
	{
	case WM_INITDIALOG:
	{
		DlgConvert *pDlgConvert = (DlgConvert *)(lParam);
		pDlgConvert->_hSelf = hWnd;
		::SetWindowLongPtr(hWnd, GWL_USERDATA, (long)lParam);
		pDlgConvert->run_dlgProc(Message, wParam, lParam);
		return TRUE;
	}

	default:
	{
		DlgConvert *pDlgConvert = reinterpret_cast<DlgConvert *>(::GetWindowLong(hWnd, GWL_USERDATA));
		if (!pDlgConvert)
			return FALSE;
		return pDlgConvert->run_dlgProc(Message, wParam, lParam);
	}

	}
	return FALSE;
}

BOOL CALLBACK DlgConvert::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_INITDIALOG:
	{
		using namespace crypt;
		if (options.to == Encoding::ascii && no_ascii)
		{
			if (options.from != Encoding::base16)
				options.to = Encoding::base16;
			else
				options.to = Encoding::base64;
		}

		::SendDlgItemMessage(_hSelf, IDC_CONVERT_FROM_ASCII, BM_SETCHECK, (options.from == Encoding::ascii), 0);
		::SendDlgItemMessage(_hSelf, IDC_CONVERT_FROM_BASE16, BM_SETCHECK, (options.from == Encoding::base16), 0);
		::SendDlgItemMessage(_hSelf, IDC_CONVERT_FROM_BASE32, BM_SETCHECK, (options.from == Encoding::base32), 0);
		::SendDlgItemMessage(_hSelf, IDC_CONVERT_FROM_BASE64, BM_SETCHECK, (options.from == Encoding::base64), 0);
		::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_ASCII, BM_SETCHECK, (options.to == Encoding::ascii), 0);
		::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE16, BM_SETCHECK, (options.to == Encoding::base16), 0);
		::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE32, BM_SETCHECK, (options.to == Encoding::base32), 0);
		::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE64, BM_SETCHECK, (options.to == Encoding::base64), 0);
		OnFromChanged(options.from);

		::SendDlgItemMessage(_hSelf, IDC_CONVERT_UPPERCASE, BM_SETCHECK, options.uppercase, 0);
		::SendDlgItemMessage(_hSelf, IDC_CONVERT_LINEBREAKS, BM_SETCHECK, options.linebreaks, 0);
		::SendDlgItemMessage(_hSelf, IDC_CONVERT_LINELEN_SPIN, UDM_SETRANGE32, 1, NPPC_MAX_LINE_LENGTH);
		::SendDlgItemMessage(_hSelf, IDC_CONVERT_LINELEN_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(_hSelf, IDC_CONVERT_LINELEN), 0);
		::SendDlgItemMessage(_hSelf, IDC_CONVERT_LINELEN_SPIN, UDM_SETPOS32, 0, options.linelength);
		::SendDlgItemMessage(_hSelf, IDC_CONVERT_LB_WINDOWS, BM_SETCHECK, options.windows, 0);
		::SendDlgItemMessage(_hSelf, IDC_CONVERT_LB_UNIX, BM_SETCHECK, !options.windows, 0);

		enableOptions((options.to != Encoding::ascii));

		return TRUE;
	} break;

	case WM_COMMAND:
	{
		switch (HIWORD(wParam))
		{
			// ----------------------------------------------------- BN_CLICKED ----------------------------------------------------------
		case BN_CLICKED:
		{
			switch (LOWORD(wParam))
			{
			case IDC_OK:
			{
				if (!!::SendDlgItemMessage(_hSelf, IDC_CONVERT_FROM_ASCII, BM_GETCHECK, 0, 0))
					options.from = crypt::Encoding::ascii;
				else if (!!::SendDlgItemMessage(_hSelf, IDC_CONVERT_FROM_BASE16, BM_GETCHECK, 0, 0))
					options.from = crypt::Encoding::base16;
				else if (!!::SendDlgItemMessage(_hSelf, IDC_CONVERT_FROM_BASE32, BM_GETCHECK, 0, 0))
					options.from = crypt::Encoding::base32;
				else if (!!::SendDlgItemMessage(_hSelf, IDC_CONVERT_FROM_BASE64, BM_GETCHECK, 0, 0))
					options.from = crypt::Encoding::base64;
				if (!!::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_ASCII, BM_GETCHECK, 0, 0))
					options.to = crypt::Encoding::ascii;
				else if (!!::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE16, BM_GETCHECK, 0, 0))
					options.to = crypt::Encoding::base16;
				else if (!!::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE32, BM_GETCHECK, 0, 0))
					options.to = crypt::Encoding::base32;
				else if (!!::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE64, BM_GETCHECK, 0, 0))
					options.to = crypt::Encoding::base64;

				if (options.to != crypt::Encoding::ascii)
				{
					options.uppercase = !!::SendDlgItemMessage(_hSelf, IDC_CONVERT_UPPERCASE, BM_GETCHECK, 0, 0);
					options.linebreaks = !!::SendDlgItemMessage(_hSelf, IDC_CONVERT_LINEBREAKS, BM_GETCHECK, 0, 0);
					options.windows = !!::SendDlgItemMessage(_hSelf, IDC_CONVERT_LB_WINDOWS, BM_GETCHECK, 0, 0);
					options.linelength = ::SendDlgItemMessage(_hSelf, IDC_CONVERT_LINELEN_SPIN, UDM_GETPOS32, 0, 0);
				}

				EndDialog(_hSelf, IDC_OK);
				return TRUE;
			} break;

			case IDC_CANCEL: case IDCANCEL:
			{
				EndDialog(_hSelf, IDC_CANCEL);
				return TRUE;
			} break;

			case IDC_CONVERT_FROM_ASCII:
				OnFromChanged(crypt::Encoding::ascii); break;
			case IDC_CONVERT_FROM_BASE16:
				OnFromChanged(crypt::Encoding::base16); break;
			case IDC_CONVERT_FROM_BASE32:
				OnFromChanged(crypt::Encoding::base32); break;
			case IDC_CONVERT_FROM_BASE64:
				OnFromChanged(crypt::Encoding::base64); break;

			case IDC_CONVERT_TO_ASCII:
				enableOptions(false);
				break;

			case IDC_CONVERT_TO_BASE16: case IDC_CONVERT_TO_BASE32: case IDC_CONVERT_TO_BASE64:
				enableOptions(true);
				break;

			case IDC_CONVERT_LINEBREAKS:
			{
				bool linebreaks = !!::SendDlgItemMessage(_hSelf, IDC_CONVERT_LINEBREAKS, BM_GETCHECK, 0, 0);
				::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LINELEN), linebreaks);
				::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LINELEN_SPIN), linebreaks);
				::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LB_WINDOWS), linebreaks);
				::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LB_UNIX), linebreaks);
			} break;

			default:
				break;
			}
		} break;

		case EN_CHANGE:
		{
			if (LOWORD(wParam) == IDC_CONVERT_LINELEN)
			{
				int temp;
				int len = GetWindowTextLength(::GetDlgItem(_hSelf, IDC_CONVERT_LINELEN));
				if (len > 0)
				{
					std::vector<TCHAR> tstr(len + 1);
					::GetDlgItemText(_hSelf, IDC_CONVERT_LINELEN, tstr.data(), tstr.size());
					#ifdef UNICODE
					temp = std::stoi(tstr.data());
					#else
					temp = std::atoi(str.data());
					#endif
					if (temp > NPPC_MAX_LINE_LENGTH)
						::SendDlgItemMessage(_hSelf, IDC_CONVERT_LINELEN_SPIN, UDM_SETPOS32, 0, NPPC_MAX_LINE_LENGTH);
				}
				else {
					::SendDlgItemMessage(_hSelf, IDC_CONVERT_LINELEN_SPIN, UDM_SETPOS32, 0, 1);
				}
			}
		} break;

		}
	} break;
	}
	return FALSE;
}

void DlgConvert::OnFromChanged(crypt::Encoding enc)
{
	switch (enc)
	{
	case crypt::Encoding::ascii:
		if (!!::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_ASCII, BM_GETCHECK, 0, 0)) {
			::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE16, BM_SETCHECK, true, 0);
			::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_ASCII, BM_SETCHECK, false, 0);
			enableOptions(true);
		}
		break;
	case crypt::Encoding::base16:
		if (!!::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE16, BM_GETCHECK, 0, 0)) {
			::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE32, BM_SETCHECK, true, 0);
			::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE16, BM_SETCHECK, false, 0);
		}
		break;
	case crypt::Encoding::base32:
		if (!!::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE32, BM_GETCHECK, 0, 0)) {
			::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE64, BM_SETCHECK, true, 0);
			::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE32, BM_SETCHECK, false, 0);
			enableOptions(true);
		}
		break;
	case crypt::Encoding::base64:
		if (!!::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE64, BM_GETCHECK, 0, 0)) {
			::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE32, BM_SETCHECK, true, 0);
			::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE64, BM_SETCHECK, false, 0);			
		}
		break;
	}
	::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_TO_ASCII), (enc != crypt::Encoding::ascii && !no_ascii));
	::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_TO_BASE16), (enc != crypt::Encoding::base16));
	::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_TO_BASE32), (enc != crypt::Encoding::base32));
	::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_TO_BASE64), (enc != crypt::Encoding::base64));
}

void DlgConvert::enableOptions(bool v)
{
	if (v)
	{
		bool base64 = !!::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE64, BM_GETCHECK, 0, 0);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_UPPERCASE), !base64);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LINEBREAKS), true);
		bool linebreaks = !!::SendDlgItemMessage(_hSelf, IDC_CONVERT_LINEBREAKS, BM_GETCHECK, 0, 0);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LINELEN), linebreaks);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LINELEN_SPIN), linebreaks);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LB_WINDOWS), linebreaks);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LB_UNIX), linebreaks);
	}
	else {
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_UPPERCASE), false);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LINEBREAKS), false);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LINELEN), false);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LINELEN_SPIN), false);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LB_WINDOWS), false);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LB_UNIX), false);
	}
}