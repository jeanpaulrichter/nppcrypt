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

#include "npp/PluginInterface.h"
#include "npp/Definitions.h"
#include "mdef.h"
#include "dlg_convert.h"
#include "exception.h"
#include "resource.h"
#include <commctrl.h>
#include "help.h"

DlgConvert::DlgConvert(crypt::Options::Convert& opt) : DockingDlgInterface(IDD_CONVERT), options(opt)
{
};

void DlgConvert::display(bool toShow) const
{
	DockingDlgInterface::display(toShow);
};

INT_PTR CALLBACK DlgConvert::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_INITDIALOG:
	{
		using namespace crypt;

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
			case IDC_OK: case IDC_COPY:
			{
				try {
					const byte*				pdata;
					size_t					data_length;
					std::basic_string<byte>	buffer;

					updateOptions(); 
					if (!helper::Scintilla::getSelection(&pdata, &data_length)) {
						return TRUE;
					}
					crypt::convert(pdata, data_length, buffer, options);
					if (LOWORD(wParam) == IDC_OK) {
						helper::Scintilla::replaceSelection(buffer);
					} else {
						helper::Windows::copyToClipboard(buffer);
					}
				} catch (CExc& exc) {
					::MessageBox(_hSelf, exc.getMsg(), TEXT("Error"), MB_OK);
				} catch (...) {
					::MessageBox(_hSelf, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
				}
				break;
			}
			case IDC_CANCEL: case IDCANCEL:
			{
				EndDialog(_hSelf, IDC_CANCEL);
				return TRUE;
			}
			case IDC_CONVERT_FROM_ASCII:
			{
				OnFromChanged(crypt::Encoding::ascii);
				break;
			}
			case IDC_CONVERT_FROM_BASE16:
			{
				OnFromChanged(crypt::Encoding::base16);
				break;
			}
			case IDC_CONVERT_FROM_BASE32:
			{
				OnFromChanged(crypt::Encoding::base32);
				break;
			}
			case IDC_CONVERT_FROM_BASE64:
			{
				OnFromChanged(crypt::Encoding::base64);
				break;
			}
			case IDC_CONVERT_TO_ASCII:
			{
				enableOptions(false);
				break;
			}
			case IDC_CONVERT_TO_BASE16: case IDC_CONVERT_TO_BASE32: case IDC_CONVERT_TO_BASE64:
			{
				enableOptions(true);
				break;
			}
			case IDC_CONVERT_LINEBREAKS:
			{
				bool linebreaks = !!::SendDlgItemMessage(_hSelf, IDC_CONVERT_LINEBREAKS, BM_GETCHECK, 0, 0);
				::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LINELEN), linebreaks);
				::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LINELEN_SPIN), linebreaks);
				::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LB_WINDOWS), linebreaks);
				::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LB_UNIX), linebreaks);
				break;
			}
			}
			break;
		}
		case EN_CHANGE:
		{
			/* prevent out of bounds user input to line-length spin-control */
			if (LOWORD(wParam) == IDC_CONVERT_LINELEN) {
				int temp_length;
				int len = GetWindowTextLength(::GetDlgItem(_hSelf, IDC_CONVERT_LINELEN));
				if (len > 0) {
					std::vector<TCHAR> tstr(len + 1);
					::GetDlgItemText(_hSelf, IDC_CONVERT_LINELEN, tstr.data(), (int)tstr.size());
					#ifdef UNICODE
					temp_length = std::stoi(tstr.data());
					#else
					temp = std::atoi(str.data());
					#endif
					if (temp_length > NPPC_MAX_LINE_LENGTH) {
						::SendDlgItemMessage(_hSelf, IDC_CONVERT_LINELEN_SPIN, UDM_SETPOS32, 0, NPPC_MAX_LINE_LENGTH);
					} else if (temp_length < 1) {
						::SendDlgItemMessage(_hSelf, IDC_CONVERT_LINELEN_SPIN, UDM_SETPOS32, 0, 1);
					}
				} else {
					::SendDlgItemMessage(_hSelf, IDC_CONVERT_LINELEN_SPIN, UDM_SETPOS32, 0, 1);
				}
			}
			break;
		}
		}
		break;
	}
	}
	return FALSE;
}

void DlgConvert::updateOptions()
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

	if (options.to != crypt::Encoding::ascii) {
		options.uppercase = !!::SendDlgItemMessage(_hSelf, IDC_CONVERT_UPPERCASE, BM_GETCHECK, 0, 0);
		options.linebreaks = !!::SendDlgItemMessage(_hSelf, IDC_CONVERT_LINEBREAKS, BM_GETCHECK, 0, 0);
		options.windows = !!::SendDlgItemMessage(_hSelf, IDC_CONVERT_LB_WINDOWS, BM_GETCHECK, 0, 0);
		options.linelength = (int)::SendDlgItemMessage(_hSelf, IDC_CONVERT_LINELEN_SPIN, UDM_GETPOS32, 0, 0);
	}
}

void DlgConvert::enableOptions(bool v) const
{
	if (v) {
		bool base64 = !!::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE64, BM_GETCHECK, 0, 0);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_UPPERCASE), !base64);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LINEBREAKS), true);
		bool linebreaks = !!::SendDlgItemMessage(_hSelf, IDC_CONVERT_LINEBREAKS, BM_GETCHECK, 0, 0);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LINELEN), linebreaks);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LINELEN_SPIN), linebreaks);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LB_WINDOWS), linebreaks);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LB_UNIX), linebreaks);
	} else {
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_UPPERCASE), false);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LINEBREAKS), false);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LINELEN), false);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LINELEN_SPIN), false);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LB_WINDOWS), false);
		::EnableWindow(::GetDlgItem(_hSelf, IDC_CONVERT_LB_UNIX), false);
	}
}

void DlgConvert::OnFromChanged(crypt::Encoding enc) const
{
	switch (enc)
	{
	case crypt::Encoding::ascii:
	{
		if (!!::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_ASCII, BM_GETCHECK, 0, 0)) {
			::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE16, BM_SETCHECK, true, 0);
			::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_ASCII, BM_SETCHECK, false, 0);
			enableOptions(true);
		}
		break;
	}
	case crypt::Encoding::base16:
	{
		if (!!::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE16, BM_GETCHECK, 0, 0)) {
			::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE32, BM_SETCHECK, true, 0);
			::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE16, BM_SETCHECK, false, 0);
		}
		break;
	}
	case crypt::Encoding::base32:
	{
		if (!!::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE32, BM_GETCHECK, 0, 0)) {
			::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE64, BM_SETCHECK, true, 0);
			::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE32, BM_SETCHECK, false, 0);
			enableOptions(true);
		}
		break;
	}
	case crypt::Encoding::base64:
	{
		if (!!::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE64, BM_GETCHECK, 0, 0)) {
			::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE32, BM_SETCHECK, true, 0);
			::SendDlgItemMessage(_hSelf, IDC_CONVERT_TO_BASE64, BM_SETCHECK, false, 0);
		}
		break;
	}
	}
}


