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

#include "dlg_random.h"
#include "resource.h"
#include "commctrl.h"
#include "exception.h"
#include "help.h"
#include "crypt_help.h"
#include "messagebox.h"

DlgRandom::DlgRandom(RandomOptions& opt) : ModalDialog(), options(opt)
{
};

INT_PTR CALLBACK DlgRandom::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG :
    {
        ::SendDlgItemMessage(_hSelf, IDC_RANDOM_SPIN, UDM_SETRANGE, true, (LPARAM)MAKELONG(nppcrypt::Constants::rand_char_max, 1));
        ::SendDlgItemMessage(_hSelf, IDC_RANDOM_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(_hSelf,IDC_RANDOM_EDIT), 0);
        ::SendDlgItemMessage(_hSelf, IDC_RANDOM_SPIN, UDM_SETPOS32, 0, options.length);

        if (!help::buffer::isCurrent8Bit() && options.encoding == nppcrypt::Encoding::ascii) {
            options.encoding = nppcrypt::Encoding::base16;
            ::EnableWindow(::GetDlgItem(_hSelf, IDC_RANDOM_ENC_BINARY), false);
        }

        using namespace nppcrypt;

        switch (options.encoding) {
            case Encoding::ascii: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_ENC_BINARY, BM_SETCHECK, BST_CHECKED, 0); break;
            case Encoding::base16: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_ENC_BASE16, BM_SETCHECK, BST_CHECKED, 0); break;
            case Encoding::base32: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_ENC_BASE32, BM_SETCHECK, BST_CHECKED, 0); break;
            case Encoding::base64: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_ENC_BASE64, BM_SETCHECK, BST_CHECKED, 0); break;
        }

        switch (options.restriction) {
            case UserData::Restriction::none: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_BINARY, BM_SETCHECK, BST_CHECKED, 0); break;
            case UserData::Restriction::digits: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_DIGITS, BM_SETCHECK, BST_CHECKED, 0); break;
            case UserData::Restriction::letters: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_LETTERS, BM_SETCHECK, BST_CHECKED, 0); break;
            case UserData::Restriction::alphanum: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_ALPHANUM, BM_SETCHECK, BST_CHECKED, 0); break;
            case UserData::Restriction::password: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_PASSWORD, BM_SETCHECK, BST_CHECKED, 0); break;
            case UserData::Restriction::specials: ::SendDlgItemMessage(_hSelf, IDC_RANDOM_SPECIALS, BM_SETCHECK, BST_CHECKED, 0); break;
        }

        help_restrictions.setup(_hInst, _hSelf, ::GetDlgItem(_hSelf, IDC_RANDOM_HELP));
        help_enc.setup(_hInst, _hSelf, ::GetDlgItem(_hSelf, IDC_RANDOM_ENC_HELP));
        help_restrictions.setTooltip("you may restrict the output to certain ASCII ranges");
        help_restrictions.setURL(NPPC_RANDOM_HELP_URL);
        updateEncodingControls(options.encoding);

        goToCenter();
        return TRUE;
    }
    case WM_COMMAND :
    {
        switch (HIWORD(wParam))
        {
        case BN_CLICKED:
        {
            switch (LOWORD(wParam))
            {
            case IDC_CANCEL: case IDCANCEL:
            {
                EndDialog(_hSelf, IDC_CANCEL);
                return TRUE;
            }
            case IDC_OK: case IDC_RANDOM_TOCLIPBOARD:
            {
                try {
                    if (::SendDlgItemMessage(_hSelf, IDC_RANDOM_ENC_BINARY, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                        options.encoding = nppcrypt::Encoding::ascii;
                    } else if (::SendDlgItemMessage(_hSelf, IDC_RANDOM_ENC_BASE16, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                        options.encoding = nppcrypt::Encoding::base16;
                    } else if (::SendDlgItemMessage(_hSelf, IDC_RANDOM_ENC_BASE32, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                        options.encoding = nppcrypt::Encoding::base32;
                    } else {
                        options.encoding = nppcrypt::Encoding::base64;
                    }
                    nppcrypt::UserData data;
                    options.length = (size_t)::SendDlgItemMessage(_hSelf, IDC_RANDOM_SPIN, UDM_GETPOS32, 0, 0);

                    if (::SendDlgItemMessage(_hSelf, IDC_RANDOM_SPECIALS, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                        options.restriction = nppcrypt::UserData::Restriction::specials;
                    } else if (::SendDlgItemMessage(_hSelf, IDC_RANDOM_DIGITS, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                        options.restriction = nppcrypt::UserData::Restriction::digits;
                    } else if (::SendDlgItemMessage(_hSelf, IDC_RANDOM_LETTERS, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                        options.restriction = nppcrypt::UserData::Restriction::letters;
                    } else if (::SendDlgItemMessage(_hSelf, IDC_RANDOM_ALPHANUM, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                        options.restriction = nppcrypt::UserData::Restriction::alphanum;
                    } else if (::SendDlgItemMessage(_hSelf, IDC_RANDOM_PASSWORD, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                        options.restriction = nppcrypt::UserData::Restriction::password;
                    } else {
                        options.restriction = nppcrypt::UserData::Restriction::none;
                    }

                    data.random(options.length, options.restriction);
                    nppcrypt::secure_string str;
                    data.get(str, options.encoding);

                    if (LOWORD(wParam) == IDC_OK) {
                        help::scintilla::replaceSelection(str.c_str(), str.size());
                    } else {
                        help::windows::copyToClipboard((const unsigned char*)str.c_str(), str.size());
                    }
                    EndDialog(_hSelf, IDC_OK);
                    return TRUE;
                } catch (std::exception& exc) {
                    msgbox::error(_hSelf, exc.what());
                    return false;
                } catch (...) {
                    msgbox::error(_hSelf, "unknown exception!");
                    return false;
                }
                break;
            }
            case IDC_RANDOM_ENC_BINARY:
            {
                updateEncodingControls(nppcrypt::Encoding::ascii);
                break;
            }
            case IDC_RANDOM_ENC_BASE16:
            {
                updateEncodingControls(nppcrypt::Encoding::base16);
                break;
            }
            case IDC_RANDOM_ENC_BASE32:
            {
                updateEncodingControls(nppcrypt::Encoding::base32);
                break;
            }
            case IDC_RANDOM_ENC_BASE64:
            {
                updateEncodingControls(nppcrypt::Encoding::base64);
                break;
            }
            case IDC_RANDOM_BINARY:
            {
                if (::SendDlgItemMessage(_hSelf, IDC_RANDOM_ENC_BINARY, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                    help_enc.setWarning(true);
                    help_enc.setTooltip(nppcrypt::help::getInfo(nppcrypt::Encoding::ascii));
                }
                break;
            }
            case IDC_RANDOM_ALPHANUM: case IDC_RANDOM_SPECIALS: case IDC_RANDOM_DIGITS: case IDC_RANDOM_LETTERS: case IDC_RANDOM_PASSWORD:
            {
                if (::SendDlgItemMessage(_hSelf, IDC_RANDOM_ENC_BINARY, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                    updateEncodingControls(nppcrypt::Encoding::ascii);
                } else if (::SendDlgItemMessage(_hSelf, IDC_RANDOM_ENC_BASE16, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                    updateEncodingControls(nppcrypt::Encoding::base16);
                } else if (::SendDlgItemMessage(_hSelf, IDC_RANDOM_ENC_BASE32, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                    updateEncodingControls(nppcrypt::Encoding::base32);
                } else {
                    updateEncodingControls(nppcrypt::Encoding::base64);
                }
                break;
            }
            }
            break;
        }
        case EN_CHANGE:
        {
            /* prevent out of bounds user input to length spin-control */
            if (LOWORD(wParam) == IDC_RANDOM_EDIT) {
                if (GetWindowTextLength(::GetDlgItem(_hSelf, IDC_RANDOM_EDIT)) > 0) {
                    nppcrypt::secure_string temp_str;
                    getText(IDC_RANDOM_EDIT, temp_str);
                    int temp = std::stoi(temp_str.c_str());
                    if (temp > nppcrypt::Constants::rand_char_max) {
                        ::SendDlgItemMessage(_hSelf, IDC_RANDOM_SPIN, UDM_SETPOS32, 0, nppcrypt::Constants::rand_char_max);
                    } else if (temp < 1) {
                        ::SendDlgItemMessage(_hSelf, IDC_RANDOM_SPIN, UDM_SETPOS32, 0, 1);
                    }
                } else {
                    ::SendDlgItemMessage(_hSelf, IDC_RANDOM_SPIN, UDM_SETPOS32, 0, 1);
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

void DlgRandom::updateEncodingControls(nppcrypt::Encoding enc)
{
    help_enc.setURL(nppcrypt::help::getHelpURL(enc));
    if (enc == nppcrypt::Encoding::ascii) {
        if (::SendDlgItemMessage(_hSelf, IDC_RANDOM_BINARY, BM_GETCHECK, 0, 0) == BST_CHECKED) {
            help_enc.setWarning(true);
            help_enc.setTooltip(nppcrypt::help::getInfo(nppcrypt::Encoding::ascii));
        } else {
            help_enc.setWarning(false);
            help_enc.setTooltip("ascii/utf8 output");
        }
    } else {
        help_enc.setWarning(false);
        help_enc.setTooltip(nppcrypt::help::getInfo(enc));
    }
}