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

#include "resource.h"
#include "dlg_hash.h"
#include "preferences.h"
#include "npp/PluginInterface.h"
#include "npp/Definitions.h"
#include "help.h"
#include "crypt_help.h"
#include "messagebox.h"

DlgHash::DlgHash(nppcrypt::Options::Hash& opt) : ModalDialog(), options(opt)
{
}

void DlgHash::destroy()
{
    if (brush_red) {
        DeleteObject(brush_red);
    }
    ModalDialog::destroy();
};

INT_PTR CALLBACK DlgHash::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG:
    {
        if (!brush_red) {
            brush_red = CreateSolidBrush(RGB(255, 0, 0));
        }
        invalid_key = false;

        if(!help::buffer::isCurrent8Bit()) {
            if (options.encoding == nppcrypt::Encoding::ascii) {
                options.encoding = nppcrypt::Encoding::base16;
                ::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_ENC_ASCII), false);
            }
        }
        ::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_ASCII, BM_SETCHECK, (options.encoding == nppcrypt::Encoding::ascii), 0);
        ::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE16, BM_SETCHECK, (options.encoding == nppcrypt::Encoding::base16), 0);
        ::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE32, BM_SETCHECK, (options.encoding == nppcrypt::Encoding::base32), 0);
        ::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE64, BM_SETCHECK, (options.encoding == nppcrypt::Encoding::base64), 0);

        for(nppcrypt::help::Hashnames it; *it; ++it) {
            ::SendDlgItemMessage(_hSelf, IDC_HASH_ALGO, CB_ADDSTRING, 0, (LPARAM)help::windows::ToWCHAR(*it).c_str());
        }
        ::SendDlgItemMessage(_hSelf, IDC_HASH_ALGO, CB_SETCURSEL, (int)options.algorithm, 0);

        ::SendDlgItemMessage(_hSelf, IDC_HASH_USE_KEY, BM_SETCHECK, options.use_key, 0);
        ::SendDlgItemMessage(_hSelf, IDC_HASH_KEY, EM_LIMITTEXT, NPPC_MAX_HMAC_KEYLENGTH, 0);
        ::SendDlgItemMessage(_hSelf, IDC_HASH_KEY, EM_SETPASSWORDCHAR, '*', 0);

        for (size_t i = 0; i < preferences.getKeyNum(); i++) {
            ::SendDlgItemMessage(_hSelf, IDC_HASH_KEYLIST, CB_ADDSTRING, 0, (LPARAM)preferences.getKeyLabel(i));
        }
        ::SendDlgItemMessage(_hSelf, IDC_HASH_KEYLIST, CB_SETCURSEL, 0, 0);
        ::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO1, BM_SETCHECK, true, 0);

        setupInputEncodingSelect(_hSelf, IDC_HASH_KEY_ENC);

        help_hash.setup(_hInst, _hSelf, ::GetDlgItem(_hSelf, IDC_HASH_ALGO_HELP), nppcrypt::help::checkProperty(options.algorithm, nppcrypt::WEAK));
        help_enc.setup(_hInst, _hSelf, ::GetDlgItem(_hSelf, IDC_HASH_ENC_HELP));

        updateEncodingControls(options.encoding);
        onChangeAlgorithm(options.digest_length);

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
            case IDC_CANCEL: case IDCANCEL:
            {
                EndDialog(_hSelf, IDC_CANCEL);
                return TRUE;
            }
            case IDC_OK: case IDC_HASH_TOCLIPBOARD:
            {
                try {
                    const byte*             pdata;
                    size_t                  data_length;
                    std::basic_string<byte> buffer;

                    if (!prepareOptions()) {
                        return TRUE;
                    }
                    help::scintilla::getSelection(&pdata, &data_length);
                    nppcrypt::hash(options, buffer, { { pdata, data_length} });
                    if (LOWORD(wParam) == IDC_OK) {
                        help::scintilla::replaceSelection(buffer);
                    } else {
                        help::windows::copyToClipboard(buffer);
                    }
                    options.key.clear();
                    EndDialog(_hSelf, IDC_OK);
                } catch (std::exception& exc) {
                    msgbox::error(_hSelf, exc.what());
                    return false;
                } catch (...) {
                    msgbox::error(_hSelf, "unknown exception!");
                    return false;
                }
                break;
            }
            case IDC_HASH_USE_KEY:
            {
                bool use_key = !!::SendDlgItemMessage(_hSelf, IDC_HASH_USE_KEY, BM_GETCHECK, 0, 0);
                updateKeyControls(use_key);
                break;
            }
            case IDC_HASH_KEYRADIO1: case IDC_HASH_KEYRADIO2:
            {
                updateKeyControls(true);
                break;
            }
            case IDC_HASH_KEY_SHOW:
            {
                bool show = !!::SendDlgItemMessage(_hSelf, IDC_HASH_KEY_SHOW, BM_GETCHECK, 0, 0);
                ::SendDlgItemMessage(_hSelf, IDC_HASH_KEY, EM_SETPASSWORDCHAR, show ? 0 : '*', 0);
                InvalidateRect(::GetDlgItem(_hSelf, IDC_HASH_KEY), 0, TRUE);
                ::SetFocus(::GetDlgItem(_hSelf, IDC_HASH_KEY));
                break;
            }
            case IDC_HASH_ENC_ASCII:
            {
                updateEncodingControls(nppcrypt::Encoding::ascii);
                break;
            }
            case IDC_HASH_ENC_BASE16:
            {
                updateEncodingControls(nppcrypt::Encoding::base16);
                break;
            }
            case IDC_HASH_ENC_BASE32:
            {
                updateEncodingControls(nppcrypt::Encoding::base32);
                break;
            }
            case IDC_HASH_ENC_BASE64:
            {
                updateEncodingControls(nppcrypt::Encoding::base64);
                break;
            }
            }
            break;
        }
        case CBN_SELCHANGE:
        {
            switch (LOWORD(wParam))
            {
            case IDC_HASH_ALGO:
            {
                onChangeAlgorithm();
                break;
            }
            case IDC_HASH_KEY_ENC:
            {
                checkKey(false);
                InvalidateRect(::GetDlgItem(_hSelf, IDC_HASH_KEY), 0, TRUE);
                ::SetFocus(::GetDlgItem(_hSelf, IDC_HASH_KEY));
                break;
            }
            }
            break;
        }
        case EN_CHANGE:
        {
            if (LOWORD(wParam) == IDC_HASH_KEY) {
                checkKey(false);
                InvalidateRect(::GetDlgItem(_hSelf, IDC_HASH_KEY), 0, TRUE);
            }
            break;
        }
        }
        break;
    }
    case WM_CTLCOLOREDIT:
    {
        if (invalid_key && (HWND)lParam == GetDlgItem(_hSelf, IDC_HASH_KEY)) {
            SetBkMode((HDC)wParam, TRANSPARENT);
            return (INT_PTR)brush_red;
        }
        break;
    }
    }
    return FALSE;
}

bool DlgHash::prepareOptions()
{
    options.algorithm = (nppcrypt::Hash)::SendDlgItemMessage(_hSelf, IDC_HASH_ALGO, CB_GETCURSEL, 0, 0);
    options.digest_length = nppcrypt::help::getHashDigestByIndex(options.algorithm, (unsigned int)::SendDlgItemMessage(_hSelf, IDC_HASH_DIGESTS, CB_GETCURSEL, 0, 0));

    if (::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_ASCII, BM_GETCHECK, 0, 0)) {
        options.encoding = nppcrypt::Encoding::ascii;
    } else if (::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE16, BM_GETCHECK, 0, 0)) {
        options.encoding = nppcrypt::Encoding::base16;
    } else if (::SendDlgItemMessage(_hSelf, IDC_HASH_ENC_BASE32, BM_GETCHECK, 0, 0)) {
        options.encoding = nppcrypt::Encoding::base32;
    } else {
        options.encoding = nppcrypt::Encoding::base64;
    }

    if (nppcrypt::help::checkProperty(options.algorithm, nppcrypt::HMAC_SUPPORT) || nppcrypt::help::checkProperty(options.algorithm, nppcrypt::KEY_SUPPORT)) {
        options.use_key = !!::SendDlgItemMessage(_hSelf, IDC_HASH_USE_KEY, BM_GETCHECK, 0, 0);
    } else {
        options.use_key = false;
    }

    if (options.use_key) {
        if (!!::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO2, BM_GETCHECK, 0, 0)) {
            if (!checkKey(true)) {
                InvalidateRect(::GetDlgItem(_hSelf, IDC_HASH_KEY), 0, TRUE);
                ::SetFocus(::GetDlgItem(_hSelf, IDC_HASH_KEY));
                return false;
            }

        } else {
            size_t keyid = (size_t)::SendDlgItemMessage(_hSelf, IDC_HASH_KEYLIST, CB_GETCURSEL, 0, 0);
            options.key.set(preferences.getKey(keyid), 16);
        }
    }
    return true;
}

bool DlgHash::checkKey(bool updatedata)
{
    int len = GetWindowTextLength(::GetDlgItem(_hSelf, IDC_HASH_KEY));
    if (len <= 0) {
        invalid_key = true;
    } else {
        nppcrypt::secure_string    temp;
        nppcrypt::UserData         data;
        nppcrypt::Encoding         enc;

        enc = (nppcrypt::Encoding)::SendDlgItemMessage(_hSelf, IDC_HASH_KEY_ENC, CB_GETCURSEL, 0, 0);
        getText(IDC_HASH_KEY, temp);
        data.set(temp.c_str(), temp.size(), enc);
        invalid_key = (data.size() == 0 || (keylength > 0 && data.size() != keylength));
        if (!invalid_key && updatedata) {
            options.key.set(data);
            for (size_t i = 0; i < temp.size(); i++) {
                temp[i] = '.';
            }
            setText(IDC_HASH_KEY, temp);
        }
    }
    return !invalid_key;
}

void DlgHash::onChangeAlgorithm(size_t digest)
{
    nppcrypt::Hash cur_sel = (nppcrypt::Hash)::SendDlgItemMessage(_hSelf, IDC_HASH_ALGO, CB_GETCURSEL, 0, 0);

    // ----------------------------- Update Digests ----------------------------------------------------------------
    std::wstring temp_str;
    ::SendDlgItemMessage(_hSelf, IDC_HASH_DIGESTS, CB_RESETCONTENT, 0, 0);

    for (nppcrypt::help::HashDigests it(cur_sel); *it; ++it) {
        temp_str = std::to_wstring(*it * 8);
        temp_str.append(TEXT(" Bits"));
        ::SendDlgItemMessage(_hSelf, IDC_HASH_DIGESTS, CB_ADDSTRING, 0, (LPARAM)temp_str.c_str());
    }
    ::SendDlgItemMessage(_hSelf, IDC_HASH_DIGESTS, CB_SETCURSEL, nppcrypt::help::getHashDigestIndex(cur_sel, (unsigned int)digest), 0);

    // ----------------------------- Key Options -------------------------------------------------------------------
    if (nppcrypt::help::checkProperty(cur_sel, nppcrypt::HMAC_SUPPORT) || nppcrypt::help::checkProperty(cur_sel, nppcrypt::KEY_SUPPORT)) {
        if (nppcrypt::help::checkProperty(cur_sel, nppcrypt::HMAC_SUPPORT)) {
            ::SetDlgItemText(_hSelf, IDC_HASH_USE_KEY, TEXT("HMAC:"));
        } else {
            ::SetDlgItemText(_hSelf, IDC_HASH_USE_KEY, TEXT("use key:"));
        }
        if (nppcrypt::help::checkProperty(cur_sel, nppcrypt::KEY_REQUIRED)) {
            ::SendDlgItemMessage(_hSelf, IDC_HASH_USE_KEY, BM_SETCHECK, true, 0);
            ::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_USE_KEY), false);
            updateKeyControls(true);
        } else {
            ::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_USE_KEY), true);
            bool use_key = !!::SendDlgItemMessage(_hSelf, IDC_HASH_USE_KEY, BM_GETCHECK, 0, 0);
            updateKeyControls(use_key);
        }
        size_t digest_len;
        nppcrypt::getHashInfo(cur_sel, digest_len, keylength);
    } else {
        updateKeyControls(false);
        ::SendDlgItemMessage(_hSelf, IDC_HASH_USE_KEY, BM_SETCHECK, false, 0);
        ::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_USE_KEY), false);
    }
    help_hash.setURL(nppcrypt::help::getHelpURL(cur_sel));
    help_hash.setTooltip(nppcrypt::help::getInfo(cur_sel));
    help_hash.setWarning(nppcrypt::help::checkProperty(cur_sel, nppcrypt::WEAK));
}

void DlgHash::updateKeyControls(bool enable)
{
    ::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEYRADIO1), enable);
    ::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEYRADIO2), enable);
    if (enable) {
        bool password = !!::SendDlgItemMessage(_hSelf, IDC_HASH_KEYRADIO2, BM_GETCHECK, 0, 0);
        ::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEYLIST), !password);
        ::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEY), password);
        ::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEY_ENC), password);
        ::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEY_SHOW), password);
        if (password) {
            checkKey(false);
            InvalidateRect(::GetDlgItem(_hSelf, IDC_HASH_KEY), 0, TRUE);
            ::SetFocus(::GetDlgItem(_hSelf, IDC_HASH_KEY));
        }
    } else {
        ::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEYLIST), false);
        ::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEY), false);
        ::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEY_ENC), false);
        ::EnableWindow(::GetDlgItem(_hSelf, IDC_HASH_KEY_SHOW), false);
    }
}

void DlgHash::updateEncodingControls(nppcrypt::Encoding enc)
{
    help_enc.setURL(nppcrypt::help::getHelpURL(enc));
    if (enc == nppcrypt::Encoding::ascii) {
        help_enc.setWarning(true);
        help_enc.setTooltip(nppcrypt::help::getInfo(nppcrypt::Encoding::ascii));
    } else {
        help_enc.setWarning(false);
        help_enc.setTooltip(nppcrypt::help::getInfo(enc));
    }
}
