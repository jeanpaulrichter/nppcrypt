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

#include <windows.h>
#include "messagebox.h"
#include "resource.h"
#include "help.h"

MsgBox::~MsgBox() {
    if (_hSelf != NULL) {
        ::SetWindowLongPtr(_hSelf, GWLP_USERDATA, (long)NULL);
        ::DestroyWindow(_hSelf);
        _hSelf = NULL;
    }
}

bool MsgBox::doDialog()
{
    INT_PTR ret = DialogBoxParam(_hInst, MAKEINTRESOURCE(IDD_MSGBOX), _hParent, dlgProc, reinterpret_cast<LPARAM>(this));

    if (ret == IDOK) {
        return true;
    } else {
        return false;
    }    
}

INT_PTR CALLBACK MsgBox::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG:
    {
        HWND hIcon, hText, hLink, hGroup, hOK;
        RECT rc_self, rc_parent, rc_icon, rc_text, rc_link, rc_group, rc_ok;
        std::wstring wsText;

        /* get handles */
        hIcon = ::GetDlgItem(_hSelf, IDC_MSGBOX_ICON);
        hText = ::GetDlgItem(_hSelf, IDC_MSGBOX_TEXT);
        hLink = ::GetDlgItem(_hSelf, IDC_MSGBOX_LINK);
        hGroup = ::GetDlgItem(_hSelf, IDC_MSGBOX_GROUP);
        hOK = ::GetDlgItem(_hSelf, IDOK);

        /* get rects */
        ::GetClientRect(_hParent, &rc_parent);
        ::GetWindowRect(_hSelf, &rc_self);
        ::GetWindowRect(hIcon, &rc_icon);
        ::GetWindowRect(hText, &rc_text);
        ::GetWindowRect(hLink, &rc_link);
        ::GetWindowRect(hGroup, &rc_group);
        ::GetWindowRect(hOK, &rc_ok);
        ::MapWindowPoints(HWND_DESKTOP, _hSelf, (LPPOINT)&rc_icon, 2);
        ::MapWindowPoints(HWND_DESKTOP, _hSelf, (LPPOINT)&rc_text, 2);
        ::MapWindowPoints(HWND_DESKTOP, _hSelf, (LPPOINT)&rc_link, 2);
        ::MapWindowPoints(HWND_DESKTOP, _hSelf, (LPPOINT)&rc_group, 2);
        ::MapWindowPoints(HWND_DESKTOP, _hSelf, (LPPOINT)&rc_ok, 2);

        /* init link-control */
        if (_url) {
            _link.init(_hInst, _hSelf);
            _link.create(hLink, _url);
        } else {
            ::ShowWindow(hLink, SW_HIDE);
        }

        /* load icon */
        int icon_id;
        if (_icon == Icon::error) {
            icon_id = IDI_MSGBOX_ERROR;
        } else if (_icon == Icon::warning) {
            icon_id = IDI_MSGBOX_WARNING;
        } else {
            icon_id = IDI_MSGBOX_INFO;
        }
        HICON hIconImage = (HICON)LoadImage(_hInst, MAKEINTRESOURCE(icon_id), IMAGE_ICON, rc_icon.right - rc_icon.left, rc_icon.bottom - rc_icon.top, LR_SHARED);
        if (hIconImage) {
            SendMessage(hIcon, STM_SETICON, (WPARAM)hIconImage, NULL);
        }

        /* set text */
        try {
            help::windows::utf8_to_wchar(_text, -1, wsText);
            ::SetWindowText(hText, wsText.c_str());

            std::wstring wsTitle;
            help::windows::utf8_to_wchar(_title, -1, wsTitle);
            SetWindowText(_hSelf, wsTitle.c_str());

            if (_url && _url_caption) {
                std::wstring wsLink;
                help::windows::utf8_to_wchar(_url_caption, -1, wsLink);
                ::SetWindowText(hLink, wsLink.c_str());
            }
        } catch (...) {}

        /* calc rect needed for text */
        HDC hdc = GetDC(hText);
        HFONT font = (HFONT)::SendMessage(hText, WM_GETFONT, 0, 0);
        HFONT font_old = (HFONT)::SelectObject(hdc, font);
        DrawText(hdc, wsText.c_str(), (int)wsText.size(), &rc_text, DT_CALCRECT | DT_LEFT | DT_WORDBREAK);
        ::SelectObject(hdc, font_old);
        ::ReleaseDC(hText, hdc);

        /* resize dialog */
        int ok_height = rc_ok.bottom - rc_ok.top;
        int icon_height = rc_icon.bottom - rc_icon.top;
        int text_height = rc_text.bottom - rc_text.top;
        int link_height = rc_link.bottom - rc_link.top;
        int content_height;
        if (_url) {
            content_height = text_height + 2 + link_height;
        } else {
            content_height = text_height;
        }
        if (content_height > icon_height) {
            rc_group.bottom = rc_text.top + content_height + 8;
        } else {
            rc_group.bottom = rc_text.top + icon_height + 8;
        }
        int group_center = (rc_group.top + rc_group.bottom) / 2;
        rc_text.top = group_center - content_height / 2 + 3;
        rc_text.bottom = rc_text.top + text_height;
        rc_link.top = rc_text.bottom + 2;
        rc_link.bottom = rc_link.top + link_height;
        rc_icon.top = group_center - (icon_height / 2) + 3;
        rc_icon.bottom = rc_icon.top + icon_height;
        rc_ok.top = rc_group.bottom + 2;
        rc_ok.bottom = rc_ok.top + ok_height;
        rc_self.bottom = rc_self.top + rc_ok.bottom + 33;
        
        ::MoveWindow(hText, rc_text.left, rc_text.top, rc_text.right - rc_text.left, rc_text.bottom - rc_text.top, false);
        ::MoveWindow(hIcon, rc_icon.left, rc_icon.top, rc_icon.right - rc_icon.left, rc_icon.bottom - rc_icon.top, false);
        ::MoveWindow(hLink, rc_link.left, rc_link.top, rc_link.right - rc_link.left, rc_link.bottom - rc_link.top, false);
        ::MoveWindow(hGroup, rc_group.left, rc_group.top, rc_group.right - rc_group.left, rc_group.bottom - rc_group.top, false);
        ::MoveWindow(hOK, rc_ok.left, rc_ok.top, rc_ok.right - rc_ok.left, rc_ok.bottom - rc_ok.top, false);

        POINT center;
        center.x = rc_parent.left + rc_parent.right / 2;
        center.y = rc_parent.top + rc_parent.bottom / 2;
        ::ClientToScreen(_hParent, &center);

        int self_width = rc_self.right - rc_self.left;
        int self_height = rc_self.bottom - rc_self.top;

        ::SetWindowPos(_hSelf, HWND_TOP, center.x - self_width / 2, center.y - self_height / 2, self_width, self_height, SWP_SHOWWINDOW);

        return TRUE;
    }
    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case IDOK:
            EndDialog(_hSelf, IDOK);
            return TRUE;
        case IDCANCEL:
            EndDialog(_hSelf, IDCANCEL);
            return TRUE;
        default:
            break;
        }
        break;
    }
    }
    return FALSE;
}

INT_PTR CALLBACK MsgBox::dlgProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG:
    {
        if (!lParam) {
            return FALSE;
        }
        MsgBox *pMsgBox = reinterpret_cast<MsgBox*>(lParam);
        ::SetWindowLongPtr(hwnd, GWLP_USERDATA, static_cast<LONG_PTR>(lParam));

        if (pMsgBox->_hSelf == NULL) {
            pMsgBox->_hSelf = hwnd;
            pMsgBox->run_dlgProc(message, wParam, lParam);
        }
        return TRUE;
    }
    case WM_DESTROY:
    {
        MsgBox *pMsgBox = reinterpret_cast<MsgBox*>(::GetWindowLongPtr(hwnd, GWLP_USERDATA));
        if (pMsgBox) {
            pMsgBox->_hSelf = NULL;
        }
        return TRUE;
    }
    default:
    {
        MsgBox *pMsgBox = reinterpret_cast<MsgBox*>(::GetWindowLongPtr(hwnd, GWLP_USERDATA));
        if (!pMsgBox) {
            return FALSE;
        } else {
            return pMsgBox->run_dlgProc(message, wParam, lParam);
        }        
    }
    }
}

void msgbox::info(HWND hwnd, const char* text, const char* url, const char* url_caption)
{
    MsgBox dlg(GetModuleHandle(TEXT("nppcrypt")), hwnd, MsgBox::Icon::info, "nppcrypt::info", text, url, url_caption);
    dlg.doDialog();
}

void msgbox::warning(HWND hwnd, const char* text, const char* url)
{
    MsgBox dlg(GetModuleHandle(TEXT("nppcrypt")), hwnd, MsgBox::Icon::warning, "nppcrypt::warning", text, url);
    dlg.doDialog();
}

void msgbox::error(HWND hwnd, const char* text, const char* url)
{
    MsgBox dlg(GetModuleHandle(TEXT("nppcrypt")), hwnd, MsgBox::Icon::error, "nppcrypt::error", text, url);
    dlg.doDialog();
}