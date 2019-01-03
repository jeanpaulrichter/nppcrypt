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

#ifndef DLG_MESSAGEBOX_H_DEF
#define DLG_MESSAGEBOX_H_DEF

#include "modaldialog.h"
#include "npp/URLCtrl.h"

class MsgBox
{
public:
    enum class Icon { info, error, warning };

    MsgBox(HINSTANCE hInst, HWND parent, Icon icon, const char* title, const char* text, const char* url = NULL, const char* url_caption = NULL) :
        _hInst(hInst), _hParent(parent), _icon(icon), _title(title), _text(text), _url(url), _url_caption(url_caption), _hSelf(NULL) {};
    ~MsgBox();

    bool doDialog();

private:
    static INT_PTR CALLBACK     dlgProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

    INT_PTR CALLBACK    run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam);    
    
    URLCtrl             _link;
    Icon                _icon;
    const char*         _title;
    const char*         _text;
    const char*         _url;
    const char*         _url_caption;

    HINSTANCE           _hInst;
    HWND                _hParent;
    HWND                _hSelf;
};

namespace msgbox {
    void info(HWND hwnd, const char* text, const char* url = NULL, const char* url_caption = NULL);
    void warning(HWND hwnd, const char* text, const char* url = NULL);
    void error(HWND hwnd, const char* text, const char* url = NULL);
};

#endif