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


#ifndef HELPCTRL_INCLUDED
#define HELPCTRL_INCLUDED

#include <string>
#include "npp/Window.h"

class HelpCtrl : public Window
{
public:
    HelpCtrl();
    ~HelpCtrl();
    void setup(HINSTANCE hInst, HWND hParent, HWND hCtrl, bool warning = false);
    void setURL(const char* s, bool tooltip = false);
    void enableURL(bool v);
    void setTooltip(const char* s);
    void enableTooltip(bool v);
    void enable(bool v);
    void setWarning(bool warning);
    void destroy();

private:
    std::wstring    s_url;
    bool            url_active;
    bool            hover;
    bool            warning;
    static HCURSOR  hCursor;
    WNDPROC         oldproc;
    HWND            hwnd_tooltip;
    HICON           icon_disabled;
    HICON           icons_normal[2];
    HICON           icons_warning[2];
    bool            icons_ready;

    void            _settooltip(LPWSTR s);

    static LRESULT CALLBACK HelpCtrlProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam) {
        return ((HelpCtrl *)(::GetWindowLongPtr(hwnd, GWLP_USERDATA)))->runProc(hwnd, Message, wParam, lParam);
    };
    LRESULT runProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam);
};

#endif