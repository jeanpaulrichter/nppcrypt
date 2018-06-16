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

/*
	XORMask[128] and ANDMask[128] used to create sursor stolen from URLCtrl.h by Don HO
*/

#include "ctl_help.h"
#include "help.h"
#include "resource.h"
#include <Commctrl.h>

static BYTE XORMask[128] =
{
	0xff, 0xff, 0xff, 0xff,
	0xf9, 0xff, 0xff, 0xff,
	0xf0, 0xff, 0xff, 0xff,
	0xf0, 0xff, 0xff, 0xff,
	0xf0, 0xff, 0xff, 0xff,
	0xf0, 0xff, 0xff, 0xff,
	0xf0, 0x24, 0xff, 0xff,
	0xf0, 0x00, 0x7f, 0xff,
	0xc0, 0x00, 0x7f, 0xff,
	0x80, 0x00, 0x7f, 0xff,
	0x80, 0x00, 0x7f, 0xff,
	0x80, 0x00, 0x7f, 0xff,
	0x80, 0x00, 0x7f, 0xff,
	0x80, 0x00, 0x7f, 0xff,
	0xc0, 0x00, 0x7f, 0xff,
	0xe0, 0x00, 0x7f, 0xff,
	0xf0, 0x00, 0xff, 0xff,
	0xf0, 0x00, 0xff, 0xff,
	0xf0, 0x00, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
};

static BYTE ANDMask[128] =
{
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x06, 0x00, 0x00, 0x00,
	0x06, 0x00, 0x00, 0x00,
	0x06, 0x00, 0x00, 0x00,
	0x06, 0x00, 0x00, 0x00,
	0x06, 0x00, 0x00, 0x00,
	0x06, 0xdb, 0x00, 0x00,
	0x06, 0xdb, 0x00, 0x00,
	0x36, 0xdb, 0x00, 0x00,
	0x36, 0xdb, 0x00, 0x00,
	0x37, 0xff, 0x00, 0x00,
	0x3f, 0xff, 0x00, 0x00,
	0x3f, 0xff, 0x00, 0x00,
	0x1f, 0xff, 0x00, 0x00,
	0x0f, 0xff, 0x00, 0x00,
	0x07, 0xfe, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
};

HCURSOR HelpCtrl::hCursor = NULL;

HelpCtrl::HelpCtrl() : oldproc(NULL), hwnd_tooltip(NULL), icons_ready(false), hover(false)
{
	icons_normal[0] = NULL;
	icons_normal[1] = NULL;
	icons_warning[0] = NULL;
	icons_warning[1] = NULL;
}

HelpCtrl::~HelpCtrl()
{
	destroy();
}

void HelpCtrl::destroy()
{
	if (hCursor) {
		::DestroyCursor(hCursor);
		hCursor = NULL;
	}
}

void HelpCtrl::setup(HINSTANCE hInst, HWND hParent, HWND hCtrl, bool warning)
{
	init(hInst, hParent);
	::SetWindowLongPtr(hCtrl, GWL_STYLE, ::GetWindowLongPtr(hCtrl, GWL_STYLE) | SS_NOTIFY);
	_hSelf = hCtrl;

	if (!icons_ready) {
		RECT rc;
		getClientRect(rc);
		int width = rc.right - rc.left;
		int height = rc.bottom - rc.top;
		icons_normal[0] = (HICON)LoadImage(_hInst, MAKEINTRESOURCE(IDI_HELPCTRL_NORMAL), IMAGE_ICON, width, height, LR_SHARED);
		icons_normal[1] = (HICON)LoadImage(_hInst, MAKEINTRESOURCE(IDI_HELPCTRL_NORMAL_HOVER), IMAGE_ICON, width, height, LR_SHARED);
		icons_warning[0] = (HICON)LoadImage(_hInst, MAKEINTRESOURCE(IDI_HELPCTRL_WARNING), IMAGE_ICON, width, height, LR_SHARED);
		icons_warning[1] = (HICON)LoadImage(_hInst, MAKEINTRESOURCE(IDI_HELPCTRL_WARNING_HOVER), IMAGE_ICON, width, height, LR_SHARED);
		icon_disabled = (HICON)LoadImage(_hInst, MAKEINTRESOURCE(IDI_HELPCTRL_DISABLED), IMAGE_ICON, width, height, LR_SHARED);
		icons_ready = (icons_normal[0] && icons_normal[1] && icons_warning[0] && icons_warning[1] && icon_disabled);
	}
	if (icons_ready) {
		if (warning) {
			SendMessage(hCtrl, STM_SETICON, (WPARAM)icons_warning[0], (LPARAM)NULL);
		} else {
			SendMessage(hCtrl, STM_SETICON, (WPARAM)icons_normal[0], (LPARAM)NULL);
		}
	}
	if (!hCursor) {
		hCursor = ::CreateCursor(::GetModuleHandle(0), 5, 2, 32, 32, XORMask, ANDMask);
	}
	oldproc = (WNDPROC)::SetWindowLongPtr(hCtrl, GWLP_WNDPROC, (LONG_PTR)HelpCtrlProc);
	::SetWindowLongPtr(hCtrl, GWLP_USERDATA, (LONG_PTR)this);
	hover = false;
	hwnd_tooltip = NULL;
	this->warning = warning;
}

void HelpCtrl::setURL(const char* s, bool tooltip)
{
	if (!s) {
		return;
	}
	try {
		helper::Windows::utf8_to_wchar(s, (int)strlen(s), s_url);
		if (tooltip) {
			_settooltip((LPWSTR)s_url.c_str());
		}
		url_active = true;
	} catch(...) {}
}

void HelpCtrl::enableURL(bool v)
{
	url_active = v;
}

void HelpCtrl::setTooltip(const char* s)
{
	if (!s) {
		return;
	}
	if (*s == '\0') {
		enableTooltip(false);
	}
	try {
		std::wstring temp;
		helper::Windows::utf8_to_wchar(s, (int)strlen(s), temp);
		_settooltip((LPWSTR)temp.c_str());
	}
	catch (...) {}
}

void HelpCtrl::enableTooltip(bool v)
{
	if (hwnd_tooltip) {
		SendMessage(hwnd_tooltip, TTM_ACTIVATE, (WPARAM)v ? TRUE : FALSE, 0);
	}
}

void HelpCtrl::enable(bool v)
{
	if (v) {
		if (icons_ready) {
			if (warning) {
				SendMessage(_hSelf, STM_SETICON, (WPARAM)icons_warning[0], (LPARAM)NULL);
			} else {
				SendMessage(_hSelf, STM_SETICON, (WPARAM)icons_normal[0], (LPARAM)NULL);
			}
		}
		::EnableWindow(_hSelf, true);
	} else {
		if (icons_ready) {
			SendMessage(_hSelf, STM_SETICON, (WPARAM)icon_disabled, (LPARAM)NULL);
		}
		::EnableWindow(_hSelf, false);
	}
}

void HelpCtrl::setWarning(bool warning)
{
	if (icons_ready) {
		this->warning = warning;
		int i = hover ? 1 : 0;
		if (warning) {
			SendMessage(_hSelf, STM_SETICON, (WPARAM)icons_warning[i], (LPARAM)NULL);
		} else {
			SendMessage(_hSelf, STM_SETICON, (WPARAM)icons_normal[i], (LPARAM)NULL);
		}
	}
}

void HelpCtrl::_settooltip(LPWSTR s)
{
	if (!hwnd_tooltip) {
		hwnd_tooltip = CreateWindowEx(NULL, TOOLTIPS_CLASS, NULL,
			WS_POPUP | TTS_ALWAYSTIP | TTS_BALLOON,
			CW_USEDEFAULT, CW_USEDEFAULT,
			CW_USEDEFAULT, CW_USEDEFAULT,
			_hSelf, NULL,
			_hInst, NULL);
		if (hwnd_tooltip) {
			TOOLINFO toolInfo = { 0 };
			toolInfo.cbSize = sizeof(toolInfo);
			toolInfo.hwnd = _hParent;
			toolInfo.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
			toolInfo.uId = (UINT_PTR)_hSelf;
			toolInfo.lpszText = s;
			SendMessage(hwnd_tooltip, TTM_ADDTOOL, 0, (LPARAM)&toolInfo);
		}
	} else {
		TOOLINFO toolInfo = { 0 };
		toolInfo.cbSize = sizeof(toolInfo);
		toolInfo.hwnd = _hParent;
		toolInfo.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
		toolInfo.uId = (UINT_PTR)_hSelf;
		toolInfo.lpszText = s;
		SendMessage(hwnd_tooltip, TTM_UPDATETIPTEXT, 0, (LPARAM)&toolInfo);
		SendMessage(hwnd_tooltip, TTM_ACTIVATE, (WPARAM)TRUE, 0);
	}
}

LRESULT HelpCtrl::runProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
	switch (Message)
	{
	case WM_MOUSEMOVE:
	{
		if (!hover && icons_ready) {
			TRACKMOUSEEVENT tme;
			tme.cbSize = sizeof(TRACKMOUSEEVENT);
			tme.dwFlags = TME_LEAVE;
			tme.hwndTrack = _hSelf;
			TrackMouseEvent(&tme);

			if (warning) {
				SendMessage(_hSelf, STM_SETICON, (WPARAM)icons_warning[1], (LPARAM)NULL);
			} else {
				SendMessage(_hSelf, STM_SETICON, (WPARAM)icons_normal[1], (LPARAM)NULL);
			}
			hover = true;
		}		
		SetCursor(hCursor);
		return TRUE;
	}
	case WM_MOUSELEAVE:
		hover = false;
		if (warning) {
			SendMessage(_hSelf, STM_SETICON, (WPARAM)icons_warning[0], (LPARAM)NULL);
		} else {
			SendMessage(_hSelf, STM_SETICON, (WPARAM)icons_normal[0], (LPARAM)NULL);
		}
		break;
	case WM_LBUTTONUP:
		if (url_active) {
			::ShellExecute(NULL, TEXT("open"), s_url.c_str(), NULL, NULL, SW_SHOWNORMAL);
		}
		break;
	case WM_NCHITTEST:
		return HTCLIENT;
	}
	return ::CallWindowProc(oldproc, hwnd, Message, wParam, lParam);
}
