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

#ifndef DLG_INITDATA_DEFINE_H
#define DLG_INITDATA_DEFINE_H

#include "npp/Window.h"
#include "unicode.h"
#include "mdef.h"
#include "crypt.h"


class DlgInitdata : public Window
{
public:

	DlgInitdata();
	void init(HINSTANCE hInst, HWND parent);
	virtual void destroy() { ::DestroyWindow(_hSelf); };

	bool doDialog(crypt::InitStrings* data, bool salt, bool iv, bool tag);

private:
	static BOOL CALLBACK dlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam);
	BOOL CALLBACK run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam);

	crypt::InitStrings* _data;
	bool				_salt;
	bool				_iv;
	bool				_tag;
};


#endif