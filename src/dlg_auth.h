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

#ifndef DLG_AUTH_H_DEF
#define DLG_AUTH_H_DEF

#include "modaldialog.h"
#include "help.h"
#include "crypt.h"

class DlgAuth: public ModalDialog
{
public:    
                        DlgAuth() : ModalDialog() {};
    bool                doDialog(const TCHAR* filename=NULL);
    crypt::UserData&    getInput();

private:
    INT_PTR CALLBACK    run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam);

    crypt::UserData     input;
    std::wstring        caption;
};



#endif