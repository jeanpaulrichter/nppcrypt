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

#ifndef DLG_HASH_H_DEF
#define DLG_HASH_H_DEF

#include "modaldialog.h"
#include "exception.h"
#include "crypt.h"
#include "ctl_help.h"

class DlgHash : public ModalDialog
{
public:
						DlgHash(crypt::Options::Hash& opt);
	void				destroy();

private:
	/**** messagehandler ****/
	INT_PTR CALLBACK run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam);

	/**** update this->options ****/
	bool prepareOptions();
	/**** make sure custom key is valid ****/
	bool checkKey(bool updatedata);

	/**** update dialog on change of algorithm ****/
	void onChangeAlgorithm(size_t digest = 0);
	/**** enable/disable key-controls ****/
	void updateKeyControls(bool enable);
	/**** update encoding controls ****/
	void updateEncodingControls(crypt::Encoding enc);
	
	crypt::Options::Hash&	options;
	size_t					keylength;
	bool					invalid_key;
	HelpCtrl				help_enc;
	HelpCtrl				help_hash;
	HBRUSH					brush_red;
};

#endif
