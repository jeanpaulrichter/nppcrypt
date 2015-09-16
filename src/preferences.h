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

#ifndef PREFERENCES_DEFINE_H
#define PREFERENCES_DEFINE_H

#include "crypt.h"

class CPreferences 
{
public:
	// nppcrypt-files:
	struct {
		bool	enable;
		bool	askonsave;
		TCHAR	extension[31];
		int		ext_length;
	} files;

	bool no_ascii;

	// key-presets:
	struct KeyPreset {
		TCHAR			label[31];
		unsigned char	data[16];
	};

	CPreferences();
	static CPreferences& Instance() { static CPreferences single; return single; };

	bool load(const TCHAR* path, Crypt::Options& crypt, Crypt::HashOptions& hash, Crypt::RandOptions& random);
	bool save(Crypt::Options& crypt, Crypt::HashOptions& hash, Crypt::RandOptions& random);

	size_t  getKeyNum();
	bool	addKey(const KeyPreset& key);
	bool	delKey(size_t i);
	const TCHAR* getKeyLabel(size_t i);
	const unsigned char* getKey(size_t i);
private:
	CPreferences(CPreferences const&);
	CPreferences& operator=(CPreferences const&);

	std::vector<KeyPreset>	keys;
	std::string				filepath;
};

extern CPreferences& preferences;

#endif