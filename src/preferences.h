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

#ifndef PREFERENCES_H_DEF
#define PREFERENCES_H_DEF

#include "crypt.h"
#include "mdef.h"

struct CurrentOptions
{
	crypt::Options::Crypt	crypt;
	crypt::Options::Hash	hash;
	crypt::Options::Random	random;
	crypt::Options::Convert	convert;
};

class CPreferences 
{
public:
	struct KeyPreset
	{
		TCHAR			label[31];
		unsigned char	data[16];
	};

	struct
	{
		bool	enable;
		bool	askonsave;
		string	extension;
	} files;

							CPreferences();
	static CPreferences&	Instance() { static CPreferences single; return single; };

	void					load(const TCHAR* path, CurrentOptions& current);
	void					save(CurrentOptions& current);

	size_t					getKeyNum() const;
	bool					addKey(const KeyPreset& key);
	bool					delKey(size_t i);
	const TCHAR*			getKeyLabel(size_t i) const;
	const unsigned char*	getKey(size_t i) const;

private:
	CPreferences(CPreferences const&);
	CPreferences& operator=(CPreferences const&);

	void load_1010(std::ifstream& f, CurrentOptions& current);
	void validate(CurrentOptions& current);

	std::vector<KeyPreset>	keys;
	std::string				filepath;
};

extern CPreferences&		preferences;

#endif