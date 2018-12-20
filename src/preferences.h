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

#ifndef PREFERENCES_H_DEF
#define PREFERENCES_H_DEF

#include "crypt.h"
#include "mdef.h"
#include "cryptheader.h"
#include "help.h"
#include "tinyxml2/tinyxml2.h"

struct CryptInfo {
	enum class Modus : unsigned { easy, advanced };
	CryptInfo() : modus(Modus::easy) {};

	crypt::Options::Crypt	options;
	crypt::UserData			password;
	CryptHeader::HMAC		hmac;
	Modus					modus;
};

struct RandomOptions
{
	RandomOptions() : length(16), restriction(crypt::UserData::Restriction::alphanum), encoding(crypt::Encoding::ascii) {};
	size_t							length;
	crypt::UserData::Restriction	restriction;
	crypt::Encoding					encoding;
};

struct CurrentOptions
{
	CryptInfo				crypt;
	crypt::Options::Hash	hash;
	RandomOptions			random;
	crypt::Options::Convert	convert;
};

class CPreferences 
{
public:
	struct KeyPreset
	{
		TCHAR			label[NPPC_MAX_PRESET_LABELLENGTH + 1];
		byte			data[16];
	};

	struct NppCryptFiles
	{
		bool			enable;
		bool			askonsave;
		std::wstring	extension;
	} files;

							CPreferences();
	static CPreferences&	Instance() { static CPreferences single; return single; };

	void					load(const std::wstring& path, CurrentOptions& current);
	void					save(CurrentOptions& current);
	bool					failed() { return !file_loaded; };

	size_t					getKeyNum() const;
	bool					addKey(const KeyPreset& key);
	bool					delKey(size_t i);
	const TCHAR*			getKeyLabel(size_t i) const;
	const unsigned char*	getKey(size_t i) const;

	const crypt::Options::Crypt& getDefaultEncryption() { return default_crypt; };

private:
	CPreferences(CPreferences const&);
	CPreferences& operator=(CPreferences const&);

	void					writeCryptOptions(std::ofstream& f, const crypt::Options::Crypt& opt, const std::string& indent, const std::string& eol);
	void					parseCryptOptions(tinyxml2::XMLElement* parent, crypt::Options::Crypt& opt);

	std::vector<KeyPreset>	keys;
	std::wstring			filepath;
	bool					file_loaded;
	crypt::Options::Crypt	default_crypt;
};

extern CPreferences&		preferences;

#endif