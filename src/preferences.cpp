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

#include "preferences.h"
#include "mdef.h"
#include "exception.h"
#include <fstream>
#include <Windows.h>
#include "help.h"
#include "tinyxml2/tinyxml2.h"
#include "cryptopp/filters.h"
#include "cryptopp/base64.h"
#include "crypt_help.h"

CPreferences& preferences = CPreferences::Instance();

CPreferences::CPreferences()
{
	keys.resize(1);
	memcpy(keys[0].data, NPPC_DEF_HMAC_KEY, 16);
	lstrcpy(keys[0].label, TEXT(NPPC_DEF_HMAC_LABEL));
	files.extension = TEXT(NPPC_DEF_FILE_EXT);
	files.askonsave = true;
	files.enable = true;
	file_loaded = false;
};

void CPreferences::load(const std::wstring& path, CurrentOptions& current)
{
	try {
		std::string buffer;
		filepath.assign(path);
		std::ifstream fin(filepath, std::ios::in | std::ios::binary);
		try {
			if (!fin.is_open()) {
				throw std::exception();
			}
			fin.exceptions(std::ifstream::failbit | std::ifstream::badbit);
			fin.seekg(0, fin.end);
			size_t fin_size = fin.tellg();
			if (!fin_size || fin_size > 2048) {
				throw std::exception();
			}
			fin.seekg(0, fin.beg);
			buffer.resize(fin_size);
			fin.read(reinterpret_cast<char*>(&buffer[0]), fin_size);
			fin.close();
		} catch (...) {
			if (fin.is_open()) {
				fin.close();
			}
			throw CExc(CExc::Code::preffile_read_fail);
		}
	
		tinyxml2::XMLError		xml_err;
		tinyxml2::XMLDocument	xml_doc;

		xml_err = xml_doc.Parse(buffer.c_str(), buffer.size());
		if (xml_err != tinyxml2::XMLError::XML_NO_ERROR) {
			throw CExc(CExc::Code::preffile_corrupted);
		}
		tinyxml2::XMLElement* xml_nppcrypt = xml_doc.FirstChildElement();
		if (!xml_nppcrypt) {
			throw CExc(CExc::Code::preffile_corrupted);
		}

		// nppcrypt-files
		tinyxml2::XMLElement* xml_temp = xml_nppcrypt->FirstChildElement("files");
		if (xml_temp) {
			crypt::help::getBoolean(xml_temp->Attribute("enabled"), files.enable);
			crypt::help::getBoolean(xml_temp->Attribute("askonsave"), files.askonsave);
			const char* pExt = xml_temp->Attribute("extension");
			if (pExt && strlen(pExt) <= NPPC_FILE_EXT_MAXLENGTH) {
				try {
					helper::Windows::utf8_to_wchar(pExt, -1, files.extension);
				} catch(...) {
					files.extension = TEXT(NPPC_DEF_FILE_EXT);
				}
			}
		}

		// crypt_basic
		xml_temp = xml_nppcrypt->FirstChildElement("crypt_basic");
		if (xml_temp) {
			crypt::help::getCipher(xml_temp->Attribute("cipher"), current.crypt.options.cipher);
			crypt::help::getUnsigned(xml_temp->Attribute("key-length"), current.crypt.options.key.length);
			crypt::help::getCipherMode(xml_temp->Attribute("mode"), current.crypt.options.mode);
			crypt::help::getIVMode(xml_temp->Attribute("iv"), current.crypt.options.iv);			
		}

		// crypt_encoding
		xml_temp = xml_nppcrypt->FirstChildElement("crypt_encoding");
		if (xml_temp) {
			crypt::help::getEncoding(xml_temp->Attribute("enc"), current.crypt.options.encoding.enc);
			crypt::help::getEOL(xml_temp->Attribute("eol"), current.crypt.options.encoding.eol);
			crypt::help::getBoolean(xml_temp->Attribute("linebreaks"), current.crypt.options.encoding.linebreaks);
			crypt::help::getUnsigned(xml_temp->Attribute("linelength"), current.crypt.options.encoding.linelength);
			crypt::help::getBoolean(xml_temp->Attribute("uppercase"), current.crypt.options.encoding.uppercase);
		}

		// crypt_key
		xml_temp = xml_nppcrypt->FirstChildElement("crypt_key");
		if (xml_temp) {
			crypt::help::getUnsigned(xml_temp->Attribute("saltbytes"), current.crypt.options.key.salt_bytes);
			if (crypt::help::getKeyDerivation(xml_temp->Attribute("algorithm"), current.crypt.options.key.algorithm)) {
				switch (current.crypt.options.key.algorithm) {
				case crypt::KeyDerivation::pbkdf2:
				{
					crypt::Hash thash;
					if (crypt::help::getHash(xml_temp->Attribute("hash"), thash)) {
						current.crypt.options.key.options[0] = static_cast<int>(thash);
					}
					crypt::help::getInteger(xml_temp->Attribute("digest-length"), current.crypt.options.key.options[1]);
					crypt::help::getInteger(xml_temp->Attribute("iterations"), current.crypt.options.key.options[2]);
					break;
				}
				case crypt::KeyDerivation::bcrypt:
				{
					crypt::help::getInteger(xml_temp->Attribute("iterations"), current.crypt.options.key.options[0], true);
					break;
				}
				case crypt::KeyDerivation::scrypt:
				{
					crypt::help::getInteger(xml_temp->Attribute("N"), current.crypt.options.key.options[0], true);
					crypt::help::getInteger(xml_temp->Attribute("r"), current.crypt.options.key.options[1]);
					crypt::help::getInteger(xml_temp->Attribute("p"), current.crypt.options.key.options[2]);
					break;
				}
				}
			}
		}

		// crypt_hmac
		xml_temp = xml_nppcrypt->FirstChildElement("crypt_hmac");
		if (xml_temp) {
			crypt::help::getBoolean(xml_temp->Attribute("enabled"), current.crypt.hmac.enable);
			crypt::help::getHash(xml_temp->Attribute("hash"), current.crypt.hmac.hash.algorithm);
			crypt::help::getUnsigned(xml_temp->Attribute("digest-length"), current.crypt.hmac.hash.digest_length);
			crypt::help::getInteger(xml_temp->Attribute("keypreset-id"), current.crypt.hmac.keypreset_id);
		}

		// hash
		xml_temp = xml_nppcrypt->FirstChildElement("hash");
		if (xml_temp) {
			crypt::help::getHash(xml_temp->Attribute("algorithm"), current.hash.algorithm);
			crypt::help::getUnsigned(xml_temp->Attribute("digest-length"), current.hash.digest_length);
			crypt::help::getEncoding(xml_temp->Attribute("encoding"), current.hash.encoding);
			crypt::help::getBoolean(xml_temp->Attribute("usekey"), current.hash.use_key);
		}

		// random
		xml_temp = xml_nppcrypt->FirstChildElement("random");
		if (xml_temp) {
			crypt::help::getRandomRestriction(xml_temp->Attribute("restriction"), current.random.restriction);
			crypt::help::getEncoding(xml_temp->Attribute("encoding"), current.random.encoding);
			crypt::help::getUnsigned(xml_temp->Attribute("length"), current.random.length);
		}

		// convert
		xml_temp = xml_nppcrypt->FirstChildElement("convert");
		if (xml_temp) {
			crypt::help::getEncoding(xml_temp->Attribute("source-enc"), current.convert.from);
			crypt::help::getEncoding(xml_temp->Attribute("target-enc"), current.convert.to);
			crypt::help::getEOL(xml_temp->Attribute("eol"), current.convert.eol);
			crypt::help::getBoolean(xml_temp->Attribute("linebreaks"), current.convert.linebreaks);
			crypt::help::getUnsigned(xml_temp->Attribute("linelength"), current.convert.linelength);
			crypt::help::getBoolean(xml_temp->Attribute("uppercase"), current.convert.uppercase);
		}

		// key_presets
		xml_temp = xml_nppcrypt->FirstChildElement("key_presets");
		if (xml_temp) {
			for (tinyxml2::XMLElement* child = xml_temp->FirstChildElement("key"); child != NULL; child = child->NextSiblingElement("key"))	{
				const char* pLabel = child->Attribute("label");
				const char* pValue = child->Attribute("value");
				size_t label_length = strlen(pLabel);
				if (pLabel && label_length > 0 && label_length <= 30 && pValue && strlen(pValue) == 24) {
					KeyPreset		temp_key;
					std::wstring	temp_str;
					try {
						helper::Windows::utf8_to_wchar(pLabel, -1, temp_str);
					} catch (...) {
						temp_str = TEXT("???");
					}
					CryptoPP::StringSource((const byte*)pValue, 24, true, new CryptoPP::Base64Decoder(new CryptoPP::ArraySink(temp_key.data, 16)));
					size_t i = 0;
					while (i < temp_str.size() && i <= 30) {
						temp_key.label[i] = temp_str[i];
						i++;
					}
					temp_key.label[i] = 0;
					keys.push_back(temp_key);
				}
			}
		}

		/* validate */
		if (current.crypt.hmac.keypreset_id < -1 || current.crypt.hmac.keypreset_id >= (int)keys.size()) {
			current.crypt.hmac.keypreset_id = 0;
		}
		if (current.random.length > crypt::Constants::rand_char_max) {
			current.random.length = 32;
		}
		crypt::help::validate(current.crypt.options, false);
		crypt::help::validate(current.crypt.hmac.hash, false);
		crypt::help::validate(current.hash, false);
		crypt::help::validate(current.convert, false);

		file_loaded = true;
	} catch(...) {
		// LOG???
	}
}

void CPreferences::save(CurrentOptions& current)
{
	std::ofstream fout(filepath, std::ios::out | std::ios::binary);
	try {
		if (!fout.is_open()) {
			throw std::exception();
		}
		fout.exceptions(std::ifstream::failbit | std::ifstream::badbit);
		using namespace crypt;

		char			EOL[3] = { '\r', '\n', 0 };
		std::string		temp_str;

		fout << std::fixed;
		fout << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" << EOL << "<nppcrypt_preferences version=\"" << NPPC_VERSION << "\">" << EOL;

		// files
		try {
			helper::Windows::wchar_to_utf8(files.extension.c_str(), (int)files.extension.size(), temp_str);
		} catch (...) {
			temp_str = NPPC_DEF_FILE_EXT;
		}
		fout << "<files enabled=\"" << help::getString(files.enable) << "\" askonsave=\"" << help::getString(files.askonsave) << "\" extension=\"" << temp_str << "\" />" << EOL;

		// crypt_basic
		fout << "<crypt_basic cipher=\"" << help::getString(current.crypt.options.cipher) << "\" key-length=\"" << current.crypt.options.key.length;
		fout << "\" mode = \"" << help::getString(current.crypt.options.mode) << "\" iv=\"" << help::getString(current.crypt.options.iv) << "\" />" << EOL;
		
		// crypt_encoding
		fout << "<crypt_encoding enc=\"" << help::getString(current.crypt.options.encoding.enc) << "\" eol=\"" << help::getString(current.crypt.options.encoding.eol);
		fout << "\" linebreaks=\"" << help::getString(current.crypt.options.encoding.linebreaks) << "\" line-length=\"" << current.crypt.options.encoding.linelength;
		fout << "\" uppercase=\"" << help::getString(current.crypt.options.encoding.uppercase) << "\" />" << EOL;

		// crypt_key
		fout << "<crypt_key saltbytes=\"" << current.crypt.options.key.salt_bytes << "\" algorithm=\"" << help::getString(current.crypt.options.key.algorithm);
		switch (current.crypt.options.key.algorithm)
		{
		case KeyDerivation::pbkdf2:
		{
			fout << "\" hash=\"" << crypt::help::getString((crypt::Hash)current.crypt.options.key.options[0]) << "\" digest-length=\"" << current.crypt.options.key.options[1] << "\" iterations=\"" << current.crypt.options.key.options[2];
			break;
		}
		case KeyDerivation::bcrypt:
		{
			fout << "\" iterations=\"" << static_cast<size_t>(std::pow(2, current.crypt.options.key.options[0]));
			break;
		}
		case KeyDerivation::scrypt:
		{
			fout << "\" N=\"" << static_cast<size_t>(std::pow(2, current.crypt.options.key.options[0])) << "\" r=\"" << current.crypt.options.key.options[1] << "\" p=\"" << current.crypt.options.key.options[2];
			break;
		}
		}
		fout << "\" />" << EOL;

		// crypt_hmac
		fout << "<crypt_hmac enabled=\"" << help::getString(current.crypt.hmac.enable) << "\" hash=\"" << help::getString(current.crypt.hmac.hash.algorithm);
		fout << "\" digest-length=\"" << current.crypt.hmac.hash.digest_length << "\" keypreset-id=\"" << current.crypt.hmac.keypreset_id << "\" />" << EOL;

		// hash
		fout << "<hash algorithm=\"" << help::getString(current.hash.algorithm) << "\" encoding=\"" << help::getString(current.hash.encoding) << "\" usekey=\"" << help::getString(current.hash.use_key) << "\" />" << EOL;

		// random
		fout << "<random restriction=\"" << help::getString(current.random.restriction) << "\" encoding =\"" << help::getString(current.random.encoding) << "\" length=\"" << current.random.length << "\" />" << EOL;

		// convert
		fout << "<convert source-enc=\"" << help::getString(current.convert.from) << "\" target-enc=\"" << help::getString(current.convert.to);
		fout << "\" eol=\"" << help::getString(current.convert.eol) << "\" linelength=\"" << current.convert.linelength;
		fout << "\" linebreaks=\"" << help::getString(current.convert.linebreaks) << "\" uppercase=\"" << help::getString(current.convert.uppercase) << "\" />" << EOL;

		// key_presets
		fout << "<key_presets>" << EOL;
		for (size_t i = 1; i < keys.size(); i++) {
			try {
				helper::Windows::wchar_to_utf8(keys[i].label, -1, temp_str);
			} catch (...) {
				temp_str = "???";
			}
			fout << "<key label=\"" << temp_str.c_str() << "\" value=\"";
			temp_str.clear();
			CryptoPP::ArraySource(keys[i].data, 16, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(temp_str), false));
			fout << temp_str.c_str() << "\" />" << EOL;
		}
		fout << "</key_presets>" << EOL;
		
		fout << "</nppcrypt_preferences>";

		fout.close();
	} catch (...) {
		if (fout.is_open()) {
			fout.close();
		}
		// LOG??
	}
}

size_t CPreferences::getKeyNum() const
{
	return keys.size();
}

bool CPreferences::addKey(const KeyPreset& key)
{
	if (lstrlen(key.label) <= 0 || keys.size() >= NPPC_HMAC_MAX_KEYS) {
		return false;
	}
	keys.push_back(key);
	return true;
}

bool CPreferences::delKey(size_t i)
{
	if(i < keys.size()) {
		keys.erase(keys.begin()+i);
		return true;
	} else {
		return false;
	}
}

const TCHAR* CPreferences::getKeyLabel(size_t i) const
{
	if (i < keys.size()) {
		return keys[i].label;
	} else {
		return NULL;
	}
}

const unsigned char* CPreferences::getKey(size_t i) const
{
	if (i < keys.size()) {
		return keys[i].data;
	} else {
		return NULL;
	}
}
