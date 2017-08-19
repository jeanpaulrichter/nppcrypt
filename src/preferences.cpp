/*
This file is part of the nppcrypt
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
			if (!fin_size) {
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
		tinyxml2::XMLElement* xml_temp = xml_nppcrypt->FirstChildElement("files");
		if (xml_temp) {
			const char* pTemp = xml_temp->Attribute("enabled");
			if (pTemp) {
				files.enable = (strcmp(pTemp, "true") == 0) ? true : false;
			}
			pTemp = xml_temp->Attribute("askonsave");
			if (pTemp) {
				files.askonsave = (strcmp(pTemp, "true") == 0) ? true : false;
			}
			pTemp = xml_temp->Attribute("extension");
			if (pTemp) {
				helper::Windows::utf8_to_wchar(pTemp, -1, files.extension);
				if (files.extension.size() > NPPC_FILE_EXT_MAXLENGTH) {
					files.extension = files.extension.substr(0, NPPC_FILE_EXT_MAXLENGTH);
				}
			}
		}
		xml_temp = xml_nppcrypt->FirstChildElement("crypt_basic");
		if (xml_temp) {
			const char* pTemp = xml_temp->Attribute("cipher");
			crypt::help::getCipher(pTemp, current.crypt.options.cipher);
			pTemp = xml_temp->Attribute("mode");
			crypt::help::getCipherMode(pTemp, current.crypt.options.mode);
			pTemp = xml_temp->Attribute("iv");
			crypt::help::getIVMode(pTemp, current.crypt.options.iv);
		}
		xml_temp = xml_nppcrypt->FirstChildElement("crypt_encoding");
		if (xml_temp) {
			const char* pTemp = xml_temp->Attribute("enc");
			crypt::help::getEncoding(pTemp, current.crypt.options.encoding.enc);
			pTemp = xml_temp->Attribute("eol");
			crypt::help::getEOL(pTemp, current.crypt.options.encoding.eol);
			pTemp = xml_temp->Attribute("linebreaks");
			if (pTemp) {
				current.crypt.options.encoding.linebreaks = (strcmp(pTemp, "true") == 0) ? true : false;
			}
			pTemp = xml_temp->Attribute("linelength");
			if (pTemp) {
				current.crypt.options.encoding.linelength = (size_t)std::atoi(pTemp);
			}
			pTemp = xml_temp->Attribute("uppercase");
			if (pTemp) {
				current.crypt.options.encoding.uppercase = (strcmp(pTemp, "true") == 0) ? true : false;
			}
		}
		xml_temp = xml_nppcrypt->FirstChildElement("crypt_key");
		if (xml_temp) {
			const char* pTemp = xml_temp->Attribute("saltbytes");
			if (pTemp) {
				current.crypt.options.key.salt_bytes = std::atoi(pTemp);
			}
			pTemp = xml_temp->Attribute("algorithm");
			if (crypt::help::getKeyDerivation(pTemp, current.crypt.options.key.algorithm)) {
				switch (current.crypt.options.key.algorithm) {
				case crypt::KeyDerivation::pbkdf2:
				{
					pTemp = xml_temp->Attribute("hash");
					crypt::Hash thash;
					if (crypt::help::getHash(pTemp, thash)) {
						current.crypt.options.key.options[0] = static_cast<int>(thash);
					}
					pTemp = xml_temp->Attribute("iterations");
					if (pTemp) {
						current.crypt.options.key.options[1] = std::atoi(pTemp);
					}
					break;
				}
				case crypt::KeyDerivation::bcrypt:
				{
					pTemp = xml_temp->Attribute("iterations");
					if (pTemp) {
						int temp_int = std::atoi(pTemp);
						if ((temp_int != 0) && !(temp_int & (temp_int - 1))) {
							current.crypt.options.key.options[0] = static_cast<int>(std::log(temp_int) / std::log(2));
						}
					}
					break;
				}
				case crypt::KeyDerivation::scrypt:
				{
					pTemp = xml_temp->Attribute("N");
					if (pTemp) {
						int temp_int = std::atoi(pTemp);
						if ((temp_int != 0) && !(temp_int & (temp_int - 1))) {
							current.crypt.options.key.options[0] = static_cast<int>(std::log(temp_int) / std::log(2));
						}
					}
					pTemp = xml_temp->Attribute("r");
					if (pTemp) {
						current.crypt.options.key.options[1] = std::atoi(pTemp);
					}
					pTemp = xml_temp->Attribute("p");
					if (pTemp) {
						current.crypt.options.key.options[2] = std::atoi(pTemp);
					}
					break;
				}
				}
			}
		}
		xml_temp = xml_nppcrypt->FirstChildElement("crypt_hmac");
		if (xml_temp) {
			const char* pTemp = xml_temp->Attribute("enabled");
			if (pTemp) {
				current.crypt.hmac.enable = (strcmp(pTemp, "true") == 0) ? true : false;
			}
			pTemp = xml_temp->Attribute("hash");
			crypt::help::getHash(pTemp, current.crypt.hmac.hash);
			pTemp = xml_temp->Attribute("keypreset_id");
			if (pTemp) {
				current.crypt.hmac.keypreset_id = std::atoi(pTemp);
			}
		}
		xml_temp = xml_nppcrypt->FirstChildElement("hash");
		if (xml_temp) {
			const char* pTemp = xml_temp->Attribute("algorithm");
			crypt::help::getHash(pTemp, current.hash.algorithm);
			pTemp = xml_temp->Attribute("encoding");
			crypt::help::getEncoding(pTemp, current.hash.encoding);
			pTemp = xml_temp->Attribute("usekey");
			if (pTemp) {
				current.hash.use_key = (strcmp(pTemp, "true") == 0) ? true : false;
			}
			pTemp = xml_temp->Attribute("keypreset_id");
			if (pTemp) {
				current.hash.keypreset_id = std::atoi(pTemp);
			}
		}
		xml_temp = xml_nppcrypt->FirstChildElement("random");
		if (xml_temp) {
			const char* pTemp = xml_temp->Attribute("mode");
			crypt::help::getRandomMode(pTemp, current.random.mode);
			pTemp = xml_temp->Attribute("length");
			if (pTemp) {
				current.random.length = std::atoi(pTemp);
			}
		}
		xml_temp = xml_nppcrypt->FirstChildElement("convert");
		if (xml_temp) {
			const char* pTemp = xml_temp->Attribute("source_enc");
			crypt::help::getEncoding(pTemp, current.convert.from);
			pTemp = xml_temp->Attribute("target_enc");
			crypt::help::getEncoding(pTemp, current.convert.to);
			pTemp = xml_temp->Attribute("eol");
			crypt::help::getEOL(pTemp, current.convert.eol);
			pTemp = xml_temp->Attribute("linebreaks");
			if (pTemp) {
				current.convert.linebreaks = (strcmp(pTemp, "true") == 0) ? true : false;
			}
			pTemp = xml_temp->Attribute("linelength");
			if (pTemp) {
				current.convert.linelength = std::atoi(pTemp);
			}
			pTemp = xml_temp->Attribute("uppercase");
			if (pTemp) {
				current.convert.uppercase = (strcmp(pTemp, "true") == 0) ? true : false;
			}
		}
		xml_temp = xml_nppcrypt->FirstChildElement("key_presets");
		if (xml_temp) {
			for (tinyxml2::XMLElement* child = xml_temp->FirstChildElement("key"); child != NULL; child = child->NextSiblingElement("key"))	{
				const char* pLabel = child->Attribute("label");
				const char* pValue = child->Attribute("value");
				if (pLabel && strlen(pLabel) > 0 && pValue && strlen(pValue) == 24) {
					KeyPreset		temp_key;
					std::wstring	temp_str;
					helper::Windows::utf8_to_wchar(pLabel, -1, temp_str);
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
		file_loaded = true;
	} catch(...) {
		// do not annoy user with msgbox at startup
	}
	validate(current);
}

void CPreferences::save(CurrentOptions& current)
{
	std::ofstream fout(filepath, std::ios::out | std::ios::binary);
	try {
		if (!fout.is_open()) {
			throw std::exception();
		}
		fout.exceptions(std::ifstream::failbit | std::ifstream::badbit);

		static const char	eol[2] = { '\r', '\n' };
		static const char*	bool_str[2] = { "false", "true" };
		std::string			temp_str;
		fout << std::fixed;
		fout << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" << eol << "<nppcrypt_preferences version=\"" << NPPC_VERSION << "\">" << eol;
		helper::Windows::wchar_to_utf8(files.extension.c_str(), (int)files.extension.size(), temp_str);
		fout << "<files enabled=\"" << bool_str[files.enable] << "\" askonsave=\"" << bool_str[files.askonsave] << "\" extension=\"" << temp_str << "\" />" << eol;
		fout << "<crypt_basic cipher=\"" << crypt::help::getString(current.crypt.options.cipher) << "\" mode=\"" << crypt::help::getString(current.crypt.options.mode) << "\" iv=\"" << crypt::help::getString(current.crypt.options.iv) << "\" />" << eol;
		fout << "<crypt_encoding enc=\"" << crypt::help::getString(current.crypt.options.encoding.enc) << "\" eol=\"" << crypt::help::getString(current.crypt.options.encoding.eol) << "\" linebreaks=\"" << bool_str[current.crypt.options.encoding.linebreaks];
		fout << "\" linelength=\"" << current.crypt.options.encoding.linelength << "\" uppercase=\"" << bool_str[current.crypt.options.encoding.uppercase] << "\" />" << eol;
		fout << "<crypt_key saltbytes=\"" << current.crypt.options.key.salt_bytes << "\" algorithm=\"" << crypt::help::getString(current.crypt.options.key.algorithm);
		switch (current.crypt.options.key.algorithm)
		{
		case crypt::KeyDerivation::pbkdf2:
		{
			fout << "\" hash=\"" << crypt::help::getString((crypt::Hash)current.crypt.options.key.options[0]) << "\" iterations=\"" << current.crypt.options.key.options[1];
			break;
		}
		case crypt::KeyDerivation::bcrypt:
		{
			fout << "\" iterations=\"" << static_cast<size_t>(std::pow(2, current.crypt.options.key.options[0]));
			break;
		}
		case crypt::KeyDerivation::scrypt:
		{
			fout << "\" N=\"" << static_cast<size_t>(std::pow(2, current.crypt.options.key.options[0])) << "\" r=\"" << current.crypt.options.key.options[1] << "\" p=\"" << current.crypt.options.key.options[2];
			break;
		}
		}
		fout << "\" />" << eol;
		fout << "<crypt_hmac enabled=\"" << bool_str[current.crypt.hmac.enable] << "\" hash=\"" << crypt::help::getString(current.crypt.hmac.hash) << "\" keypreset_id=\"" << current.crypt.hmac.keypreset_id << "\" />" << eol;
		fout << "<hash algorithm=\"" << crypt::help::getString(current.hash.algorithm) << "\" encoding=\"" << crypt::help::getString(current.hash.encoding) << "\" usekey=\"" << bool_str[current.hash.use_key] << "\" keypreset_id=\"" << current.hash.keypreset_id << "\" />" << eol;
		fout << "<random mode=\"" << crypt::help::getString(current.random.mode) << "\" length=\"" << current.random.length << "\" />" << eol;
		fout << "<convert source_enc=\"" << crypt::help::getString(current.convert.from) << "\" target_enc=\"" << crypt::help::getString(current.convert.to) << "\" eol=\"" << crypt::help::getString(current.convert.eol) << "\" linelength=\"" << current.convert.linelength;
		fout << "\" linebreaks=\"" << bool_str[current.convert.linebreaks] << "\" uppercase=\"" << bool_str[current.convert.uppercase] << "\" />" << eol;
		fout << "<key_presets>" << eol;
		for (size_t i = 1; i < keys.size(); i++) {
			helper::Windows::wchar_to_utf8(keys[i].label, -1, temp_str);
			fout << "<key label=\"" << temp_str.c_str() << "\" value=\"";
			temp_str.clear();
			CryptoPP::ArraySource(keys[i].data, 16, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(temp_str), false));
			fout << temp_str.c_str() << "\" />" << eol;
		}
		fout << "</key_presets>" << eol << "</nppcrypt_preferences>";

		fout.close();
	} catch (...) {
		if (fout.is_open()) {
			fout.close();
		}
		// no annoying msgboxes at shutdown, log?
	}
}

void CPreferences::validate(CurrentOptions& current)
{
	if (int(current.crypt.options.cipher) < 0 || int(current.crypt.options.cipher) >= int(crypt::Cipher::COUNT)) {
		current.crypt.options.cipher = crypt::Cipher::rijndael256;
	}
	if (int(current.crypt.options.mode) < 0 || int(current.crypt.options.mode) >= int(crypt::Mode::COUNT) || !crypt::help::validCipherMode(current.crypt.options.cipher, current.crypt.options.mode)) {
		current.crypt.options.mode = crypt::Mode::cbc;
	}
	if (int(current.crypt.options.iv) < 0 || int(current.crypt.options.iv) >= int(crypt::IV::COUNT)) {
		current.crypt.options.iv = crypt::IV::random;
	}
	if (int(current.crypt.options.encoding.enc) < 0 || int(current.crypt.options.encoding.enc) >= int(crypt::Encoding::COUNT)) {
		current.crypt.options.encoding.enc = crypt::Encoding::base64;
	}
	if (int(current.crypt.options.encoding.eol) < 0 || int(current.crypt.options.encoding.enc) >= int(crypt::EOL::COUNT)) {
		current.crypt.options.encoding.eol = crypt::EOL::windows;
	}
	if (current.crypt.options.encoding.linelength < 1 || current.crypt.options.encoding.linelength > NPPC_MAX_LINE_LENGTH) {
		current.crypt.options.encoding.linelength = 64;
	}
	if (int(current.crypt.options.key.algorithm) < 0 || int(current.crypt.options.key.algorithm) >= int(crypt::KeyDerivation::COUNT)) {
		current.crypt.options.key.algorithm = crypt::KeyDerivation::scrypt;
	}
	if (current.crypt.options.key.salt_bytes < 0 || current.crypt.options.key.salt_bytes > crypt::Constants::salt_max) {
		current.crypt.options.key.salt_bytes = 16;
	}
	switch (current.crypt.options.key.algorithm)
	{
	case crypt::KeyDerivation::pbkdf2:
	{
		if (current.crypt.options.key.options[0] < 0 || current.crypt.options.key.options[0] >= (int)crypt::Hash::COUNT 
			|| !crypt::help::checkHashProperty((crypt::Hash)current.crypt.options.key.options[0], crypt::HashProperties::hmac_possible)) {
			current.crypt.options.key.options[0]= crypt::Constants::pbkdf2_default_hash;
		}
		if (current.crypt.options.key.options[1] < crypt::Constants::pbkdf2_iter_min || current.crypt.options.key.options[1] > crypt::Constants::pbkdf2_iter_max) {
			current.crypt.options.key.options[1] = crypt::Constants::pbkdf2_iter_default;
		}
		current.crypt.options.key.options[2] = 0;
		break;
	}
	case crypt::KeyDerivation::bcrypt:
	{
		if (current.crypt.options.key.options[0] < crypt::Constants::bcrypt_iter_min || current.crypt.options.key.options[0] > crypt::Constants::bcrypt_iter_max) {
			current.crypt.options.key.options[0]= crypt::Constants::bcrypt_iter_default;
		}
		current.crypt.options.key.options[1] = 0;
		current.crypt.options.key.options[2] = 0;
		break;
	}
	case crypt::KeyDerivation::scrypt:
	{
		if (current.crypt.options.key.options[0] < crypt::Constants::scrypt_N_min || current.crypt.options.key.options[0] > crypt::Constants::scrypt_N_max) {
			current.crypt.options.key.options[0]= crypt::Constants::scrypt_N_default;
		}
		if (current.crypt.options.key.options[1] < crypt::Constants::scrypt_r_min || current.crypt.options.key.options[1] > crypt::Constants::scrypt_r_max) {
			current.crypt.options.key.options[1] = crypt::Constants::scrypt_r_default;
		}
		if (current.crypt.options.key.options[2] < crypt::Constants::scrypt_p_min || current.crypt.options.key.options[2] > crypt::Constants::scrypt_p_max) {
			current.crypt.options.key.options[2] = crypt::Constants::scrypt_p_default;
		}
		break;
	}
	}
	if (int(current.crypt.hmac.hash) < 0 || int(current.crypt.hmac.hash) >= int(crypt::Hash::COUNT) 
		|| !crypt::help::checkHashProperty(current.crypt.hmac.hash, crypt::HashProperties::hmac_possible)) {
		current.crypt.hmac.hash = crypt::Hash::tiger128;
	}
	if (current.crypt.hmac.keypreset_id < -1 || current.crypt.hmac.keypreset_id >= (int)keys.size()) {
		current.crypt.hmac.keypreset_id = 0;
	}

	if (int(current.convert.from) < 0 || int(current.convert.from) >= int(crypt::Encoding::COUNT)) {
		current.convert.from = crypt::Encoding::ascii;
	}
	if (int(current.convert.to) < 0 || int(current.convert.to) >= int(crypt::Encoding::COUNT)) {
		current.convert.to = crypt::Encoding::base64;
	}
	if (int(current.convert.eol) < 0 || int(current.convert.eol) >= int(crypt::EOL::COUNT)) {
		current.convert.eol = crypt::EOL::windows;
	}
	if (current.convert.linelength < 1 || current.convert.linelength > NPPC_MAX_LINE_LENGTH) {
		current.convert.linelength = 64;
	}
	if (int(current.hash.algorithm) < 0 || int(current.hash.algorithm) >= int(crypt::Hash::COUNT)) {
		current.hash.algorithm = crypt::Hash::tiger128;
	}
	if (int(current.hash.encoding) < 0 || int(current.hash.encoding) >= int(crypt::Encoding::COUNT)) {
		current.hash.encoding = crypt::Encoding::base16;
	}
	if (current.hash.keypreset_id < -1 || current.hash.keypreset_id >= (int)keys.size()) {
		current.hash.keypreset_id = 0;
	}

	if (int(current.random.mode) < 0 || int(current.random.mode) >= int(crypt::Random::COUNT)) {
		current.random.mode = crypt::Random::charnum;
	}
	if (current.random.length > crypt::Constants::rand_char_max) {
		current.random.length = 32;
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
