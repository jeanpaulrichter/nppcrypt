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
		/* ----- load preferences file ----- */
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
			throwError(preffile_read);
		}
	
		/* ----- parse preferences file ----- */
		tinyxml2::XMLError		xml_err;
		tinyxml2::XMLDocument	xml_doc;
		xml_err = xml_doc.Parse(buffer.c_str(), buffer.size());
		if (xml_err != tinyxml2::XMLError::XML_NO_ERROR) {
			throwError(preffile_parse);
		}
		tinyxml2::XMLElement* xml_nppcrypt = xml_doc.FirstChildElement();
		if (!xml_nppcrypt) {
			throwError(preffile_parse);
		}

		/* ----- files ----- */
		tinyxml2::XMLElement* xml_files = xml_nppcrypt->FirstChildElement("files");
		if (xml_files) {
			crypt::help::getBoolean(xml_files->Attribute("enabled"), files.enable);
			crypt::help::getBoolean(xml_files->Attribute("askonsave"), files.askonsave);
			const char* pExt = xml_files->Attribute("extension");
			if (pExt && strlen(pExt) <= NPPC_FILE_EXT_MAXLENGTH) {
				try {
					helper::Windows::utf8_to_wchar(pExt, -1, files.extension);
				} catch(...) {
					// LOG???
					files.extension = TEXT(NPPC_DEF_FILE_EXT);
				}
			}
		}
		/* ----- current_options ----- */
		tinyxml2::XMLElement* xml_current = xml_nppcrypt->FirstChildElement("current_options");
		if (xml_current) {
			// encryption
			tinyxml2::XMLElement* xml_temp = xml_current->FirstChildElement("encryption");
			if (xml_temp) {
				bool advanced = false;
				crypt::help::getBoolean(xml_temp->Attribute("advanced"), advanced);
				current.crypt.modus = advanced ? CryptInfo::Modus::advanced : CryptInfo::Modus::easy;
				parseCryptOptions(xml_temp, current.crypt.options);
				tinyxml2::XMLElement* xml_hmac = xml_temp->FirstChildElement("hmac");
				if (xml_hmac) {
					crypt::help::getBoolean(xml_hmac->Attribute("enabled"), current.crypt.hmac.enable);
					crypt::help::getHash(xml_hmac->Attribute("hash"), current.crypt.hmac.hash.algorithm);
					crypt::help::getUnsigned(xml_hmac->Attribute("digest-length"), current.crypt.hmac.hash.digest_length);
					crypt::help::getInteger(xml_hmac->Attribute("keypreset-id"), current.crypt.hmac.keypreset_id);
				}
			}
			// hash
			xml_temp = xml_current->FirstChildElement("hash");
			if (xml_temp) {
				crypt::help::getHash(xml_temp->Attribute("algorithm"), current.hash.algorithm);
				crypt::help::getUnsigned(xml_temp->Attribute("digest-length"), current.hash.digest_length);
				crypt::help::getEncoding(xml_temp->Attribute("encoding"), current.hash.encoding);
				crypt::help::getBoolean(xml_temp->Attribute("usekey"), current.hash.use_key);
			}
			// random
			xml_temp = xml_current->FirstChildElement("random");
			if (xml_temp) {
				crypt::help::getRandomRestriction(xml_temp->Attribute("restriction"), current.random.restriction);
				crypt::help::getEncoding(xml_temp->Attribute("encoding"), current.random.encoding);
				crypt::help::getUnsigned(xml_temp->Attribute("length"), current.random.length);
			}
			// convert
			xml_temp = xml_current->FirstChildElement("convert");
			if (xml_temp) {
				crypt::help::getEncoding(xml_temp->Attribute("source-enc"), current.convert.from);
				crypt::help::getEncoding(xml_temp->Attribute("target-enc"), current.convert.to);
				crypt::help::getEOL(xml_temp->Attribute("eol"), current.convert.eol);
				crypt::help::getBoolean(xml_temp->Attribute("linebreaks"), current.convert.linebreaks);
				crypt::help::getUnsigned(xml_temp->Attribute("linelength"), current.convert.linelength);
				crypt::help::getBoolean(xml_temp->Attribute("uppercase"), current.convert.uppercase);
			}
		}
		/* ----- default encryption ----- */
		tinyxml2::XMLElement* xml_defaultenc = xml_nppcrypt->FirstChildElement("default_encryption");
		if (xml_defaultenc) {
			parseCryptOptions(xml_defaultenc, default_crypt);
		}
		/* ----- key presets ----- */
		tinyxml2::XMLElement* xml_presets = xml_nppcrypt->FirstChildElement("key_presets");
		if (xml_presets) {
			for (tinyxml2::XMLElement* child = xml_presets->FirstChildElement("key"); child != NULL; child = child->NextSiblingElement("key"))	{
				try {
					const char* pLabel = child->Attribute("label");
					const char* pValue = child->Attribute("value");
					if (!pLabel || !pValue) {
						throw std::exception();
					}
					size_t label_length = strlen(pLabel);
					if (!label_length || label_length > NPPC_MAX_PRESET_LABELLENGTH || strlen(pValue) != 24) {
						throw std::exception();
					}
					KeyPreset		key;
					std::wstring	label;
					helper::Windows::utf8_to_wchar(pLabel, -1, label);
					CryptoPP::StringSource((const byte*)pValue, 24, true, new CryptoPP::Base64Decoder(new CryptoPP::ArraySink(key.data, 16)));
					size_t i = 0;
					while (i < label.size() && i < NPPC_MAX_PRESET_LABELLENGTH) {
						key.label[i] = label[i];
						i++;
					}
					key.label[i] = 0;
					keys.push_back(key);
				} catch (...) {
					// LOG ???
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
		crypt::help::validate(default_crypt, false);
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

		std::string eol = "\r\n";
		const crypt::Options::Crypt& crypt = current.crypt.options;
		const CryptHeader::HMAC& hmac = current.crypt.hmac;
		const crypt::Options::Hash& hash = current.hash;
		const RandomOptions& random = current.random;
		const crypt::Options::Convert& convert = current.convert;
		std::string	file_extension;
		try {
			helper::Windows::wchar_to_utf8(files.extension.c_str(), (int)files.extension.size(), file_extension);
		} catch (...) {
			file_extension = NPPC_DEF_FILE_EXT;
		}

		/* ------------------------------ */
		fout << std::fixed;
		fout << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" << eol << "<nppcrypt_preferences version=\"" << NPPC_VERSION << "\">" << eol;
		fout << " <files monitor=\"" << help::getString(files.enable) << "\" askonsave=\"" << help::getString(files.askonsave) << "\" extension=\"" << file_extension << "\" />" << eol;
		fout << " <current_options>" << eol;
		fout << "  <encryption advanced=\"" << help::getString(current.crypt.modus == CryptInfo::Modus::advanced) << "\">" << eol;
		writeCryptOptions(fout, crypt, "   ", eol);
		fout << "   <hmac enabled=\"" << help::getString(hmac.enable) << "\" hash=\"" << help::getString(hmac.hash.algorithm) << "\" digest-length=\"" << hmac.hash.digest_length << "\" keypreset-id=\"" << hmac.keypreset_id << "\" />" << eol;
		fout << "  </encryption>" << eol;
		fout << "  <hash algorithm=\"" << help::getString(hash.algorithm) << "\" encoding=\"" << help::getString(hash.encoding) << "\" usekey=\"" << help::getString(hash.use_key) << "\" />" << eol;
		fout << "  <random restriction=\"" << help::getString(random.restriction) << "\" encoding =\"" << help::getString(random.encoding) << "\" length=\"" << random.length << "\" />" << eol;
		fout << "  <convert source-enc=\"" << help::getString(convert.from) << "\" target-enc=\"" << help::getString(convert.to) << "\" eol=\"" << help::getString(convert.eol) << "\" linelength=\"" << convert.linelength << "\" linebreaks=\"" << help::getString(convert.linebreaks) << "\" uppercase=\"" << help::getString(convert.uppercase) << "\" />" << eol;
		fout << " </current_options>" << eol;
		fout << " <default_encryption>" << eol;
		writeCryptOptions(fout, default_crypt, "  ", eol);
		fout << " </default_encryption>" << eol;
		fout << " <key_presets>" << eol;
		for (size_t i = 1; i < keys.size(); i++) {
			std::string label, value;
			try {
				helper::Windows::wchar_to_utf8(keys[i].label, -1, label);
				CryptoPP::ArraySource(keys[i].data, 16, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(value), false));
				fout << "  <key label=\"" << label.c_str() << "\" value=\"" << value.c_str() << "\" />" << eol;
			} catch (...) {
				// LOG??
			}
		}
		fout << " </key_presets>" << eol;		
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

void CPreferences::writeCryptOptions(std::ofstream& f, const crypt::Options::Crypt& opt, const std::string& indent, const std::string& eol)
{
	using namespace crypt;

	f << indent << "<basic cipher=\"" << help::getString(opt.cipher) << "\" key-length=\"" << opt.key.length << "\" mode=\"" << help::getString(opt.mode) << "\" iv=\"" << help::getString(opt.iv) << "\" />" << eol;
	f << indent << "<encoding enc=\"" << help::getString(opt.encoding.enc) << "\" eol=\"" << help::getString(opt.encoding.eol) << "\" linebreaks=\"" << help::getString(opt.encoding.linebreaks) << "\" line-length=\"" << opt.encoding.linelength << "\" uppercase=\"" << help::getString(opt.encoding.uppercase) << "\" />" << eol;
	f << indent << "<key saltbytes=\"" << opt.key.salt_bytes << "\" algorithm=\"" << help::getString(opt.key.algorithm);
	switch (opt.key.algorithm)
	{
	case KeyDerivation::pbkdf2:
	{
		f << "\" hash=\"" << crypt::help::getString((crypt::Hash)opt.key.options[0]) << "\" digest-length=\"" << opt.key.options[1] << "\" iterations=\"" << opt.key.options[2];
		break;
	}
	case KeyDerivation::bcrypt:
	{
		f << "\" iterations=\"" << static_cast<size_t>(std::pow(2, opt.key.options[0]));
		break;
	}
	case KeyDerivation::scrypt:
	{
		f << "\" N=\"" << static_cast<size_t>(std::pow(2, opt.key.options[0])) << "\" r=\"" << opt.key.options[1] << "\" p=\"" << opt.key.options[2];
		break;
	}
	}
	f << "\" />" << eol;
}

void CPreferences::parseCryptOptions(tinyxml2::XMLElement* parent, crypt::Options::Crypt& opt)
{
	tinyxml2::XMLElement* xml_temp = parent->FirstChildElement("basic");
	if (xml_temp) {
		crypt::help::getCipher(xml_temp->Attribute("cipher"), opt.cipher);
		crypt::help::getUnsigned(xml_temp->Attribute("key-length"), opt.key.length);
		crypt::help::getCipherMode(xml_temp->Attribute("mode"), opt.mode);
		crypt::help::getIVMode(xml_temp->Attribute("iv"), opt.iv);
	}
	xml_temp = parent->FirstChildElement("encoding");
	if (xml_temp) {
		crypt::help::getEncoding(xml_temp->Attribute("enc"), opt.encoding.enc);
		crypt::help::getEOL(xml_temp->Attribute("eol"), opt.encoding.eol);
		crypt::help::getBoolean(xml_temp->Attribute("linebreaks"), opt.encoding.linebreaks);
		crypt::help::getUnsigned(xml_temp->Attribute("linelength"), opt.encoding.linelength);
		crypt::help::getBoolean(xml_temp->Attribute("uppercase"), opt.encoding.uppercase);
	}
	xml_temp = parent->FirstChildElement("key");
	if (xml_temp) {
		crypt::help::getUnsigned(xml_temp->Attribute("saltbytes"), opt.key.salt_bytes);
		if (crypt::help::getKeyDerivation(xml_temp->Attribute("algorithm"), opt.key.algorithm)) {
			switch (opt.key.algorithm) {
			case crypt::KeyDerivation::pbkdf2:
			{
				crypt::Hash thash;
				if (crypt::help::getHash(xml_temp->Attribute("hash"), thash)) {
					opt.key.options[0] = static_cast<int>(thash);
				}
				crypt::help::getInteger(xml_temp->Attribute("digest-length"), opt.key.options[1]);
				crypt::help::getInteger(xml_temp->Attribute("iterations"), opt.key.options[2]);
				break;
			}
			case crypt::KeyDerivation::bcrypt:
			{
				crypt::help::getInteger(xml_temp->Attribute("iterations"), opt.key.options[0], true);
				break;
			}
			case crypt::KeyDerivation::scrypt:
			{
				crypt::help::getInteger(xml_temp->Attribute("N"), opt.key.options[0], true);
				crypt::help::getInteger(xml_temp->Attribute("r"), opt.key.options[1]);
				crypt::help::getInteger(xml_temp->Attribute("p"), opt.key.options[2]);
				break;
			}
			}
		}
	}
}