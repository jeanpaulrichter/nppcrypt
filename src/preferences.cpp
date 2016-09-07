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


#include "preferences.h"
#include "mdef.h"
#include "unicode.h"
#include "exception.h"
#include <fstream>

CPreferences& preferences = CPreferences::Instance();

CPreferences::CPreferences()
{
	keys.resize(1);
	memcpy(keys[0].data, NPPC_DEF_HMAC_KEY, 16);
	lstrcpy(keys[0].label, TEXT(NPPC_DEF_HMAC_LABEL));
	files.extension = TEXT(NPPC_DEF_FILE_EXT);
	files.askonsave = true;
	files.enable = true;
};

void CPreferences::load(const TCHAR* path, CurrentOptions& current)
{
	if (!path) {
		throw CExc(CExc::Code::preffile_missing);
	}

	#ifdef UNICODE
	unicode::wchar_to_utf8(path, -1, filepath);
	#else
	filepath.assign(path);
	#endif

	std::ifstream f(filepath, std::ios::in | std::ios::binary);
	
	try {
		f.exceptions(std::ifstream::failbit | std::ifstream::badbit);
		if (!f.is_open()) {
			throw CExc(CExc::Code::preffile_missing);
		}
		char theader[22];
		f.read(theader, 21);
		theader[21] = 0;
		if (strcmp(NPPC_PREFFILE_HEADER_1010, theader) == 0) {
			load_1010(f, current);
		} else {
			if (strcmp(NPPC_PREFFILE_HEADER, theader) != 0) {
				throw CExc(CExc::File::preferences, __LINE__, CExc::Code::preffile_corrupted);
			}

			size_t		t_size_t;
			std::string t_string;
			KeyPreset	t_key;

			f.read(reinterpret_cast<char*>(&files.enable), sizeof(bool));
			f.read(reinterpret_cast<char*>(&files.askonsave), sizeof(bool));
			f.read(reinterpret_cast<char*>(&t_size_t), sizeof(size_t));
			if (t_size_t > 255) {
				throw CExc(CExc::File::preferences, __LINE__, CExc::Code::preffile_corrupted);
			}
			t_string.resize(t_size_t);
			f.read(reinterpret_cast<char*>(&t_string[0]), t_size_t);
			unicode::utf8_to_wchar(t_string.c_str(), (int)t_string.size(), files.extension);

			f.read(reinterpret_cast<char*>(&current.crypt.cipher), sizeof(crypt::Cipher));
			f.read(reinterpret_cast<char*>(&current.crypt.mode), sizeof(crypt::Mode));
			f.read(reinterpret_cast<char*>(&current.crypt.encoding), sizeof(crypt::Options::Crypt::Encoding));
			f.read(reinterpret_cast<char*>(&current.crypt.iv), sizeof(crypt::IV));
			f.read(reinterpret_cast<char*>(&current.crypt.key), sizeof(crypt::Options::Crypt::Key));
			f.read(reinterpret_cast<char*>(&current.crypt.hmac.enable), sizeof(bool));
			f.read(reinterpret_cast<char*>(&current.crypt.hmac.hash), sizeof(crypt::Hash));
			f.read(reinterpret_cast<char*>(&current.crypt.hmac.key_id), sizeof(int));
			f.read(reinterpret_cast<char*>(&t_size_t), sizeof(size_t));
			if (t_size_t > 255) {
				throw CExc(CExc::File::preferences, __LINE__, CExc::Code::preffile_corrupted);
			}
			current.crypt.hmac.key_input.resize(t_size_t);
			f.read(reinterpret_cast<char*>(&current.crypt.hmac.key_input[0]), t_size_t);

			f.read(reinterpret_cast<char*>(&current.hash.algorithm), sizeof(crypt::Hash));
			f.read(reinterpret_cast<char*>(&current.hash.encoding), sizeof(crypt::Encoding));
			f.read(reinterpret_cast<char*>(&current.hash.use_key), sizeof(bool));
			f.read(reinterpret_cast<char*>(&t_size_t), sizeof(size_t));
			if (t_size_t > 255) {
				throw CExc(CExc::File::preferences, __LINE__, CExc::Code::preffile_corrupted);
			}
			current.hash.key_input.resize(t_size_t);
			f.read(&current.hash.key_input[0], t_size_t);

			f.read(reinterpret_cast<char*>(&current.random), sizeof(crypt::Options::Random));
			f.read(reinterpret_cast<char*>(&current.convert), sizeof(crypt::Options::Convert));

			f.read(reinterpret_cast<char*>(&t_size_t), sizeof(size_t));
			if (t_size_t > NPPC_HMAC_MAX_KEYS) {
				throw CExc(CExc::File::preferences, __LINE__, CExc::Code::preffile_corrupted);
			}
			keys.reserve(t_size_t);
			for (size_t i = 0; i < t_size_t; i++) {
				f.read(reinterpret_cast<char*>(&t_key), sizeof(KeyPreset));
				t_key.label[30] = 0;
				keys.push_back(t_key);
			}
		}
	} catch(CExc& exc) {
		if (f.is_open()) {
			f.close();
		}
		throw exc;
	} catch(...) {
		if (f.is_open()) {
			f.close();
		}
		throw CExc(CExc::File::preferences, __LINE__, CExc::Code::preffile_corrupted);
	}
	f.close();
	validate(current);
}

void CPreferences::save(CurrentOptions& current)
{
	/* no human readable config-file, because its easier and faster this way and i don't think it matters */

	std::ofstream f(filepath.c_str(), std::ios::out|std::ios::binary);
	try {
		if (!f.is_open()) {
			throw CExc(CExc::Code::preffile_missing);
		}
		f.write(NPPC_PREFFILE_HEADER, NPPC_PREFFILE_HEADER_LEN);

		size_t		ts;
		std::string t_string;

		f.write(reinterpret_cast<char*>(&files.enable), sizeof(bool));
		f.write(reinterpret_cast<char*>(&files.askonsave), sizeof(bool));
		unicode::wchar_to_utf8(files.extension.c_str(), (int)files.extension.size(), t_string);
		ts = t_string.size();
		f.write(reinterpret_cast<char*>(&ts), sizeof(size_t));
		f.write(reinterpret_cast<char*>(&t_string[0]), ts);

		f.write(reinterpret_cast<char*>(&current.crypt.cipher), sizeof(crypt::Cipher));
		f.write(reinterpret_cast<char*>(&current.crypt.mode), sizeof(crypt::Mode));
		f.write(reinterpret_cast<char*>(&current.crypt.encoding), sizeof(crypt::Options::Crypt::Encoding));
		f.write(reinterpret_cast<char*>(&current.crypt.iv), sizeof(crypt::IV));
		f.write(reinterpret_cast<char*>(&current.crypt.key), sizeof(crypt::Options::Crypt::Key));
		f.write(reinterpret_cast<char*>(&current.crypt.hmac.enable), sizeof(bool));
		f.write(reinterpret_cast<char*>(&current.crypt.hmac.hash), sizeof(crypt::Hash));
		f.write(reinterpret_cast<char*>(&current.crypt.hmac.key_id), sizeof(int));
		ts = current.crypt.hmac.key_input.size();
		f.write(reinterpret_cast<char*>(&ts), sizeof(size_t));
		f.write(reinterpret_cast<char*>(&current.crypt.hmac.key_input[0]), ts);

		f.write(reinterpret_cast<char*>(&current.hash.algorithm), sizeof(crypt::Hash));
		f.write(reinterpret_cast<char*>(&current.hash.encoding), sizeof(crypt::Encoding));
		f.write(reinterpret_cast<char*>(&current.hash.use_key), sizeof(bool));
		ts = current.hash.key_input.size();
		f.write(reinterpret_cast<char*>(&ts), sizeof(size_t));
		f.write(&current.hash.key_input[0], ts);

		f.write(reinterpret_cast<char*>(&current.random), sizeof(crypt::Options::Random));
		f.write(reinterpret_cast<char*>(&current.convert), sizeof(crypt::Options::Convert));

		ts = keys.size() - 1;
		f.write(reinterpret_cast<char*>(&ts), sizeof(size_t));
		for(size_t i=1; i<keys.size(); i++) {
			f.write(reinterpret_cast<char*>(&keys[i]), sizeof(KeyPreset));
		}
	} catch (CExc& exc) {
		if (f.is_open()) {
			f.close();
		}
		throw exc;
	} catch (...) {
		if (f.is_open()) {
			f.close();
		}
		throw CExc(CExc::File::preferences, __LINE__, CExc::Code::preffile_corrupted);
	}
	f.close();
}

void CPreferences::load_1010(std::ifstream& f, CurrentOptions& current)
{
	bool			t_bool;
	size_t			t_size_t;
	std::string		t_string;
	KeyPreset		t_key;

	f.read(reinterpret_cast<char*>(&current.crypt.encoding.windows), sizeof(bool));
	f.read(reinterpret_cast<char*>(&t_bool), sizeof(bool)); // Base16::spaces
	f.read(reinterpret_cast<char*>(&t_bool), sizeof(bool));
	current.crypt.encoding.uppercase = !t_bool;
	f.read(reinterpret_cast<char*>(&current.crypt.encoding.linelength), sizeof(size_t));
	f.read(reinterpret_cast<char*>(&t_size_t), sizeof(size_t)); // Base64::cpl

	f.read(reinterpret_cast<char*>(&files.enable), sizeof(bool));
	f.read(reinterpret_cast<char*>(&files.askonsave), sizeof(bool));
	f.read(reinterpret_cast<char*>(&t_size_t), sizeof(size_t));
	if (t_size_t > 255) {
		throw CExc(CExc::File::preferences, __LINE__, CExc::Code::preffile_corrupted);
	}
	t_string.resize(t_size_t);
	f.read(reinterpret_cast<char*>(&t_string[0]), t_size_t);
	unicode::utf8_to_wchar(t_string.c_str(), (int)t_string.size(), files.extension);

	f.read(reinterpret_cast<char*>(&current.crypt.cipher), sizeof(crypt::Cipher));
	f.read(reinterpret_cast<char*>(&current.crypt.mode), sizeof(crypt::Mode));
	f.read(reinterpret_cast<char*>(&current.crypt.encoding.enc), sizeof(crypt::Encoding));
	f.read(reinterpret_cast<char*>(&current.crypt.iv), sizeof(crypt::IV));
	f.read(reinterpret_cast<char*>(&current.crypt.key.algorithm), sizeof(crypt::KeyDerivation));
	f.read(reinterpret_cast<char*>(&current.crypt.key.salt_bytes), sizeof(int));
	f.read(reinterpret_cast<char*>(&current.crypt.key.option1), sizeof(int));
	f.read(reinterpret_cast<char*>(&current.crypt.key.option2), sizeof(int));
	f.read(reinterpret_cast<char*>(&current.crypt.key.option3), sizeof(int));

	f.read(reinterpret_cast<char*>(&current.crypt.hmac.enable), sizeof(bool));
	f.read(reinterpret_cast<char*>(&current.crypt.hmac.hash), sizeof(crypt::Hash));
	f.read(reinterpret_cast<char*>(&current.crypt.hmac.key_id), sizeof(int));

	f.read(reinterpret_cast<char*>(&current.hash.algorithm), sizeof(crypt::Hash));
	f.read(reinterpret_cast<char*>(&current.hash.encoding), sizeof(crypt::Encoding));
	f.read(reinterpret_cast<char*>(&current.hash.use_key), sizeof(bool));
	f.read(reinterpret_cast<char*>(&t_size_t), sizeof(size_t));
	if (t_size_t > NPPC_HMAC_INPUT_MAX) {
		throw CExc(CExc::File::preferences, __LINE__, CExc::Code::preffile_corrupted);
	}
	current.hash.key_input.resize(t_size_t);
	f.read(&current.hash.key_input[0], t_size_t);

	f.read(reinterpret_cast<char*>(&current.random.mode), sizeof(crypt::Random));
	f.read(reinterpret_cast<char*>(&current.random.length), sizeof(size_t));

	f.read(reinterpret_cast<char*>(&t_size_t), sizeof(size_t));
	if (t_size_t > NPPC_HMAC_MAX_KEYS) {
		throw CExc(CExc::File::preferences, __LINE__, CExc::Code::preffile_corrupted);
	}
	keys.reserve(t_size_t);
	for (size_t i = 0; i<t_size_t; i++) {
		f.read(reinterpret_cast<char*>(&t_key), sizeof(KeyPreset));
		t_key.label[30] = 0;
		keys.push_back(t_key);
	}
}

void CPreferences::validate(CurrentOptions& current)
{
	if (int(current.crypt.cipher) < 0 || int(current.crypt.cipher) >= int(crypt::Cipher::COUNT)) {
		current.crypt.cipher = crypt::Cipher::rijndael256;
	}
	if (int(current.crypt.mode) < 0 || int(current.crypt.mode) >= int(crypt::Mode::COUNT) || !crypt::help::validCipherMode(current.crypt.cipher, current.crypt.mode)) {
		current.crypt.mode = crypt::Mode::cbc;
	}
	if (int(current.crypt.iv) < 0 || int(current.crypt.iv) >= int(crypt::IV::COUNT)) {
		current.crypt.iv = crypt::IV::random;
	}
	if (int(current.crypt.encoding.enc) < 0 || int(current.crypt.encoding.enc) >= int(crypt::Encoding::COUNT)) {
		current.crypt.encoding.enc = crypt::Encoding::base64;
	}
	if (current.crypt.encoding.linelength < 1 || current.crypt.encoding.linelength > NPPC_MAX_LINE_LENGTH) {
		current.crypt.encoding.linelength = 64;
	}
	if (int(current.crypt.key.algorithm) < 0 || int(current.crypt.key.algorithm) >= int(crypt::KeyDerivation::COUNT)) {
		current.crypt.key.algorithm = crypt::KeyDerivation::scrypt;
	}
	if (current.crypt.key.salt_bytes < 0 || current.crypt.key.salt_bytes > crypt::Constants::salt_max) {
		current.crypt.key.salt_bytes = 16;
	}
	switch (current.crypt.key.algorithm)
	{
	case crypt::KeyDerivation::pbkdf2:
	{
		if (current.crypt.key.option1 < 0 || current.crypt.key.option1 >= static_cast<int>(crypt::Hash::sha3_256)) {
			current.crypt.key.option1 = crypt::Constants::pbkdf2_default_hash;
		}
		if (current.crypt.key.option2 < crypt::Constants::pbkdf2_iter_min || current.crypt.key.option2 > crypt::Constants::pbkdf2_iter_max) {
			current.crypt.key.option2 = crypt::Constants::pbkdf2_iter_default;
		}
		current.crypt.key.option3 = 0;
		break;
	}
	case crypt::KeyDerivation::bcrypt:
	{
		if (current.crypt.key.option1 < crypt::Constants::bcrypt_iter_min || current.crypt.key.option1 > crypt::Constants::bcrypt_iter_max) {
			current.crypt.key.option1 = crypt::Constants::bcrypt_iter_default;
		}
		current.crypt.key.option2 = 0;
		current.crypt.key.option3 = 0;
		break;
	}
	case crypt::KeyDerivation::scrypt:
	{
		if (current.crypt.key.option1 < crypt::Constants::scrypt_N_min || current.crypt.key.option1 > crypt::Constants::scrypt_N_max) {
			current.crypt.key.option1 = crypt::Constants::scrypt_N_default;
		}
		if (current.crypt.key.option2 < crypt::Constants::scrypt_r_min || current.crypt.key.option2 > crypt::Constants::scrypt_r_max) {
			current.crypt.key.option2 = crypt::Constants::scrypt_r_default;
		}
		if (current.crypt.key.option3 < crypt::Constants::scrypt_p_min || current.crypt.key.option3 > crypt::Constants::scrypt_p_max) {
			current.crypt.key.option3 = crypt::Constants::scrypt_p_default;
		}
		break;
	}
	}
	if (int(current.crypt.hmac.hash) < 0 || int(current.crypt.hmac.hash) >= int(crypt::Hash::COUNT)) {
		current.crypt.hmac.hash = crypt::Hash::tiger;
	}
	if (current.crypt.hmac.key_id < -1 || current.crypt.hmac.key_id >= (int)keys.size()) {
		current.crypt.hmac.key_id = 0;
	}

	if (int(current.convert.from) < 0 || int(current.convert.from) >= int(crypt::Encoding::COUNT)) {
		current.convert.from = crypt::Encoding::ascii;
	}
	if (int(current.convert.to) < 0 || int(current.convert.to) >= int(crypt::Encoding::COUNT)) {
		current.convert.to = crypt::Encoding::base64;
	}
	if (current.convert.linelength < 1 || current.convert.linelength > NPPC_MAX_LINE_LENGTH) {
		current.convert.linelength = 64;
	}
	if (int(current.hash.algorithm) < 0 || int(current.hash.algorithm) >= int(crypt::Hash::COUNT)) {
		current.hash.algorithm = crypt::Hash::tiger;
	}
	if (int(current.hash.encoding) < 0 || int(current.hash.encoding) >= int(crypt::Encoding::COUNT)) {
		current.hash.encoding = crypt::Encoding::base16;
	}
	if (current.hash.key_id < -1 || current.hash.key_id >= (int)keys.size()) {
		current.hash.key_id = 0;
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
