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

#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include <sstream>
#include "tinyxml2/tinyxml2.h"
#include "unicode.h"
#include "exception.h"
#include "preferences.h"
#include "cryptheader.h"

inline bool cmpchars(const char* s1, const char* s2, int len)
{
	for (int i = 0; i < len; i++) {
		if (s1[i] != s2[i])
			return false;
	}
	return true;
}

bool CryptHeaderReader::parse(const byte* in, size_t in_len)
{
	if (in == NULL || in_len == 0) {
		throw CExc(CExc::File::cryptheader, __LINE__);
	}
	if (in_len < 9)	{
		pCData = in;
		cdata_len = in_len;
		return false;
	}		
	if (!cmpchars((const char*)in, "<nppcrypt", 9))	{
		if (cmpchars((const char*)in, "nppcrypt", 8)) {
			// header-version < 1010
			parse_old(in, in_len);
			return true;
		} else {
			pCData = in;
			cdata_len = in_len;
			return false;
		}
	}

	size_t					offset = 10;
	size_t					body_start;
	tinyxml2::XMLError		xml_err;
	tinyxml2::XMLDocument	xml_doc;
	crypt::Options::Crypt	t_options;

	t_options.encoding = options.encoding;

	// find header body start:
	while (offset < in_len - 11 && in[offset] != '\n') {
		offset++;
	}
	body_start = offset + 1;
	pContent = (const char*)in + body_start;

	// find header end:
	while (offset < in_len - 11 && !cmpchars((const char*)in + offset, "</nppcrypt>", 11)) {
		offset++;
	}
	if (offset > in_len - 12) {
		throw CExc(CExc::File::cryptheader, __LINE__, CExc::Code::parse_header);
	}
	content_len = offset - body_start;

	// ------ parse header:
	xml_err = xml_doc.Parse((const char*)in, offset + 11);
	if (xml_err != tinyxml2::XMLError::XML_NO_ERROR) {
		throw CExc(CExc::File::cryptheader, __LINE__, CExc::Code::parse_header);
	}
	tinyxml2::XMLElement* xml_nppcrypt = xml_doc.FirstChildElement();
	if (!xml_nppcrypt) {
		throw CExc(CExc::File::cryptheader, __LINE__, CExc::Code::parse_header);
	}
	xml_err = xml_nppcrypt->QueryIntAttribute("version", &version);
	if (xml_err != tinyxml2::XMLError::XML_NO_ERROR) {
		throw CExc(CExc::Code::header_version);
	}
	const char* pHMAC = xml_nppcrypt->Attribute("hmac");
	if (pHMAC) {
		if (strlen(pHMAC) > 256) {
			throw CExc(CExc::Code::header_hmac_data);
		}
		s_hmac = std::string(pHMAC);
		const char* pHMAC_hash = xml_nppcrypt->Attribute("hmac-hash");
		if (!crypt::help::getHash(pHMAC_hash, t_options.hmac.hash) || t_options.hmac.hash == crypt::Hash::sha3_256
			|| t_options.hmac.hash == crypt::Hash::sha3_384 || t_options.hmac.hash == crypt::Hash::sha3_512)
		{
			throw CExc(CExc::Code::header_hmac_hash);
		}
		xml_err = xml_nppcrypt->QueryIntAttribute("auth-key", &t_options.hmac.key_id);
		if (xml_err != tinyxml2::XMLError::XML_NO_ERROR) {
			t_options.hmac.key_id = -1;
		}
		if (t_options.hmac.key_id >= (int)preferences.getKeyNum() || t_options.hmac.key_id < -1) {
			throw CExc(CExc::Code::header_hmac_key);
		}
		t_options.hmac.enable = true;
	}
	tinyxml2::XMLElement* xml_random = xml_nppcrypt->FirstChildElement("random");
	t_options.key.salt_bytes = 0;
	if (xml_random) {
		const char* pSalt = xml_random->Attribute("salt");
		if (pSalt) {
			if (strlen(pSalt) > 2 * crypt::Constants::salt_max) {
				throw CExc(CExc::Code::header_salt);
			}
			s_init.salt = std::string(pSalt);
			try {
				std::string tsalt;
				CryptoPP::StringSource(s_init.salt, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(tsalt)));
				t_options.key.salt_bytes = (int)tsalt.size();
			} catch (CryptoPP::Exception&) {
				throw CExc(CExc::Code::header_salt);
			}
			if (t_options.key.salt_bytes < 1 || t_options.key.salt_bytes > crypt::Constants::salt_max) {
				throw CExc(CExc::Code::header_salt);
			}
		}
		const char* pIV = xml_random->Attribute("iv");
		if (pIV) {
			if (strlen(pIV) > 1024) {
				throw CExc(CExc::Code::header_iv);
			}
			s_init.iv = std::string(pIV);
		}
	}
	tinyxml2::XMLElement* xml_crypt = xml_nppcrypt->FirstChildElement("encryption");
	if (xml_crypt) {
		const char* t = xml_crypt->Attribute("cipher");
		if (!crypt::help::getCipher(t, t_options.cipher)) {
			throw CExc(CExc::Code::header_cipher);
		}
		t = xml_crypt->Attribute("mode");
		if (!crypt::help::getCipherMode(t, t_options.mode)) {
			throw CExc(CExc::Code::header_mode);
		}
		t = xml_crypt->Attribute("encoding");
		if (!crypt::help::getEncoding(t, t_options.encoding.enc)) {
			throw CExc(CExc::Code::header_mode);
		}
		if ((t = xml_crypt->Attribute("tag")) != NULL) {
			if (strlen(t) != 24) {
				throw CExc(CExc::Code::header_tag);
			}
			s_init.tag = std::string(t);
		}
	}
	tinyxml2::XMLElement* xml_key = xml_nppcrypt->FirstChildElement("key");
	if (xml_key) {
		const char* t = xml_key->Attribute("algorithm");
		if (!crypt::help::getKeyDerivation(t, t_options.key.algorithm)) {
			throw CExc(CExc::Code::header_keyderi);
		}
		switch (t_options.key.algorithm)
		{
		case crypt::KeyDerivation::pbkdf2:
		{
			t = xml_key->Attribute("hash");
			crypt::Hash thash;
			if (!crypt::help::getHash(t, thash) || thash == crypt::Hash::sha3_256 || thash == crypt::Hash::sha3_384 || thash == crypt::Hash::sha3_512) {
				throw CExc(CExc::Code::header_pbkdf2);
			}
			t_options.key.option1 = static_cast<int>(thash);
			if (!(t = xml_key->Attribute("iterations"))) {
				throw CExc(CExc::Code::header_pbkdf2);
			}
			t_options.key.option2 = std::atoi(t);
			if (t_options.key.option2 < crypt::Constants::pbkdf2_iter_min || t_options.key.option2 > crypt::Constants::pbkdf2_iter_max) {
				throw CExc(CExc::Code::header_pbkdf2);
			}
			break;
		}
		case crypt::KeyDerivation::bcrypt:
		{
			if (!(t = xml_key->Attribute("iterations"))) {
				throw CExc(CExc::Code::header_bcrypt);
			}
			t_options.key.option1 = std::atoi(t);
			if (!((t_options.key.option1 != 0) && !(t_options.key.option1 & (t_options.key.option1 - 1)))) {
				throw CExc(CExc::Code::header_bcrypt);
			}
			t_options.key.option1 = static_cast<int>(std::log(t_options.key.option1) / std::log(2));
			if (t_options.key.option1 < crypt::Constants::bcrypt_iter_min || t_options.key.option1 > crypt::Constants::bcrypt_iter_max) {
				throw CExc(CExc::Code::header_bcrypt);
			}
			break;
		}
		case crypt::KeyDerivation::scrypt:
		{
			if (!(t = xml_key->Attribute("N"))) {
				throw CExc(CExc::Code::header_scrypt);
			}
			t_options.key.option1 = std::atoi(t);
			if (!((t_options.key.option1 != 0) && !(t_options.key.option1 & (t_options.key.option1 - 1)))) {
				throw CExc(CExc::Code::header_scrypt);
			}
			t_options.key.option1 = static_cast<int>(std::log(t_options.key.option1) / std::log(2));
			if (t_options.key.option1 < crypt::Constants::scrypt_N_min || t_options.key.option1 > crypt::Constants::scrypt_N_max) {
				throw CExc(CExc::Code::header_scrypt);
			}
			if (!(t = xml_key->Attribute("r"))) {
				throw CExc(CExc::Code::header_scrypt);
			}
			t_options.key.option2 = std::atoi(t);
			if (t_options.key.option2 < crypt::Constants::scrypt_r_min || t_options.key.option2 > crypt::Constants::scrypt_r_max) {
				throw CExc(CExc::Code::header_scrypt);
			}
			if (!(t = xml_key->Attribute("p"))) {
				throw CExc(CExc::Code::header_scrypt);
			}
			t_options.key.option3 = std::atoi(t);
			if (t_options.key.option3 < crypt::Constants::scrypt_p_min || t_options.key.option3 > crypt::Constants::scrypt_p_max) {
				throw CExc(CExc::Code::header_scrypt);
			}
			break;
		}
		}
		t = xml_key->Attribute("generateIV");
		if (t != NULL && strlen(t) == 4 && strcmp(t, "true") == 0) {
			t_options.iv = crypt::IV::keyderivation;
		} else {
			if (s_init.iv.size() > 0) {
				t_options.iv = crypt::IV::random;
			} else {
				t_options.iv = crypt::IV::zero;
			}
		}
	}
	options = t_options;
	if (in[offset + 11] == '\r' && in[offset + 12] == '\n') {
		pCData = in + offset + 13;
		cdata_len = in_len - offset - 13;
	} else if (in[offset + 11] == '\n')	{
		pCData = in + offset + 12;
		cdata_len = in_len - offset - 12;
	} else {
		pCData = in + offset + 11;
		cdata_len = in_len - offset - 11;
	}
	// ------ check encoding:
	for (size_t i = 1; i < cdata_len - 1; i++) {
		if (pCData[i] == '\r' && pCData[i + 1] == '\n')	{
			options.encoding.linebreaks = true;
			options.encoding.linelength = (int)i;
			options.encoding.windows = true;
			break;
		} else if (pCData[i] == '\n') {
			options.encoding.linebreaks = true;
			options.encoding.linelength = (int)i;
			options.encoding.windows = false;
			break;
		}
	}
	if (options.encoding.enc == crypt::Encoding::base16 || options.encoding.enc == crypt::Encoding::base32)	{
		for (size_t i = 0; i < cdata_len - 1; i++) {
			if (std::isalpha((int)*pCData + (int)i)) {
				options.encoding.uppercase = (std::isupper((int)*pCData + (int)i) == 0) ? false : true;
				break;
			}
		}
	} else {
		options.encoding.uppercase = false;
	}
	return true;
}

void CryptHeaderReader::parse_old(const byte* in, size_t in_len)
{
	if (in_len > 16 && in[8] == 1) {
		// ### version 1008/9 ###
		crypt::Cipher old_ciphers[] = { crypt::Cipher::blowfish, crypt::Cipher::des, crypt::Cipher::rc2, crypt::Cipher::idea, crypt::Cipher::cast128, crypt::Cipher::rijndael128,
			crypt::Cipher::rijndael256, crypt::Cipher::des_ede, crypt::Cipher::des_ede3, crypt::Cipher::desx, crypt::Cipher::rc4 };
		crypt::Mode old_modes[] = { crypt::Mode::cbc, crypt::Mode::ecb, crypt::Mode::cfb, crypt::Mode::ofb, crypt::Mode::ctr };

		if (in[9] < 0 || in[9] > 10) {
			throw CExc(CExc::File::cryptheader, __LINE__, CExc::Code::parse_header);
		}
		if (in[10] < 0 || in[10] > 4) {
			throw CExc(CExc::File::cryptheader, __LINE__, CExc::Code::parse_header);
		}
		options.cipher = old_ciphers[in[9]];
		options.mode = old_modes[in[10]];
		options.encoding.enc = (in[13] == 1) ? crypt::Encoding::base16 : crypt::Encoding::ascii;

		if (in[12] == 0) {
			options.key.algorithm = crypt::KeyDerivation::pbkdf2;
			options.key.option1 = static_cast<int>(crypt::Hash::md5);
			options.key.option2 = 1000;
		} else {
			throw CExc(CExc::Code::nppfile1009);
		}
		size_t header_len = 16;
		pCData = in + 16;
		cdata_len = in_len - 16;
		options.key.salt_bytes = 0;
		try	{
			if (options.encoding.enc == crypt::Encoding::ascii) {
				if (in_len > 32 && cmpchars((const char*)in + 16, "Salted__", 8)) {
					CryptoPP::StringSource(in + 24, 8, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(s_init.salt), false));
					header_len = 32;
					pCData = in + 32;
					cdata_len = in_len - 32;
					options.key.salt_bytes = 8;
				}
			} else {
				unsigned char t[8];
				if (in_len > 48 && cmpchars((const char*)in + 16, "53616C7465645F5F", 16)) {
					CryptoPP::StringSource(in + 32, 16, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(t, 8)));
					header_len = 48;
					pCData = in + 48;
					cdata_len = in_len - 48;
					options.key.salt_bytes = 8;
				} else if (in_len > 64 && cmpchars((const char*)in + 16, "53 61 6C 74 65 64 5F 5F ", 24)) {
					CryptoPP::StringSource(in + 40, 24, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(t, 8)));
					header_len = 64;
					pCData = in + 64;
					cdata_len = in_len - 64;
					options.key.salt_bytes = 8;
				}
				if (options.key.salt_bytes == 8) {
					CryptoPP::StringSource(t, 8, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(s_init.salt), false));
				}
			}
		} catch (CryptoPP::Exception&) {
			throw CExc(CExc::Code::header_salt);
		}

		pContent = (const char*)in;
		content_len = header_len;
		options.hmac.enable = false;
		options.iv = crypt::IV::keyderivation;
	} else {
		// ### version 1007 ###
		throw CExc(CExc::Code::nppfile1007);
	}
}

bool CryptHeaderReader::checkHMAC(const std::string& hmac)
{
	return (s_hmac.compare(hmac) == 0);
};

// ====================================================================================================================================================================

void CryptHeaderWriter::create()
{
	std::ostringstream	out;
	size_t				body_start;
	size_t				body_end;

	static const char win[] = { '\r', '\n', 0 };
	const char* linebreak;
	if (options.encoding.windows) {
		linebreak = win;
	} else {
		linebreak = &win[1];
	}

	out << "<nppcrypt version=\"" << NPPC_VERSION << "\"";
	if (options.hmac.enable) {
		if (options.hmac.key_id >= 0)
			out << " auth-key=\"" << options.hmac.key_id << "\"";
		out << " hmac-hash=\"" << crypt::help::getString(options.hmac.hash) << "\" hmac=\"";
		hmac_offset = static_cast<size_t>(out.tellp());
		out << std::string(base64length(crypt::getHashLength(options.hmac.hash)), ' ') << "\"";
	}
	out << ">" << linebreak;
	body_start = static_cast<size_t>(out.tellp());
	out << "<encryption cipher=\"" << crypt::help::getString(options.cipher) << "\" mode=\"" << crypt::help::getString(options.mode)
		<< "\" encoding=\"" << crypt::help::getString(options.encoding.enc) << "\" ";
	if (s_init.tag.size()) { out << "tag=\"" << s_init.tag << "\" "; }
	out << "/>" << linebreak;
	if ((options.iv == crypt::IV::random && s_init.iv.size()>0) || options.key.salt_bytes > 0) {
		out << "<random ";
		if ((options.iv == crypt::IV::random && s_init.iv.size() > 0)) {
			out << "iv=\"" << s_init.iv << "\" ";
		}
		if (options.key.salt_bytes > 0) {
			out << "salt=\"" << s_init.salt << "\" ";
		}
		out << "/>" << linebreak;
	}
	out << "<key algorithm=\"" << crypt::help::getString(options.key.algorithm);
	switch (options.key.algorithm)
	{
	case crypt::KeyDerivation::pbkdf2:
	{
		out << "\" hash=\"" << crypt::help::getString((crypt::Hash)options.key.option1) << "\" iterations=\"" << options.key.option2 << "\" ";
		break;
	}
	case crypt::KeyDerivation::bcrypt:
	{
		out << "\" iterations=\"" << std::pow(2, options.key.option1) << "\" "; break;
	}
	case crypt::KeyDerivation::scrypt:
	{
		out << "\" N=\"" << std::pow(2, options.key.option1) << "\" r=\"" << options.key.option2 << "\" p=\"" << options.key.option3 << "\" ";
		break;
	}
	}
	if (options.iv == crypt::IV::keyderivation) {
		out << "generateIV=\"true\" />" << linebreak;
	} else {
		out << "/>" << linebreak;
	}
	body_end = static_cast<size_t>(out.tellp());
	out << "</nppcrypt>" << linebreak;

	s_header.assign(out.str());
	pContent = &s_header[body_start];
	content_len = body_end - body_start;
}

void CryptHeaderWriter::updateHMAC(const std::string& hmac)
{
	std::copy(hmac.begin(), hmac.end(), s_header.begin() + hmac_offset);
}

size_t CryptHeaderWriter::base64length(size_t bin_length, bool linebreaks, size_t line_length, bool windows)
{
	if (bin_length == 0) {
		return 0;
	}
	size_t chars = 4 * (bin_length + 2 - ((bin_length + 2) % 3)) / 3;
	if (linebreaks) {
		if (windows) {
			return chars + (((chars - 1) / line_length + 1) - 1) * 2;
		} else {
			return chars + (((chars - 1) / line_length + 1) - 1);
		}
	} else {
		return chars;
	}
}
