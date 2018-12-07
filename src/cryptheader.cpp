/*
This file is part of nppcrypt
(http://www.github.com/jeanpaulrichter/nppcrypt)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
*/

#include <sstream>
#include "tinyxml2/tinyxml2.h"
#include "cryptheader.h"
#include "exception.h"
//#include "preferences.h"
#include "crypt_help.h"

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
		return false;
	}
	pEncryptedData = in;
	encryptedDataLen = in_len;
	if (in_len < 9)	{
		return false;
	}
	if (!cmpchars((const char*)in, "<nppcrypt", 9))	{
		return false;
	}

	size_t					offset = 10;
	size_t					body_start;
	tinyxml2::XMLError		xml_err;
	tinyxml2::XMLDocument	xml_doc;
	crypt::Options::Crypt	t_options;

	// find header body start:
	while (offset < in_len - 11 && in[offset] != '\n') {
		offset++;
	}
	body_start = offset + 1;
	pBody = in + body_start;

	// find header end:
	while (offset < in_len - 11 && !cmpchars((const char*)in + offset, "</nppcrypt>", 11)) {
		offset++;
	}
	if (offset > in_len - 12) {
		throw CExc(CExc::Code::invalid_header);
	}
	bodyLength = offset - body_start;

	// ------ parse header:
	xml_err = xml_doc.Parse((const char*)in, offset + 11);
	if (xml_err != tinyxml2::XMLError::XML_NO_ERROR) {
		throw CExc(CExc::Code::invalid_header);
	}
	tinyxml2::XMLElement* xml_nppcrypt = xml_doc.FirstChildElement();
	if (!xml_nppcrypt) {
		throw CExc(CExc::Code::invalid_header);
	}
	xml_err = xml_nppcrypt->QueryIntAttribute("version", &version);
	if (xml_err != tinyxml2::XMLError::XML_NO_ERROR) {
		throw CExc(CExc::Code::invalid_header_version);
	}
	if (version != NPPC_VERSION) {
		throw CExc(CExc::Code::bad_version);
	}
	const char* pHMAC = xml_nppcrypt->Attribute("hmac");
	if (pHMAC) {
		size_t hmac_length = strlen(pHMAC);
		if (hmac_length > 512) {
			throw CExc(CExc::Code::invalid_hmac_data);
		}
		hmac_digest.set(pHMAC, hmac_length, crypt::Encoding::base64);
		const char* pHMAC_hash = xml_nppcrypt->Attribute("hmac-hash");
		if (!crypt::help::getHash(pHMAC_hash, hmac.hash.algorithm) || !crypt::help::checkProperty(hmac.hash.algorithm, crypt::HMAC_SUPPORT)) {
			throw CExc(CExc::Code::invalid_hmac_hash);
		}
		hmac.hash.digest_length = hmac_digest.size();
		if (!crypt::help::checkHashDigest(hmac.hash.algorithm, (unsigned int)hmac.hash.digest_length)) {
			throw CExc(CExc::Code::invalid_hmac_data);
		}
		xml_err = xml_nppcrypt->QueryIntAttribute("auth-key", &hmac.keypreset_id);
		if (xml_err != tinyxml2::XMLError::XML_NO_ERROR) {
			hmac.keypreset_id = -1;
		}
		if (hmac.keypreset_id >= 0) {
			//hmac.hash.key.set(preferences.getKey((size_t)hmac.keypreset_id), 16);
		}
		hmac.enable = true;
		hmac.hash.use_key = true;
		hmac.hash.encoding = crypt::Encoding::ascii;
	} else {
		hmac.enable = false;
	}
	tinyxml2::XMLElement* xml_random = xml_nppcrypt->FirstChildElement("random");
	t_options.key.salt_bytes = 0;
	if (xml_random) {
		const char* pSalt = xml_random->Attribute("salt");
		if (pSalt) {
			if (strlen(pSalt) > 2 * crypt::Constants::salt_max) {
				throw CExc(CExc::Code::invalid_salt);
			}
			s_init.salt.set(pSalt, strlen(pSalt), crypt::Encoding::base64);
			t_options.key.salt_bytes = (int)s_init.salt.size();
			if (t_options.key.salt_bytes < 1 || t_options.key.salt_bytes > crypt::Constants::salt_max) {
				throw CExc(CExc::Code::invalid_salt);
			}
		}
		const char* pIV = xml_random->Attribute("iv");
		if (pIV) {
			if (strlen(pIV) > 1024) {
				throw CExc(CExc::Code::invalid_iv);
			}
			s_init.iv.set(pIV, strlen(pIV), crypt::Encoding::base64);
		}
	}
	tinyxml2::XMLElement* xml_crypt = xml_nppcrypt->FirstChildElement("encryption");
	if (xml_crypt) {
		const char* t = xml_crypt->Attribute("cipher");
		if (!crypt::help::getCipher(t, t_options.cipher)) {
			throw CExc(CExc::Code::invalid_cipher);
		}
		if (!(t = xml_crypt->Attribute("key-length"))) {
			throw CExc(CExc::Code::keylength_missing);
		}
		t_options.key.length = (size_t)std::atoi(t);
		if (!crypt::help::checkCipherKeylength(t_options.cipher, t_options.key.length)) {
			throw CExc(CExc::Code::invalid_keylength);
		}
		t = xml_crypt->Attribute("mode");
		if (t) {
			if (!crypt::help::getCipherMode(t, t_options.mode)) {
				throw CExc(CExc::Code::invalid_mode);
			}
			if (!crypt::help::checkCipherMode(t_options.cipher, t_options.mode)) {
				throw CExc(CExc::Code::invalid_mode);
			}
		} else {
			if (!crypt::help::checkProperty(t_options.cipher, crypt::STREAM)) {
				throw CExc(CExc::Code::cipher_mode_missing);
			}
		}
		t = xml_crypt->Attribute("encoding");
		if (!crypt::help::getEncoding(t, t_options.encoding.enc)) {
			throw CExc(CExc::Code::invalid_encoding);
		}
		if ((t = xml_crypt->Attribute("tag")) != NULL) {
			if (strlen(t) != 24) {
				throw CExc(CExc::Code::invalid_tag);
			}
			s_init.tag.set(t, 24, crypt::Encoding::base64);
		}
	}
	tinyxml2::XMLElement* xml_key = xml_nppcrypt->FirstChildElement("key");
	if (xml_key) {
		const char* t = xml_key->Attribute("algorithm");
		if (!crypt::help::getKeyDerivation(t, t_options.key.algorithm)) {
			throw CExc(CExc::Code::invalid_keyderivation);
		}
		switch (t_options.key.algorithm)
		{
		case crypt::KeyDerivation::pbkdf2:
		{
			t = xml_key->Attribute("hash");
			crypt::Hash thash;
			if (!crypt::help::getHash(t, thash) || !crypt::help::checkProperty(thash, crypt::HMAC_SUPPORT)) {
				throw CExc(CExc::Code::invalid_pbkdf2);
			}
			t_options.key.options[0] = static_cast<int>(thash);
			if (!(t = xml_key->Attribute("digest-length"))) {
				throw CExc(CExc::Code::invalid_pbkdf2);
			}
			t_options.key.options[1] = std::atoi(t);
			if (!crypt::help::checkHashDigest(thash, (unsigned int)t_options.key.options[1])) {
				throw CExc(CExc::Code::invalid_pbkdf2);
			}
			if (!(t = xml_key->Attribute("iterations"))) {
				throw CExc(CExc::Code::invalid_pbkdf2);
			}
			t_options.key.options[2] = std::atoi(t);
			if (t_options.key.options[2] < crypt::Constants::pbkdf2_iter_min || t_options.key.options[2] > crypt::Constants::pbkdf2_iter_max) {
				throw CExc(CExc::Code::invalid_pbkdf2);
			}
			break;
		}
		case crypt::KeyDerivation::bcrypt:
		{
			if (!(t = xml_key->Attribute("iterations"))) {
				throw CExc(CExc::Code::invalid_bcrypt);
			}
			t_options.key.options[0] = std::atoi(t);
			if (!((t_options.key.options[0] != 0) && !(t_options.key.options[0] & (t_options.key.options[0] - 1)))) {
				throw CExc(CExc::Code::invalid_bcrypt);
			}
			t_options.key.options[0] = static_cast<int>(std::log(t_options.key.options[0]) / std::log(2));
			if (t_options.key.options[0] < crypt::Constants::bcrypt_iter_min || t_options.key.options[0] > crypt::Constants::bcrypt_iter_max) {
				throw CExc(CExc::Code::invalid_bcrypt);
			}
			break;
		}
		case crypt::KeyDerivation::scrypt:
		{
			if (!(t = xml_key->Attribute("N"))) {
				throw CExc(CExc::Code::invalid_scrypt);
			}
			t_options.key.options[0] = std::atoi(t);
			if (!((t_options.key.options[0] != 0) && !(t_options.key.options[0] & (t_options.key.options[0] - 1)))) {
				throw CExc(CExc::Code::invalid_scrypt);
			}
			t_options.key.options[0] = static_cast<int>(std::log(t_options.key.options[0]) / std::log(2));
			if (t_options.key.options[0] < crypt::Constants::scrypt_N_min || t_options.key.options[0] > crypt::Constants::scrypt_N_max) {
				throw CExc(CExc::Code::invalid_scrypt);
			}
			if (!(t = xml_key->Attribute("r"))) {
				throw CExc(CExc::Code::invalid_scrypt);
			}
			t_options.key.options[1] = std::atoi(t);
			if (t_options.key.options[1] < crypt::Constants::scrypt_r_min || t_options.key.options[1] > crypt::Constants::scrypt_r_max) {
				throw CExc(CExc::Code::invalid_scrypt);
			}
			if (!(t = xml_key->Attribute("p"))) {
				throw CExc(CExc::Code::invalid_scrypt);
			}
			t_options.key.options[2] = std::atoi(t);
			if (t_options.key.options[2] < crypt::Constants::scrypt_p_min || t_options.key.options[2] > crypt::Constants::scrypt_p_max) {
				throw CExc(CExc::Code::invalid_scrypt);
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
				t_options.iv = crypt::IV::custom;
			}
		}
	}

	options.cipher = t_options.cipher;
	options.iv = t_options.iv;
	options.key = t_options.key;
	options.mode = t_options.mode;

	if (in[offset + 11] == '\r' && in[offset + 12] == '\n') {
		pEncryptedData = in + offset + 13;
		encryptedDataLen = in_len - offset - 13;
	} else if (in[offset + 11] == '\n')	{
		pEncryptedData = in + offset + 12;
		encryptedDataLen = in_len - offset - 12;
	} else {
		pEncryptedData = in + offset + 11;
		encryptedDataLen = in_len - offset - 11;
	}
	// ------ check EOLs: (only important in case of nppcrypt files that use this options to reencrypt)
	for (size_t i = 1; i < encryptedDataLen - 1; i++) {
		if (pEncryptedData[i] == '\r' && pEncryptedData[i + 1] == '\n')	{
			options.encoding.linebreaks = true;
			options.encoding.linelength = (int)i;
			options.encoding.eol = crypt::EOL::windows;
			break;
		} else if (pEncryptedData[i] == '\n') {
			options.encoding.linebreaks = true;
			options.encoding.linelength = (int)i;
			options.encoding.eol = crypt::EOL::unix;
			break;
		}
	}
	if (options.encoding.enc == crypt::Encoding::base16 || options.encoding.enc == crypt::Encoding::base32)	{
		for (size_t i = 0; i < encryptedDataLen - 1; i++) {
			if (std::isalpha((int)*pEncryptedData + (int)i)) {
				options.encoding.uppercase = (std::isupper((int)*pEncryptedData + (int)i) == 0) ? false : true;
				break;
			}
		}
	} else {
		options.encoding.uppercase = false;
	}
	return true;
}

bool CryptHeaderReader::checkHMAC()
{
	if (hmac.enable) {
		std::basic_string<byte> buf;
		crypt::hash(hmac.hash, buf, { { pBody, bodyLength },{ pEncryptedData,encryptedDataLen } });
		if (buf.size() != hmac_digest.size()) {
			return false;
		}
		const byte* pDigest = hmac_digest.BytePtr();
		for (size_t i = 0; i < hmac.hash.digest_length; i++) {
			if (buf[i] != *(pDigest + i)) {
				return false;
			}
		}
		return true;
	}
	else {
		return false;
	}
}

// ====================================================================================================================================================================

CryptHeaderWriter::CryptHeaderWriter(const crypt::Options::Crypt& opt, HMAC& hmac_opt, const byte* h_key, size_t h_len) : options(opt), hmac(hmac_opt)
{
}


void CryptHeaderWriter::create(const byte* data, size_t data_length)
{
	std::ostringstream	out;
	size_t				body_start;
	size_t				body_end;
	size_t				hmac_offset;
	crypt::secure_string temp_s;

	static const char win[] = { '\r', '\n', 0 };
	const char* linebreak;
	if (options.encoding.eol == crypt::EOL::windows) {
		linebreak = win;
	} else {
		linebreak = &win[1];
	}
	out << std::fixed;
	out << "<nppcrypt version=\"" << NPPC_VERSION << "\"";
	if (hmac.enable) {
		size_t hmac_length = hmac.hash.digest_length;
		size_t key_length;
		if (!crypt::getHashInfo(hmac.hash.algorithm, hmac_length, key_length)) {
			throw CExc(CExc::Code::invalid_hmac_hash);
		}
		out << " hmac-hash=\"" << crypt::help::getString(hmac.hash.algorithm) << "\"";
		if (hmac.keypreset_id >= 0) {
			out << " auth-key=\"" << hmac.keypreset_id << "\"";
		}
		out << " hmac=\"";
		hmac_offset = static_cast<size_t>(out.tellp());
		out << std::string(base64length(hmac_length), ' ') << "\"";
	}
	out << ">" << linebreak;
	body_start = static_cast<size_t>(out.tellp());
	out << "<encryption cipher=\"" << crypt::help::getString(options.cipher) << "\" key-length=\"" << options.key.length << "\"";
	if (!crypt::help::checkProperty(options.cipher, crypt::STREAM)) {
		out << " mode=\"" << crypt::help::getString(options.mode) << "\"";
	}
	out << " encoding=\"" << crypt::help::getString(options.encoding.enc) << "\" ";
	if (s_init.tag.size()) {
		s_init.tag.get(temp_s, crypt::Encoding::base64);
		out << "tag=\"" << temp_s << "\" ";
	}
	out << "/>" << linebreak;
	if ((options.iv == crypt::IV::random && s_init.iv.size()>0) || options.key.salt_bytes > 0) {
		out << "<random ";
		if ((options.iv == crypt::IV::random || options.iv == crypt::IV::custom) && s_init.iv.size() > 0) {
			s_init.iv.get(temp_s, crypt::Encoding::base64);
			out << "iv=\"" << temp_s << "\" ";
		}
		if (options.key.salt_bytes > 0) {
			s_init.salt.get(temp_s, crypt::Encoding::base64);
			out << "salt=\"" << temp_s << "\" ";
		}
		out << "/>" << linebreak;
	}
	out << "<key algorithm=\"" << crypt::help::getString(options.key.algorithm);
	switch (options.key.algorithm)
	{
	case crypt::KeyDerivation::pbkdf2:
	{
		out << "\" hash=\"" << crypt::help::getString((crypt::Hash)options.key.options[0]) << "\" digest-length=\"" << options.key.options[1] << "\" iterations=\"" << options.key.options[2] << "\" ";
		break;
	}
	case crypt::KeyDerivation::bcrypt:
	{
		out << "\" iterations=\"" << static_cast<size_t>(std::pow(2, options.key.options[0])) << "\" ";
		break;
	}
	case crypt::KeyDerivation::scrypt:
	{
		out << "\" N=\"" << static_cast<size_t>(std::pow(2, options.key.options[0])) << "\" r=\"" << options.key.options[1] << "\" p=\"" << options.key.options[2] << "\" ";
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
	out << std::scientific;

	buffer.assign(out.str());
	pBody = (const byte*)&buffer[body_start];
	bodyLength = body_end - body_start;

	if (hmac.enable && hmac_offset > 0) {
		// create hmac hash and insert it into header
		std::basic_string<byte> buf;
		hmac.hash.encoding = crypt::Encoding::base64;
		crypt::hash(hmac.hash, buf, { { pBody, bodyLength },{ data, data_length } });
		std::string tstring(buf.begin(), buf.end());
		buffer.replace(hmac_offset, tstring.size(), tstring);
	}
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
