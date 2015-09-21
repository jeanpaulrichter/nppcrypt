#include <sstream>
#include "tinyxml2/tinyxml2.h"
#include "encoding.h"
#include "exception.h"
#include "preferences.h"
#include "header.h"

// ======================================================================================================================================================================

inline bool cmpchars(const char* s1, const char* s2, int len)
{
	for (int i = 0; i < len; i++)
	{
		if (s1[i] != s2[i])
			return false;
	}
	return true;
}

// ======================================================================================================================================================================

DataParser::DataParser(const unsigned char* in, size_t in_len, crypt::Options::Crypt& opt)
	: pData(in), pHeader(NULL), pHeader_c(NULL), pCryptData(NULL), data_len(in_len), header_c_len(0), header_len(0), crypt_data_len(0), hmac_start(0), options(opt), version(NPPCRYPT_VERSION)
{
}

// ======================================================================================================================================================================

bool DataParser::readHeader()
{
	if(pData == NULL)
		throw CExc(CExc::File::header, __LINE__);
	if (data_len < 9)
		return false;
	
	if (!cmpchars((const char*)pData, "<nppcrypt", 9))
	{
		// header-version < 1010
		if (cmpchars((const char*)pData, "nppcrypt", 8))
		{
			parse_old_headers();
			return true;
		}
		else {
			return false;
		}
	}

	size_t					offset = 10;
	size_t					body_start;
	tinyxml2::XMLError		xml_err;
	tinyxml2::XMLDocument	xml_doc;
	crypt::Options::Crypt	t_options;

	// find header body start:
	while (offset < data_len - 11 && pData[offset] != '\n')
		offset++;
	body_start = offset + 1;
	pHeader_c = (const char*)pData + body_start;

	// find header end:
	while (offset < data_len - 11 && !cmpchars((const char*)pData + offset, "</nppcrypt>", 11))
		offset++;
	if (offset > data_len - 12) {
		throw CExc(CExc::File::header, __LINE__, CExc::Code::parse_header);
	}
	header_c_len = offset - body_start;

	// ------ parse header:
	xml_err = xml_doc.Parse((const char*)pData, offset + 11);
	if (xml_err != tinyxml2::XMLError::XML_NO_ERROR)
		throw CExc(CExc::File::header, __LINE__, CExc::Code::parse_header);
	tinyxml2::XMLElement* xml_nppcrypt = xml_doc.FirstChildElement();
	if (!xml_nppcrypt)
		throw CExc(CExc::File::header, __LINE__, CExc::Code::parse_header);

	// ------ check version:
	xml_err = xml_nppcrypt->QueryIntAttribute("version", &version);
	if (xml_err != tinyxml2::XMLError::XML_NO_ERROR)
		throw CExc(CExc::Code::header_version);

	// ------ valid hmac present?
	const char* pHMAC = xml_nppcrypt->Attribute("hmac");
	if (pHMAC) {
		if (strlen(pHMAC) > 256)
			throw CExc(CExc::Code::header_hmac_data);
		s_hmac = std::string(pHMAC);
		const char* pHMAC_hash = xml_nppcrypt->Attribute("hmac-hash");
		if (!crypt::help::getHash(pHMAC_hash, t_options.hmac.hash) || t_options.hmac.hash == crypt::Hash::sha3_256
			|| t_options.hmac.hash == crypt::Hash::sha3_384 || t_options.hmac.hash == crypt::Hash::sha3_512)
		{
			throw CExc(CExc::Code::header_hmac_hash);
		}
		xml_err = xml_nppcrypt->QueryIntAttribute("auth-key", &t_options.hmac.key_id);
		if (xml_err != tinyxml2::XMLError::XML_NO_ERROR)
			t_options.hmac.key_id = -1;
		if (t_options.hmac.key_id >= (int)preferences.getKeyNum() || t_options.hmac.key_id < -1) {
			throw CExc(CExc::Code::header_hmac_key);
		}
		t_options.hmac.enable = true;
	}

	// ------- valid IV or Salt present?
	tinyxml2::XMLElement* xml_random = xml_nppcrypt->FirstChildElement("random");
	t_options.key.salt_bytes = 0;
	if (xml_random) {
		const char* pSalt = xml_random->Attribute("salt");
		if (pSalt) {
			if (strlen(pSalt) > 2 * crypt::Constants::salt_bytes_max)
				throw CExc(CExc::Code::header_salt);
			s_init.salt = std::string(pSalt);
			t_options.key.salt_bytes = Encode::base64_to_bin(s_init.salt.c_str(), s_init.salt.size());
			if (t_options.key.salt_bytes < 1 || t_options.key.salt_bytes > crypt::Constants::salt_bytes_max)
				throw CExc(CExc::Code::header_salt);
		}
		const char* pIV = xml_random->Attribute("iv");
		if (pIV) {
			if (strlen(pIV) > 1024)
				throw CExc(CExc::Code::header_iv);
			s_init.iv = std::string(pIV);
		}
	}

	// ------- valid Cipher information present?
	tinyxml2::XMLElement* xml_crypt = xml_nppcrypt->FirstChildElement("encryption");
	if (xml_crypt) {
		const char* t = xml_crypt->Attribute("cipher");
		if (!crypt::help::getCipher(t, t_options.cipher))
			throw CExc(CExc::Code::header_cipher);
		t = xml_crypt->Attribute("mode");
		if (!crypt::help::getCipherMode(t, t_options.mode))
			throw CExc(CExc::Code::header_mode);
		t = xml_crypt->Attribute("encoding");
		if (!crypt::help::getEncoding(t, t_options.encoding))
			throw CExc(CExc::Code::header_mode);
		if ((t = xml_crypt->Attribute("tag")) != NULL) {
			if (strlen(t) != 24)
				throw CExc(CExc::Code::header_tag);
			s_init.tag = std::string(t);
		}
	}

	// ------- valid key derivation information present?
	tinyxml2::XMLElement* xml_key = xml_nppcrypt->FirstChildElement("key");
	if (xml_key) {
		const char* t = xml_key->Attribute("algorithm");
		if (!crypt::help::getKeyDerivation(t, t_options.key.algorithm))
			throw CExc(CExc::Code::header_keyderi);

		switch (t_options.key.algorithm) {
		case crypt::KeyDerivation::pbkdf2:
		{
			t = xml_key->Attribute("hash");
			crypt::Hash thash;
			if (!crypt::help::getHash(t, thash) || thash == crypt::Hash::sha3_256 || thash == crypt::Hash::sha3_384 || thash == crypt::Hash::sha3_512)
				throw CExc(CExc::Code::header_pbkdf2);
			t_options.key.option1 = static_cast<int>(thash);
			if (!(t = xml_key->Attribute("iterations")))
				throw CExc(CExc::Code::header_pbkdf2);
			t_options.key.option2 = std::atoi(t);
			if (t_options.key.option2 < crypt::Constants::pbkdf2_iter_min || t_options.key.option2 > crypt::Constants::pbkdf2_iter_max)
				throw CExc(CExc::Code::header_pbkdf2);
			break;
		}
		case crypt::KeyDerivation::bcrypt:
			if (!(t = xml_key->Attribute("iterations")))
				throw CExc(CExc::Code::header_bcrypt);
			t_options.key.option1 = std::atoi(t);
			if (!((t_options.key.option1 != 0) && !(t_options.key.option1 & (t_options.key.option1 - 1))))
				throw CExc(CExc::Code::header_bcrypt);
			t_options.key.option1 = static_cast<int>(std::log(t_options.key.option1) / std::log(2));
			if (t_options.key.option1 < crypt::Constants::bcrypt_iter_min || t_options.key.option1 > crypt::Constants::bcrypt_iter_max)
				throw CExc(CExc::Code::header_bcrypt);
			break;
		case crypt::KeyDerivation::scrypt:
			if (!(t = xml_key->Attribute("N")))
				throw CExc(CExc::Code::header_scrypt);
			t_options.key.option1 = std::atoi(t);
			if (!((t_options.key.option1 != 0) && !(t_options.key.option1 & (t_options.key.option1 - 1))))
				throw CExc(CExc::Code::header_scrypt);
			t_options.key.option1 = static_cast<int>(std::log(t_options.key.option1) / std::log(2));
			if (t_options.key.option1 < crypt::Constants::scrypt_N_min || t_options.key.option1 > crypt::Constants::scrypt_N_max)
				throw CExc(CExc::Code::header_scrypt);
			if (!(t = xml_key->Attribute("r")))
				throw CExc(CExc::Code::header_scrypt);
			t_options.key.option2 = std::atoi(t);
			if (t_options.key.option2 < crypt::Constants::scrypt_r_min || t_options.key.option2 > crypt::Constants::scrypt_r_max)
				throw CExc(CExc::Code::header_scrypt);
			if (!(t = xml_key->Attribute("p")))
				throw CExc(CExc::Code::header_scrypt);
			t_options.key.option3 = std::atoi(t);
			if (t_options.key.option3 < crypt::Constants::scrypt_p_min || t_options.key.option3 > crypt::Constants::scrypt_p_max)
				throw CExc(CExc::Code::header_scrypt);
			break;
		}
		t = xml_key->Attribute("generateIV");
		if (t != NULL && strlen(t) == 4 && strcmp(t, "true") == 0) {
			t_options.iv = crypt::IV::keyderivation;
		}
		else {
			if (s_init.iv.size() > 0)
				t_options.iv = crypt::IV::random;
			else
				t_options.iv = crypt::IV::zero;
		}
	}

	options = t_options;
	if (pData[offset + 11] == '\r' && pData[offset + 12] == '\n')
	{
		pCryptData = pData + offset + 13;
		crypt_data_len = data_len - offset - 13;
	}
	else if (pData[offset + 11] == '\n')
	{
		pCryptData = pData + offset + 12;
		crypt_data_len = data_len - offset - 12;
	}
	else
	{
		pCryptData = pData + offset + 11;
		crypt_data_len = data_len - offset - 11;
	}
	pHeader = (const char*)pData;
	header_len = data_len - crypt_data_len;
	return true;
}

// ======================================================================================================================================================================

void DataParser::parse_old_headers()
{
	if (data_len > 16 && pData[8] == 1)
	{
		// -------------------------- 1008/9 ----------------------------------------------------------------------------------------------------------------------------

		crypt::Cipher old_ciphers[] = { crypt::Cipher::blowfish, crypt::Cipher::des, crypt::Cipher::rc2, crypt::Cipher::idea, crypt::Cipher::cast5, crypt::Cipher::aes128,
			crypt::Cipher::aes256, crypt::Cipher::des_ede, crypt::Cipher::des_ede3, crypt::Cipher::desx, crypt::Cipher::rc4 };
		crypt::Mode old_modes[] = { crypt::Mode::cbc, crypt::Mode::ecb, crypt::Mode::cfb, crypt::Mode::ofb, crypt::Mode::ctr };

		if (pData[9] < 0 || pData[9] > 10)
			throw CExc(CExc::File::header, __LINE__, CExc::Code::parse_header);
		if (pData[10] < 0 || pData[10] > 4)
			throw CExc(CExc::File::header, __LINE__, CExc::Code::parse_header);
		options.cipher = old_ciphers[pData[9]];
		options.mode = old_modes[pData[10]];
		options.encoding = (pData[13] == 1) ? crypt::Encoding::base16 : crypt::Encoding::ascii;

		if (pData[12] == 0) {
			options.key.algorithm = crypt::KeyDerivation::pbkdf2;
			options.key.option1 = static_cast<int>(crypt::Hash::md5);
			options.key.option2 = 1000;
		}
		else {
			throw CExc(CExc::Code::nppfile1009);
		}

		// default: no salt
		header_len = 16;
		pCryptData = pData + 16;
		crypt_data_len = data_len - 16;
		options.key.salt_bytes = 0;

		if (options.encoding == crypt::Encoding::ascii) {
			if (data_len > 32 && cmpchars((const char*)pData + 16, "Salted__", 8)) {
				s_init.salt.resize(13);
				s_init.salt[12] = 0;
				Encode::bin_to_base64(pData + 24, 8, &s_init.salt[0], true);
				header_len = 32;
				pCryptData = pData + 32;
				crypt_data_len = data_len - 32;
				options.key.salt_bytes = 8;
			}
		}
		else {
			unsigned char t[8];
			if (data_len > 48 && cmpchars((const char*)pData + 16, "53616C7465645F5F", 16)) {
				Encode::hex_to_bin((const char*)pData + 32, 16, t);
				header_len = 48;
				pCryptData = pData + 48;
				crypt_data_len = data_len - 48;
				options.key.salt_bytes = 8;
			}
			else if (data_len > 64 && cmpchars((const char*)pData + 16, "53 61 6C 74 65 64 5F 5F ", 24)) {
				Encode::hex_to_bin((const char*)pData + 40, 24, t);
				header_len = 64;
				pCryptData = pData + 64;
				crypt_data_len = data_len - 64;
				options.key.salt_bytes = 8;
			}
			if (options.key.salt_bytes == 8) {
				s_init.salt.resize(13);
				s_init.salt[12] = 0;
				Encode::bin_to_base64(t, 8, &s_init.salt[0], true);
			}
		}

		pHeader = (const char*)pData;
		pHeader_c = pHeader;
		header_c_len = header_len;

		options.hmac.enable = false;
		options.iv = crypt::IV::keyderivation;
	}
	else {
		// -------------------------- 1007 ---------------------------------------------------------------------------------------------------------------------------
		throw CExc(CExc::Code::nppfile1007);
	}
}

// ====================================================================================================================================================================

void DataParser::setupHeader()
{
	std::ostringstream	out;
	size_t				body_start;
	size_t				body_end;

	static const char win[] = { '\r', '\n', 0 };
	const char* linebreak;
	if (Encode::Options::Common::eol == Encode::Options::Common::EOL::windows)
		linebreak = win;
	else
		linebreak = &win[1];

	out << "<nppcrypt version=\"" << NPPCRYPT_VERSION << "\"";
	if (options.hmac.enable) {
		if (options.hmac.key_id >= 0)
			out << " auth-key=\"" << options.hmac.key_id << "\"";
		out << " hmac-hash=\"" << crypt::help::getString(options.hmac.hash) << "\" hmac=\"";
		hmac_start = static_cast<size_t>(out.tellp());
		out << std::string(Encode::bin_to_base64(NULL, crypt::getHashLength(options.hmac.hash), NULL, true), ' ') << "\"";
	}
	out << ">" << linebreak;
	body_start = static_cast<size_t>(out.tellp());
	out << "<encryption cipher=\"" << crypt::help::getString(options.cipher) << "\" mode=\"" << crypt::help::getString(options.mode)
		<< "\" encoding=\"" << crypt::help::getString(options.encoding) << "\" ";
	if (s_init.tag.size()) { out << "tag=\"" << s_init.tag << "\" "; }
	out << "/>" << linebreak;
	if ((options.iv == crypt::IV::random && s_init.iv.size()>0) || options.key.salt_bytes > 0) {
		out << "<random ";
		if ((options.iv == crypt::IV::random && s_init.iv.size()>0))
			out << "iv=\"" << s_init.iv << "\" ";
		if (options.key.salt_bytes > 0)
			out << "salt=\"" << s_init.salt << "\" ";
		out << "/>" << linebreak;
	}
	out << "<key algorithm=\"" << crypt::help::getString(options.key.algorithm);
	switch (options.key.algorithm) {
	case crypt::KeyDerivation::pbkdf2:
		out << "\" hash=\"" << crypt::help::getString((crypt::Hash)options.key.option1) << "\" iterations=\"" << options.key.option2 << "\" "; break;
	case crypt::KeyDerivation::bcrypt:
		out << "\" iterations=\"" << std::pow(2, options.key.option1) << "\" "; break;
	case crypt::KeyDerivation::scrypt:
		out << "\" N=\"" << std::pow(2, options.key.option1) << "\" r=\"" << options.key.option2 << "\" p=\"" << options.key.option3 << "\" "; break;
	}
	if (options.iv == crypt::IV::keyderivation)
		out << "generateIV=\"true\" />" << linebreak;
	else
		out << "/>" << linebreak;
	body_end = static_cast<size_t>(out.tellp());
	out << "</nppcrypt>" << linebreak;

	s_header.assign(out.str());
	pHeader_c = &s_header[body_start];
	header_c_len = body_end - body_start;
	pHeader = s_header.c_str();
	header_len = s_header.size();
}

// ====================================================================================================================================================================

void DataParser::updateHMAC(const std::string& hmac)
{
	std::copy(hmac.begin(), hmac.end(), s_header.begin() + hmac_start);
}

bool DataParser::checkHMAC(const std::string& hmac)
{
	return (s_hmac.compare(hmac) == 0);
};

int	DataParser::getVersion()
{
	return version;
};

// ====================================================================================================================================================================

const char*	DataParser::header() { return pHeader; };
const char*	DataParser::header_c() { return pHeader_c; };
const unsigned char* DataParser::data() { return pData; };
const unsigned char* DataParser::crypt_data() { return pCryptData; };

size_t DataParser::header_length() { return header_len; };
size_t DataParser::header_c_length() { return header_c_len; };
size_t DataParser::data_length() { return data_len; };
size_t DataParser::crypt_data_length() { return crypt_data_len; };

crypt::InitStrings&	DataParser::init() { return s_init; };
