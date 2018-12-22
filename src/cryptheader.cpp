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
#include "crypt_help.h"

inline bool cmpchars(const char* s1, const char* s2, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (s1[i] != s2[i]) {
            return false;
        }
    }
    return true;
}

bool CryptHeaderReader::parse(crypt::Options::Crypt& options, crypt::InitData& initdata, const crypt::byte* in, size_t in_len)
{
    if (in == NULL || in_len == 0) {
        return false;
    }
    encrypted.start = in;
    encrypted.length = in_len;

    if (in_len < 9) {
        return false;
    }
    if (!cmpchars((const char*)in, "<nppcrypt", 9)) {
        return false;
    }

    size_t                  offset = 10;
    size_t                  offset_body;
    tinyxml2::XMLError      xml_err;
    tinyxml2::XMLDocument   xml_doc;
    crypt::Options::Crypt   t_options;

    // find header body start:
    while (offset < in_len - 12 && in[offset] != '>') {
        offset++;
    }
    if (offset >= in_len - 12) {
        throwInvalid(invalid_header);
    }
    offset_body = offset + 1;
    body.start = in + offset_body;

    // find header end:
    while (offset < in_len - 11 && !cmpchars((const char*)in + offset, "</nppcrypt>", 11)) {
        offset++;
    }
    if (offset >= in_len - 11) {
        throwInvalid(invalid_header);
    }
    body.length = offset - offset_body;

    // parse header:
    xml_err = xml_doc.Parse((const char*)in, offset + 11);
    if (xml_err != tinyxml2::XMLError::XML_NO_ERROR) {
        throwInvalid(invalid_header);
    }
    tinyxml2::XMLElement* xml_nppcrypt = xml_doc.FirstChildElement();
    if (!xml_nppcrypt) {
        throwInvalid(invalid_header);
    }

    // version:
    xml_err = xml_nppcrypt->QueryIntAttribute("version", &version);
    if (xml_err != tinyxml2::XMLError::XML_NO_ERROR) {
        throwInvalid(invalid_header_version);
    }
    if (version != NPPC_VERSION) {
        throwInfo(bad_header_version);
    }

    // hmac:
    const char* pHMAC = xml_nppcrypt->Attribute("hmac");
    if (pHMAC) {
        size_t hmac_length = strlen(pHMAC);
        if (hmac_length > 512) {
            throwInvalid(invalid_hmac_data);
        }
        hmac_digest.set(pHMAC, hmac_length, crypt::Encoding::base64);
        if (!crypt::help::getHash(xml_nppcrypt->Attribute("hmac-hash"), hmac.hash.algorithm)) {
            throwInvalid(invalid_hmac_hash);
        }
        hmac.hash.digest_length = hmac_digest.size();
        xml_err = xml_nppcrypt->QueryIntAttribute("hmac-key", &hmac.keypreset_id);
        if (xml_err != tinyxml2::XMLError::XML_NO_ERROR) {
            hmac.keypreset_id = -1;
        }
        hmac.enable = true;
        hmac.hash.use_key = true;
        hmac.hash.encoding = crypt::Encoding::ascii;
    } else {
        hmac.enable = false;
    }

    // encryption:
    tinyxml2::XMLElement* xml_crypt = xml_nppcrypt->FirstChildElement("encryption");
    if (xml_crypt) {
        if (!crypt::help::getCipher(xml_crypt->Attribute("cipher"), t_options.cipher)) {
            throwInvalid(invalid_cipher);
        }
        if (!crypt::help::getUnsigned(xml_crypt->Attribute("key-length"), t_options.key.length)) {
            throwInvalid(keylength_missing);
        }
        if (crypt::help::checkProperty(t_options.cipher, crypt::BLOCK)) {
            if (!crypt::help::getCipherMode(xml_crypt->Attribute("mode"), t_options.mode)) {
                throwInvalid(invalid_mode);
            }
            if ((t_options.mode == crypt::Mode::gcm || t_options.mode == crypt::Mode::ccm || t_options.mode == crypt::Mode::eax) &&
                !crypt::help::getBoolean(xml_crypt->Attribute("aad"), t_options.aad)) {
                throwInvalid(invalid_aad_flag);
            }
        }
        if (!crypt::help::getEncoding(xml_crypt->Attribute("encoding"), t_options.encoding.enc)) {
            throwInvalid(invalid_encoding);
        }
    }

    // key
    tinyxml2::XMLElement* xml_key = xml_nppcrypt->FirstChildElement("key");
    if (xml_key) {
        if (!crypt::help::getKeyDerivation(xml_key->Attribute("algorithm"), t_options.key.algorithm)) {
            throwInvalid(invalid_keyderivation);
        }
        switch (t_options.key.algorithm)
        {
        case crypt::KeyDerivation::pbkdf2:
        {
            crypt::Hash thash;
            if (!crypt::help::getHash(xml_key->Attribute("hash"), thash)) {
                throwInvalid(invalid_pbkdf2);
            }
            t_options.key.options[0] = static_cast<int>(thash);
            if (!crypt::help::getInteger(xml_key->Attribute("digest-length"), t_options.key.options[1])) {
                throwInvalid(invalid_pbkdf2);
            }
            if (!crypt::help::getInteger(xml_key->Attribute("iterations"), t_options.key.options[2])) {
                throwInvalid(invalid_pbkdf2);
            }
            break;
        }
        case crypt::KeyDerivation::bcrypt:
        {
            if (!crypt::help::getInteger(xml_key->Attribute("iterations"), t_options.key.options[0], true)) {
                throwInvalid(invalid_bcrypt);
            }
            break;
        }
        case crypt::KeyDerivation::scrypt:
        {
            if (!crypt::help::getInteger(xml_key->Attribute("N"), t_options.key.options[0], true)) {
                throwInvalid(invalid_scrypt);
            }
            if (!crypt::help::getInteger(xml_key->Attribute("r"), t_options.key.options[1])) {
                throwInvalid(invalid_scrypt);
            }
            if (!crypt::help::getInteger(xml_key->Attribute("p"), t_options.key.options[2])) {
                throwInvalid(invalid_scrypt);
            }
            break;
        }
        }
        const char* pSalt = xml_key->Attribute("salt");
        if (pSalt) {
            size_t t_len = strlen(pSalt);
            if (t_len > 2 * crypt::Constants::salt_max) {
                throwInvalid(invalid_salt);
            }
            initdata.salt.set(pSalt, t_len, crypt::Encoding::base64);
            t_options.key.salt_bytes = initdata.salt.size();
        } else {
            t_options.key.salt_bytes = 0;
        }
    }

    // IV:
    tinyxml2::XMLElement* xml_iv = xml_nppcrypt->FirstChildElement("iv");
    if (xml_iv) {
        const char* pIV = xml_iv->Attribute("value");
        if (!pIV) {
            throwInvalid(invalid_iv);
        }
        size_t iv_len = strlen(pIV);
        if (iv_len > 2048) {
            throwInvalid(invalid_iv);
        }
        initdata.iv.set(pIV, iv_len, crypt::Encoding::base64);
        if (!crypt::help::getIVMode(xml_iv->Attribute("method"), t_options.iv)) {
            throwInvalid(invalid_iv);
        }
    }

    // Tag:
    tinyxml2::XMLElement* xml_tag = xml_nppcrypt->FirstChildElement("tag");
    if (xml_tag) {
        const char* pTag = xml_tag->Attribute("value");
        if (!pTag) {
            throwInvalid(invalid_tag);
        }
        size_t tag_len = strlen(pTag);
        if (tag_len > 2048) {
            throwInvalid(invalid_tag);
        }
        initdata.tag.set(pTag, tag_len, crypt::Encoding::base64);
    }

    // setup encrypted data pointer
    if (in[offset + 11] == '\r' && in[offset + 12] == '\n') {
        encrypted.start = in + offset + 13;
        encrypted.length = in_len - offset - 13;
    } else if (in[offset + 11] == '\n') {
        encrypted.start = in + offset + 12;
        encrypted.length = in_len - offset - 12;
    } else {
        encrypted.start = in + offset + 11;
        encrypted.length = in_len - offset - 11;
    }

    // check EOLs:
    for (size_t i = 1; i < encrypted.length - 1; i++) {
        if (encrypted.start[i] == '\r' && encrypted.start[i + 1] == '\n')   {
            t_options.encoding.linebreaks = true;
            t_options.encoding.linelength = i;
            t_options.encoding.eol = crypt::EOL::windows;
            break;
        } else if (encrypted.start[i] == '\n') {
            t_options.encoding.linebreaks = true;
            t_options.encoding.linelength = i;
            t_options.encoding.eol = crypt::EOL::unix;
            break;
        }
    }
    // check if uppercase or lowercase
    if (t_options.encoding.enc == crypt::Encoding::base16 || t_options.encoding.enc == crypt::Encoding::base32) {
        for (size_t i = 0; i < encrypted.length - 1; i++) {
            if (std::isalpha((int)*(encrypted.start + i))) {
                t_options.encoding.uppercase = (std::isupper((int)*(encrypted.start + i)) == 0) ? false : true;
                break;
            }
        }
    } else {
        t_options.encoding.uppercase = false;
    }

    // validate options
    crypt::help::validate(t_options);
    if (hmac.enable) {
        crypt::help::validate(hmac.hash);
    }

    options.aad = t_options.aad;
    options.cipher = t_options.cipher;
    options.mode = t_options.mode;
    options.key = t_options.key;
    options.encoding = t_options.encoding;
    options.iv = t_options.iv;

    return true;
}

bool CryptHeaderReader::checkHMAC()
{
    if (hmac.enable) {
        std::basic_string<crypt::byte> buf;
        crypt::hash(hmac.hash, buf, { { body.start, body.length },{ encrypted.start, encrypted.length } });
        if (buf.size() != hmac_digest.size()) {
            return false;
        }
        const crypt::byte* pDigest = hmac_digest.BytePtr();
        for (size_t i = 0; i < buf.size(); i++) {
            if (buf[i] != *(pDigest + i)) {
                return false;
            }
        }
        return true;
    } else {
        return false;
    }
}

// ====================================================================================================================================================================

void CryptHeaderWriter::create(const crypt::Options::Crypt& options, const crypt::InitData& initdata, const crypt::byte* data, size_t data_length)
{
    std::ostringstream      out;
    size_t                  body_start;
    size_t                  body_end;
    size_t                  hmac_offset;
    crypt::secure_string    temp_s;

    if (!data || !data_length) {
        throwError(header_write_failed);
    }

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
            throwInvalid(invalid_hmac_hash);
        }
        out << " hmac-hash=\"" << crypt::help::getString(hmac.hash.algorithm) << "\"";
        if (hmac.keypreset_id >= 0) {
            out << " hmac-key=\"" << hmac.keypreset_id << "\"";
        }
        out << " hmac=\"";
        hmac_offset = static_cast<size_t>(out.tellp());
        out << std::string(base64length(hmac_length), ' ') << "\"";
    }
    out << ">";
    body_start = static_cast<size_t>(out.tellp()); 
    out << linebreak;   
    // <encryption>
    out << "<encryption cipher=\"" << crypt::help::getString(options.cipher) << "\" key-length=\"" << options.key.length << "\"";
    if (!crypt::help::checkProperty(options.cipher, crypt::STREAM)) {
        out << " mode=\"" << crypt::help::getString(options.mode) << "\"";
        if (options.mode == crypt::Mode::gcm || options.mode == crypt::Mode::ccm || options.mode == crypt::Mode::eax) {
            out << " aad=\"" << crypt::help::getString(options.aad) << "\"";
        }
    }
    out << " encoding=\"" << crypt::help::getString(options.encoding.enc) << "\" />" << linebreak;
    // <key>
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
    if (options.key.salt_bytes > 0) {
        initdata.salt.get(temp_s, crypt::Encoding::base64);
        out << "salt=\"" << temp_s << "\" ";
    }
    out << "/>" << linebreak;
    //<iv> and <tag>
    bool add_linebreak = false;
    if (initdata.iv.size() > 0) {
        initdata.iv.get(temp_s, crypt::Encoding::base64);
        out << "<iv value=\"" << temp_s << "\" method=\"" << crypt::help::getString(options.iv) << "\" />";
        add_linebreak = true;
    }
    if (initdata.tag.size() > 0) {
        initdata.tag.get(temp_s, crypt::Encoding::base64);
        out << "<tag value=\"" << temp_s << "\" />";
        add_linebreak = true;
    }
    if (add_linebreak) {
        out << linebreak;
    }

    body_end = static_cast<size_t>(out.tellp());
    out << "</nppcrypt>" << linebreak;
    out << std::scientific;

    buffer.assign(out.str());
    body.start = (const crypt::byte*)&buffer[body_start];
    body.length = body_end - body_start;

    if (hmac.enable && hmac_offset > 0) {
        // create hmac hash and insert it into header
        std::basic_string<crypt::byte> buf;
        hmac.hash.encoding = crypt::Encoding::base64;
        crypt::hash(hmac.hash, buf, { { body.start, body.length }, { data, data_length } });
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
