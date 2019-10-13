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
    base32_alphabet.setup(NPPC_BASE32_ALPHABET, NPPC_BASE32_PAD);
    base64_alphabet.setup(NPPC_BASE64_ALPHABET, NPPC_BASE64_PAD);
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
        tinyxml2::XMLError      xml_err;
        tinyxml2::XMLDocument   xml_doc;
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
            nppcrypt::help::getBoolean(xml_files->Attribute("enabled"), files.enable);
            nppcrypt::help::getBoolean(xml_files->Attribute("askonsave"), files.askonsave);
            const char* pExt = xml_files->Attribute("extension");
            if (pExt && strlen(pExt) <= NPPC_FILE_EXT_MAXLENGTH) {
                try {
                    help::windows::utf8_to_wchar(pExt, -1, files.extension);
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
                nppcrypt::help::getBoolean(xml_temp->Attribute("advanced"), advanced);
                current.crypt.modus = advanced ? CryptInfo::Modus::advanced : CryptInfo::Modus::easy;
                parseCryptOptions(xml_temp, current.crypt.options);
                tinyxml2::XMLElement* xml_hmac = xml_temp->FirstChildElement("hmac");
                if (xml_hmac) {
                    nppcrypt::help::getBoolean(xml_hmac->Attribute("enabled"), current.crypt.hmac.enable);
                    nppcrypt::help::getHash(xml_hmac->Attribute("hash"), current.crypt.hmac.hash.algorithm);
                    nppcrypt::help::getUnsigned(xml_hmac->Attribute("digest-length"), current.crypt.hmac.hash.digest_length);
                    nppcrypt::help::getInteger(xml_hmac->Attribute("keypreset-id"), current.crypt.hmac.keypreset_id);
                }
            }
            // hash
            xml_temp = xml_current->FirstChildElement("hash");
            if (xml_temp) {
                nppcrypt::help::getHash(xml_temp->Attribute("algorithm"), current.hash.algorithm);
                nppcrypt::help::getUnsigned(xml_temp->Attribute("digest-length"), current.hash.digest_length);
                nppcrypt::help::getEncoding(xml_temp->Attribute("encoding"), current.hash.encoding);
                nppcrypt::help::getBoolean(xml_temp->Attribute("usekey"), current.hash.use_key);
            }
            // random
            xml_temp = xml_current->FirstChildElement("random");
            if (xml_temp) {
                nppcrypt::help::getRandomRestriction(xml_temp->Attribute("restriction"), current.random.restriction);
                nppcrypt::help::getEncoding(xml_temp->Attribute("encoding"), current.random.encoding);
                nppcrypt::help::getUnsigned(xml_temp->Attribute("length"), current.random.length);
            }
            // convert
            xml_temp = xml_current->FirstChildElement("convert");
            if (xml_temp) {
                nppcrypt::help::getEncoding(xml_temp->Attribute("source-enc"), current.convert.from);
                nppcrypt::help::getEncoding(xml_temp->Attribute("target-enc"), current.convert.to);
                nppcrypt::help::getEOL(xml_temp->Attribute("eol"), current.convert.eol);
                nppcrypt::help::getBoolean(xml_temp->Attribute("linebreaks"), current.convert.linebreaks);
                nppcrypt::help::getUnsigned(xml_temp->Attribute("linelength"), current.convert.linelength);
                nppcrypt::help::getBoolean(xml_temp->Attribute("uppercase"), current.convert.uppercase);
            }
        }
        /* ----- default encryption ----- */
        tinyxml2::XMLElement* xml_defaultenc = xml_nppcrypt->FirstChildElement("default_encryption");
        if (xml_defaultenc) {
            parseCryptOptions(xml_defaultenc, default_crypt);
        }
        /* ----- encoding alphabets ----- */
        tinyxml2::XMLElement* xml_base32 = xml_nppcrypt->FirstChildElement("base32");
        if (xml_base32) {
            nppcrypt::byte padding = 0;
            const char* pPadding = xml_base32->Attribute("padding");
            if (pPadding) {
                padding = (nppcrypt::byte)*pPadding;
            }
            const char* pAlphabet = xml_base32->Attribute("alphabet");
            if (pAlphabet && strlen(pAlphabet) == 32) {
                base32_alphabet.setup(pAlphabet, padding);
            }
        }
        tinyxml2::XMLElement* xml_base64 = xml_nppcrypt->FirstChildElement("base64");
        if (xml_base64) {
            nppcrypt::byte padding = 0;
            const char* pPadding = xml_base64->Attribute("padding");
            if (pPadding) {
                padding = (nppcrypt::byte)*pPadding;
            }
            const char* pAlphabet = xml_base64->Attribute("alphabet");
            if (pAlphabet && strlen(pAlphabet) == 64) {
                base64_alphabet.setup(pAlphabet, padding);
            }
        }
        /* ----- key presets ----- */
        tinyxml2::XMLElement* xml_presets = xml_nppcrypt->FirstChildElement("key_presets");
        if (xml_presets) {
            for (tinyxml2::XMLElement* child = xml_presets->FirstChildElement("key"); child != NULL; child = child->NextSiblingElement("key"))  {
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
                    KeyPreset       key;
                    std::wstring    label;
                    help::windows::utf8_to_wchar(pLabel, -1, label);
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
        if (current.random.length > nppcrypt::Constants::rand_char_max) {
            current.random.length = 32;
        }
        nppcrypt::help::validate(default_crypt, false);
        nppcrypt::help::validate(current.crypt.options, false);
        nppcrypt::help::validate(current.crypt.hmac.hash, false);
        nppcrypt::help::validate(current.hash, false);
        nppcrypt::help::validate(current.convert, false);

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
        using namespace nppcrypt::help;

        std::string eol = "\r\n";
        const nppcrypt::Options::Crypt& crypt = current.crypt.options;
        const CryptHeader::HMAC& hmac = current.crypt.hmac;
        const nppcrypt::Options::Hash& hash = current.hash;
        const RandomOptions& random = current.random;
        const nppcrypt::Options::Convert& convert = current.convert;
        std::string file_extension;
        try {
            help::windows::wchar_to_utf8(files.extension.c_str(), (int)files.extension.size(), file_extension);
        } catch (...) {
            file_extension = NPPC_DEF_FILE_EXT;
        }

        /* ------------------------------ */
        fout << std::fixed;
        fout << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" << eol << "<nppcrypt_preferences version=\"" << NPPC_VERSION << "\">" << eol;
        fout << " <files monitor=\"" << getString(files.enable) << "\" askonsave=\"" << getString(files.askonsave) << "\" extension=\"" << file_extension << "\" />" << eol;
        fout << " <current_options>" << eol;
        fout << "  <encryption advanced=\"" << getString(current.crypt.modus == CryptInfo::Modus::advanced) << "\">" << eol;
        writeCryptOptions(fout, crypt, "   ", eol);
        fout << "   <hmac enabled=\"" << getString(hmac.enable) << "\" hash=\"" << getString(hmac.hash.algorithm) << "\" digest-length=\"" << hmac.hash.digest_length << "\" keypreset-id=\"" << hmac.keypreset_id << "\" />" << eol;
        fout << "  </encryption>" << eol;
        fout << "  <hash algorithm=\"" << getString(hash.algorithm) << "\" encoding=\"" << getString(hash.encoding) << "\" usekey=\"" << getString(hash.use_key) << "\" />" << eol;
        fout << "  <random restriction=\"" << getString(random.restriction) << "\" encoding =\"" << getString(random.encoding) << "\" length=\"" << random.length << "\" />" << eol;
        fout << "  <convert source-enc=\"" << getString(convert.from) << "\" target-enc=\"" << getString(convert.to) << "\" eol=\"" << getString(convert.eol) << "\" linelength=\"" << convert.linelength << "\" linebreaks=\"" << getString(convert.linebreaks) << "\" uppercase=\"" << getString(convert.uppercase) << "\" />" << eol;
        fout << " </current_options>" << eol;
        fout << " <default_encryption>" << eol;
        writeCryptOptions(fout, default_crypt, "  ", eol);
        fout << " </default_encryption>" << eol;
        if (base32_alphabet.getPadding() > 0) {
            fout << " <base32 padding=\"" << (char)base32_alphabet.getPadding() << "\" alphabet=\"" << (const char*)base32_alphabet.c_str() << "\" />" << eol;
        } else {
            fout << " <base32 alphabet=\"" << (const char*)base32_alphabet.c_str() << "\" />" << eol;
        }
        if (base64_alphabet.getPadding() > 0) {
            fout << " <base64 padding=\"" << (char)base64_alphabet.getPadding() << "\" alphabet=\"" << (const char*)base64_alphabet.c_str() << "\" />" << eol;
        } else {
            fout << " <base64 alphabet=\"" << (const char*)base64_alphabet.c_str() << "\" />" << eol;
        }
        fout << " <key_presets>" << eol;
        for (size_t i = 1; i < keys.size(); i++) {
            std::string label, value;
            try {
                help::windows::wchar_to_utf8(keys[i].label, -1, label);
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

void CPreferences::writeCryptOptions(std::ofstream& f, const nppcrypt::Options::Crypt& opt, const std::string& indent, const std::string& eol)
{
    using namespace nppcrypt::help;

    f << indent << "<basic cipher=\"" << getString(opt.cipher) << "\" key-length=\"" << opt.key.length << "\" mode=\"" << getString(opt.mode) << "\" aad=\"" << getString(opt.aad) << "\" iv=\"" << getString(opt.iv) << "\" />" << eol;
    f << indent << "<encoding enc=\"" << getString(opt.encoding.enc) << "\" eol=\"" << getString(opt.encoding.eol) << "\" linebreaks=\"" << getString(opt.encoding.linebreaks) << "\" line-length=\"" << opt.encoding.linelength << "\" uppercase=\"" << getString(opt.encoding.uppercase) << "\" />" << eol;
    f << indent << "<key saltbytes=\"" << opt.key.salt_bytes << "\" algorithm=\"" << getString(opt.key.algorithm);
    switch (opt.key.algorithm)
    {
    case nppcrypt::KeyDerivation::pbkdf2:
    {
        f << "\" hash=\"" << nppcrypt::help::getString((nppcrypt::Hash)opt.key.options[0]) << "\" digest-length=\"" << opt.key.options[1] << "\" iterations=\"" << opt.key.options[2];
        break;
    }
    case nppcrypt::KeyDerivation::bcrypt:
    {
        f << "\" iterations=\"" << static_cast<size_t>(std::pow(2, opt.key.options[0]));
        break;
    }
    case nppcrypt::KeyDerivation::scrypt:
    {
        f << "\" N=\"" << static_cast<size_t>(std::pow(2, opt.key.options[0])) << "\" r=\"" << opt.key.options[1] << "\" p=\"" << opt.key.options[2];
        break;
    }
    }
    f << "\" />" << eol;
}

void CPreferences::parseCryptOptions(tinyxml2::XMLElement* parent, nppcrypt::Options::Crypt& opt)
{
    tinyxml2::XMLElement* xml_temp = parent->FirstChildElement("basic");
    if (xml_temp) {
        nppcrypt::help::getCipher(xml_temp->Attribute("cipher"), opt.cipher);
        nppcrypt::help::getUnsigned(xml_temp->Attribute("key-length"), opt.key.length);
        nppcrypt::help::getCipherMode(xml_temp->Attribute("mode"), opt.mode);
        nppcrypt::help::getBoolean(xml_temp->Attribute("aad"), opt.aad);
        nppcrypt::help::getIVMode(xml_temp->Attribute("iv"), opt.iv);
    }
    xml_temp = parent->FirstChildElement("encoding");
    if (xml_temp) {
        nppcrypt::help::getEncoding(xml_temp->Attribute("enc"), opt.encoding.enc);
        nppcrypt::help::getEOL(xml_temp->Attribute("eol"), opt.encoding.eol);
        nppcrypt::help::getBoolean(xml_temp->Attribute("linebreaks"), opt.encoding.linebreaks);
        nppcrypt::help::getUnsigned(xml_temp->Attribute("linelength"), opt.encoding.linelength);
        nppcrypt::help::getBoolean(xml_temp->Attribute("uppercase"), opt.encoding.uppercase);
    }
    xml_temp = parent->FirstChildElement("key");
    if (xml_temp) {
        nppcrypt::help::getUnsigned(xml_temp->Attribute("saltbytes"), opt.key.salt_bytes);
        if (nppcrypt::help::getKeyDerivation(xml_temp->Attribute("algorithm"), opt.key.algorithm)) {
            switch (opt.key.algorithm) {
            case nppcrypt::KeyDerivation::pbkdf2:
            {
                nppcrypt::Hash thash;
                if (nppcrypt::help::getHash(xml_temp->Attribute("hash"), thash)) {
                    opt.key.options[0] = static_cast<int>(thash);
                }
                nppcrypt::help::getInteger(xml_temp->Attribute("digest-length"), opt.key.options[1]);
                nppcrypt::help::getInteger(xml_temp->Attribute("iterations"), opt.key.options[2]);
                break;
            }
            case nppcrypt::KeyDerivation::bcrypt:
            {
                nppcrypt::help::getInteger(xml_temp->Attribute("iterations"), opt.key.options[0], true);
                break;
            }
            case nppcrypt::KeyDerivation::scrypt:
            {
                nppcrypt::help::getInteger(xml_temp->Attribute("N"), opt.key.options[0], true);
                nppcrypt::help::getInteger(xml_temp->Attribute("r"), opt.key.options[1]);
                nppcrypt::help::getInteger(xml_temp->Attribute("p"), opt.key.options[2]);
                break;
            }
            }
        }
    }
}