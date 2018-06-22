/*
This file is part of the nppcrypt
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

#include <string>
#include <algorithm>
#include <iostream>
#include <algorithm>
#include <fstream>
#include <array>
#include <vector>
#include <sys/stat.h>
#include <exception>
#include <codecvt>
#include <memory>
#include "cli11/CLI11.hpp"
#include "crypt.h"
#include "crypt_help.h"
#include "cryptheader.h"
#include "exception.h"
#include "cryptopp/base64.h"  
#include "clihelp.h"

enum class BOM : unsigned { utf8, utf16be, utf16le, utf32be, utf32le, none };
static const std::array<std::array<byte, 5>, 5> BOMbytes = 
{ { /* first byte = length of BOM */
	{ 3, 239, 187, 191, 0 },	/* utf8 */
	{ 2, 254, 255, 0, 0 },		/* utf16 big-endian */
	{ 2, 255, 254, 0, 0 },		/* utf16 little-endian*/
	{ 4, 0, 0, 254, 255 },		/* utf32 big-endian */
	{ 4, 255, 254, 0, 0 }		/* utf32 little-endian */
} };

enum class Action : unsigned
{
	encrypt, decrypt, hash
};

struct Arguments
{
	std::string	action;
	std::string input;
	std::string output;
	std::string hash;
	std::string password;
	std::string cipher;
	std::string mode;
	std::string encoding;
	std::string keyderivation;
	std::string tag;
	std::string iv;
	std::string salt;
	std::string hmac;
	std::string hmac_key;
};

struct CLIOptions
{
	CLI::Option* input;
	CLI::Option* output;
	CLI::Option* hash;
	CLI::Option* password;
	CLI::Option* cipher;
	CLI::Option* mode;
	CLI::Option* encoding;
	CLI::Option* keyderivation;
	CLI::Option* tag;
	CLI::Option* iv;
	CLI::Option* salt;
	CLI::Option* hmac;
	CLI::Option* hmac_key;
	CLI::Option* action;
	CLI::Option* noheader;
	CLI::Option* silent;
	CLI::Option* nointeraction;
};

inline bool file_exists(const std::string& name)
{
	struct stat buffer;
	return (stat(name.c_str(), &buffer) == 0);
}

bool readFile(const std::string& path, std::basic_string<byte>& data)
{
	std::ifstream fin(path, std::ios::in | std::ios::binary);
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
		data.resize(fin_size);
		fin.read(reinterpret_cast<char*>(&data[0]), fin_size);
		fin.close();
		return true;
	} catch (...) {
		if (fin.is_open()) {
			fin.close();
		}
		return false;
	}
}

// write data to output file with or without header & BOM
bool writeFile(const std::string& path, BOM bom, const byte* data, size_t length, const char* header = 0, size_t header_length = 0)
{
	std::ofstream fout(path, std::ios::out | std::ios::binary);
	try {
		if (!fout.is_open()) {
			throw std::exception();
		}
		fout.exceptions(std::ifstream::failbit | std::ifstream::badbit);
		if (bom != BOM::none) {
			fout.write((const char*)&BOMbytes[static_cast<unsigned>(bom)][1], BOMbytes[static_cast<unsigned>(bom)][0]);
		}
		if (header != 0 && header_length != 0) {
			fout.write(header, header_length);
		}
		fout.write((const char*)data, length);
		fout.close();
		return true;
	} catch (...) {
		if (fout.is_open()) {
			fout.close();
		}
		return false;
	}
}

BOM getBOM(const byte* input, size_t length) {
	BOM ret = BOM::none;

	for (size_t i = 0; i < BOMbytes.size(); i++) {
		size_t c = 0;
		while (c < BOMbytes[i][0] + 1 && c < length && BOMbytes[i][c + 1] == input[c]) {
			c++;
		}
		if (c == BOMbytes[i][0]) {
			ret = (BOM)i;
			break;
		}
	}
	return ret;
}

// some arguments like --key-derivation accept additional options (i.e. scrypt:13:7:2) and need to be parsed
// splitArgument replaces the delimiter (:) with zeros and returns the offset of all substrings (pos)
void splitArgument(std::string& arg, std::vector<size_t>& pos, char delimiter)
{
	pos.clear();
	if (!arg.size()) {
		return;
	}
	pos.push_back(0);
	size_t tpos = arg.find_first_of(delimiter);
	if (tpos == std::string::npos || tpos + 1 >= arg.size()) {
		return;
	}
	std::replace(arg.begin(), arg.end(), delimiter, (char)0);
	for (size_t i = 0; i < 6; i++) {
		pos.push_back(tpos + 1);
		tpos = arg.find((char)0, tpos + 1);
		if (tpos == std::string::npos || tpos + 1 >= arg.size()) {
			break;
		}
	}
}

bool setUserData(const char* s, size_t len, crypt::UserData& d, crypt::Encoding default_enc)
{
	if (len > 4 && s[0] == 'h' && s[1] == 'e' && s[2] == 'x'  && s[3] == ':') {
		d.set(s + 4, len - 4, crypt::Encoding::base16);
	} else if (len > 7 && s[0] == 'b' && s[1] == 'a' && s[2] == 's'  && s[3] == 'e'  && s[4] == '3'  && s[5] == '2'  && s[6] == ':') {
		d.set(s + 7, len - 7, crypt::Encoding::base32);
	} else if (len > 7 && s[0] == 'b' && s[1] == 'a' && s[2] == 's'  && s[3] == 'e'  && s[4] == '6'  && s[5] == '4'  && s[6] == ':') {
		d.set(s + 7, len - 7, crypt::Encoding::base64);
	} else if (len > 5 && s[0] == 'u' && s[1] == 't' && s[2] == 'f' && s[3] == '8' && s[4] == ':') {
		d.set(s, len, crypt::Encoding::ascii);
	} else {
		d.set(s, len, default_enc);
	}
	return (d.size() > 0);
}

bool getUserInput(const char* msg, crypt::UserData& data, crypt::Encoding default_enc, size_t trys, bool repeat, bool echo)
{
	crypt::secure_string input1, input2;
	size_t counter = 0;
	setEcho(echo);
	while (true) {
		std::cout << msg << ": ";
		readLine(input1);
		if (repeat) {
			std::cout << std::endl << "repeat: ";
			readLine(input2);
			std::cout << std::endl;
			if (input1.compare(input2) != 0) {
				std::cout << "input did not match!" << std::endl;
				continue;
			}
		}
		if (setUserData(input1.c_str(), input1.size(), data, default_enc)) {
			break;
		} else {
			std::cout << "invalid input (empty)." << std::endl;
		}
		counter++;
		if (counter >= trys) {
			setEcho(true);
			return false;
		}
	}
	setEcho(true);
	return true;
}

void checkPassword(CLI::Option* opt, std::string& arg, crypt::Options::Crypt& options)
{
	if (opt->count()) {
		setUserData(arg.c_str(), arg.size(), options.password, crypt::Encoding::ascii);
		for (size_t i = 0; i < arg.size(); i++) {
			arg[i] = 0;
		}
	}
}

// check -c --cipher argument
void checkCipher(CLI::Option* opt, const std::string& arg, crypt::Options::Crypt& options)
{
	if (opt->count()) {
		std::string s(arg);
		std::vector<size_t> pos;
		splitArgument(s, pos, ':');

		if (!crypt::help::getCipher(s.c_str(), options.cipher)) {
			throw CExc(CExc::Code::invalid_cipher);
		}
		if (pos.size() > 1) {
			options.key.length = std::atoi(&s[pos[1]]) / 8;
			if (!crypt::help::checkCipherKeylength(options.cipher, (size_t)options.key.length)) {
				throw CExc(CExc::Code::invalid_keylength);
			}
			if (pos.size() > 2) {
				if (!crypt::help::getCipherMode(&s[pos[2]], options.mode)) {
					throw CExc(CExc::Code::invalid_mode);
				}
				if (!crypt::help::checkCipherMode(options.cipher, options.mode)) {
					throw CExc(CExc::Code::invalid_mode);
				}
			} else {
				if (!crypt::help::checkProperty(options.cipher, crypt::STREAM)) {
					if (crypt::help::checkCipherMode(options.cipher, crypt::Mode::gcm)) {
						options.mode = crypt::Mode::gcm;
					} else {
						options.mode = crypt::Mode::cbc;
					}
				}
			}
		}
	}
}

// check -e --encoding ,examples:
//	-e base16:unix:96:true (= base16, unix eol, 96 linelength, uppercase)
//  -e base64 (=base64 default values for eol, linelength)
void checkEncoding(CLI::Option* opt, const std::string& arg, crypt::Options::Crypt& options)
{
	if (opt->count()) {
		std::string s(arg);
		std::vector<size_t> pos;
		splitArgument(s, pos, ':');
		if (!crypt::help::getEncoding(s.c_str(), options.encoding.enc)) {
			throw CExc(CExc::Code::invalid_encoding);
		}
		if (pos.size() > 1) {
			if (!crypt::help::getEOL(&s[pos[1]], options.encoding.eol)) {
				throw CExc(CExc::Code::invalid_eol);
			}
		}
		if (pos.size() > 2) {
			options.encoding.linelength = std::atoi(&s[pos[2]]);
			options.encoding.linebreaks = (options.encoding.linelength == 0) ? false : true;
			if (options.encoding.linelength < 0 || options.encoding.linelength > NPPC_MAX_LINE_LENGTH) {
				throw CExc(CExc::Code::invalid_linelength);
			}
		}
		if (pos.size() > 3) {
			if (strcmp(&s[pos[3]], "true")) {
				options.encoding.uppercase = true;
			} else if (strcmp(&s[pos[3]], "false")) {
				options.encoding.uppercase = false;
			} else {
				throw CExc(CExc::Code::invalid_uppercase);
			}
		}
	}
}

// check -k --key-derivation, examples:
//   -k scrypt:13:8:3 (= scrypt with N=2^13, r=8, p=3)
//	 -k pbkdf2:sha3:256:1000 (= pbkdf2 with sha3-256 and 1000 iterations)
//	 -k scrypt (= scrypt with default values for N,r,p)
void checkKeyDerivation(CLI::Option* opt, const std::string& arg, crypt::Options::Crypt& options)
{
	if (opt->count()) {
		std::string s(arg);
		std::vector<size_t> pos;
		splitArgument(s, pos, ':');
		if (!crypt::help::getKeyDerivation(s.c_str(), options.key.algorithm)) {
			throw CExc(CExc::Code::invalid_keyderivation);
		}
		switch (options.key.algorithm) {
		case crypt::KeyDerivation::pbkdf2:
		{
			crypt::Hash thash;
			if (pos.size() > 1) {				
				if (!crypt::help::getHash(&s[pos[1]], thash) || !crypt::help::checkProperty(thash, crypt::HMAC_SUPPORT)) {
					throw CExc(CExc::Code::invalid_pbkdf2_hash);
				}
				options.key.options[0] = static_cast<int>(thash);
			} else {
				options.key.options[0] = static_cast<int>(crypt::Constants::pbkdf2_default_hash);
			}
			if (pos.size() > 2) {
				options.key.options[1] = std::atoi(&s[pos[2]]) / 8;
				if (!crypt::help::checkHashDigest(thash, (unsigned int)options.key.options[1])) {
					throw CExc(CExc::Code::invalid_pbkdf2_hash);
				}
			} else {
				options.key.options[1] = static_cast<int>(crypt::Constants::pbkdf2_default_hash_digest);;
			}
			if (pos.size() > 3) {
				options.key.options[2] = std::atoi(&s[pos[3]]);
				if (options.key.options[2] < crypt::Constants::pbkdf2_iter_min || options.key.options[2] > crypt::Constants::pbkdf2_iter_max) {
					throw CExc(CExc::Code::invalid_pbkdf2);
				}
			} else {
				options.key.options[2] = crypt::Constants::pbkdf2_iter_default;
			}
			break;
		}
		case crypt::KeyDerivation::bcrypt:
		{
			if (pos.size() > 1) {
				options.key.options[0] = std::atoi(&s[pos[1]]);
				if (options.key.options[0] < crypt::Constants::bcrypt_iter_min || options.key.options[0] > crypt::Constants::bcrypt_iter_max) {
					throw CExc(CExc::Code::invalid_bcrypt);
				}
			} else {
				options.key.options[0] = crypt::Constants::bcrypt_iter_default;
			}
			break;
		}
		case crypt::KeyDerivation::scrypt:
		{
			if (pos.size() > 1) {
				options.key.options[0] = std::atoi(&s[pos[1]]);
				if (options.key.options[0] < crypt::Constants::scrypt_N_min || options.key.options[0] > crypt::Constants::scrypt_N_max) {
					throw CExc(CExc::Code::invalid_scrypt);
				}
			} else {
				options.key.options[0] = crypt::Constants::scrypt_N_default;
			}
			if (pos.size() > 2) {
				options.key.options[1] = std::atoi(&s[pos[2]]);
				if (options.key.options[1] < crypt::Constants::scrypt_r_min || options.key.options[1] > crypt::Constants::scrypt_r_max) {
					throw CExc(CExc::Code::invalid_scrypt);
				}
			} else {
				options.key.options[1] = crypt::Constants::scrypt_r_default;
			}
			if (pos.size() > 3) {
				options.key.options[2] = std::atoi(&s[pos[3]]);
				if (options.key.options[2] < crypt::Constants::scrypt_p_min || options.key.options[2] > crypt::Constants::scrypt_p_max) {
					throw CExc(CExc::Code::invalid_scrypt);
				}
			} else {
				options.key.options[2] = crypt::Constants::scrypt_p_default;
			}
			break;
		}
		}
	}
}

// check --hmac, example:
//   --hmac md5:128
void checkHMAC(CLI::Option* opt, const std::string& arg, CryptHeaderWriter::HMAC& hmac)
{
	hmac.enable = false;
	hmac.keypreset_id = -1;
	if (opt->count()) {
		std::string s(arg);
		std::vector<size_t> pos;
		splitArgument(s, pos, ':');

		if (!crypt::help::getHash(s.c_str(), hmac.hash.algorithm) || !crypt::help::checkProperty(hmac.hash.algorithm, crypt::HMAC_SUPPORT)) {
			throw CExc(CExc::Code::invalid_hmac_hash);
		}
		if (pos.size() > 1) {
			hmac.hash.digest_length = (size_t)std::atoi(&s[pos[1]]) / 8;
			if (!crypt::help::checkHashDigest(hmac.hash.algorithm, hmac.hash.digest_length)) {
				throw CExc(CExc::Code::invalid_hmac_hash);
			}
		}
		hmac.enable = true;
		hmac.hash.use_key = true;
	}
}

// check -s --salt
void checkHMACKey(CLI::Option* opt, const std::string& arg, CryptHeader::HMAC& hmac)
{
	if (opt->count()) {
		setUserData(arg.c_str(), arg.size(), hmac.hash.key, crypt::Encoding::ascii);
	}
}


// check -t --tag
void checkTag(CLI::Option* opt, const std::string& arg, crypt::InitData& initdata)
{
	if (opt->count()) {
		setUserData(arg.c_str(), arg.size(), initdata.tag, crypt::Encoding::base64);
	}
}

// check -v --iv
void checkIV(CLI::Option* opt, const std::string& arg, crypt::Options::Crypt& options, crypt::InitData& initdata)
{
	if (opt->count()) {
		if (arg.size() == 6 && arg.compare("random") == 0) {
			options.iv = crypt::IV::random;
		} else if (arg.size() == 4 && arg.compare("zero") == 0) {
			options.iv = crypt::IV::zero;
		} else if (arg.size() == 13 && arg.compare("keyderivation") == 0) {
			options.iv = crypt::IV::keyderivation;
		} else {
			options.iv = crypt::IV::custom;
			if (!setUserData(arg.c_str(), arg.size(), initdata.iv, crypt::Encoding::base64)) {
				throw CExc(CExc::Code::iv_missing);
			}
		}
	}
}

// check -s --salt
void checkSalt(CLI::Option* opt, const std::string& arg, crypt::InitData& initdata, crypt::Options::Crypt& options)
{
	if (opt->count()) {
		setUserData(arg.c_str(), arg.size(), initdata.salt, crypt::Encoding::base64);
		options.key.salt_bytes = (int)initdata.salt.size();
	}
}

// printout crypt options
void printOptions(const crypt::Options::Crypt& options)
{
	using namespace crypt;
	size_t c_keylen = options.key.length;
	size_t c_ivlen, c_blocksize;
	getCipherInfo(options.cipher, options.mode, c_keylen, c_ivlen, c_blocksize);

	std::cout << "options: " << help::getString(options.cipher) << "-" << c_keylen * 8;
	if (!crypt::help::checkProperty(options.cipher, crypt::STREAM)) {
		std::cout << "-" << crypt::help::getString(options.mode);
	}
	std::cout << ", iv: " << c_ivlen << " bytes (" << help::getString(options.iv) << "), " << help::getString(options.key.algorithm);;

	switch (options.key.algorithm) {
	case KeyDerivation::pbkdf2:
	{
		std::cout << " (" << help::getString(crypt::Hash(options.key.options[0])) << "-" << options.key.options[1]*8 << ", " << options.key.options[2] << " iterations)";
		break;
	}
	case KeyDerivation::bcrypt:
	{
		std::cout << " (2^" << options.key.options[0] << " iterations)";
		break;
	}
	case KeyDerivation::scrypt:
	{
		std::cout << " (N:2^" << options.key.options[0] << ", r:" << options.key.options[1] << ", p:" << options.key.options[2] << ")";
	}
	}
	std::cout << ", encoding: " << help::getString(options.encoding.enc) << std::endl;
}

// printout initialization data
void printInitData(const crypt::Options::Crypt& options, const crypt::InitData& initdata)
{
	using namespace crypt;
	secure_string tstr;
	if (options.key.salt_bytes && initdata.salt.size()) {
		initdata.salt.get(tstr, crypt::Encoding::base64);
		std::cout << "Salt: " << tstr << std::endl;;
	}
	if ((options.mode == Mode::gcm || options.mode == Mode::ccm || options.mode == Mode::eax) && initdata.tag.size()) {
		initdata.tag.get(tstr, crypt::Encoding::base64);
		std::cout << "Tag: " << tstr << std::endl;
	}
	if (options.iv == IV::random && initdata.iv.size()) {
		initdata.iv.get(tstr, crypt::Encoding::base64);
		std::cout << "IV: " << tstr << std::endl;
	}
}

void hash(const Arguments& args, const CLIOptions& opt, const byte* input, size_t input_length, bool isfile = false)
{
	std::basic_string<byte>		buffer;
	std::vector<std::string>	digests;
	crypt::Options::Hash		options;
	std::ostringstream			out;
	static const crypt::Hash	thashes[5] = { crypt::Hash::crc32, crypt::Hash::md5, crypt::Hash::sha1, crypt::Hash::sha2, crypt::Hash::sha3 };
	static const size_t			thashes_digests[5] = { 4, 16, 20, 32, 32 };

	if (opt.encoding->count() && !crypt::help::getEncoding(args.encoding.c_str(), options.encoding)) {
		throw CExc(CExc::Code::invalid_encoding);
	}

	if (opt.hash->count()) {
		std::string s(args.hash);
		std::vector<size_t> pos;
		splitArgument(s, pos, ':');

		if (!crypt::help::getHash(s.c_str(), options.algorithm)) {
			throw CExc(CExc::Code::invalid_hash);
		}
		if (pos.size() > 1) {
			options.digest_length = std::atoi(&s[pos[1]]) / 8;
			if (!crypt::help::checkHashDigest(options.algorithm, options.digest_length)) {
				throw CExc(CExc::Code::invalid_hash);
			}
		} else {
			options.digest_length = 0;
		}
		if (isfile) {
			std::string filename((const char*)input, input_length);
			crypt::hash(options, buffer, filename);
		} else {
			crypt::hash(options, buffer, { { input, input_length } });
		}
		digests.push_back(std::string(buffer.begin(), buffer.end()));
		out << crypt::help::getString(options.algorithm) << "-" << options.digest_length * 8 << ": " << (const char*)buffer.c_str() << std::endl;
	} else {		
		for (size_t i = 0; i < 5; i++) {
			options.algorithm = thashes[i];
			options.digest_length = thashes_digests[i];
			if (isfile) {
				std::string filename((const char*)input, input_length);
				crypt::hash(options, buffer, filename);
			} else {
				crypt::hash(options, buffer, { { input, input_length } });
			}
			digests.push_back(std::string(buffer.begin(), buffer.end()));
			out << crypt::help::getString(options.algorithm) << ": " << (const char*)buffer.c_str() << std::endl;
		}
	}
	
	if (opt.output->count()) {
		std::string temp = out.str();
		if (!writeFile(args.output, BOM::none, (const byte*)temp.c_str(), temp.size())) {
			throw CExc(CExc::Code::outputfile_write_fail);
		}
	} else {
		std::cout << out.str();
		if (!*opt.nointeraction) {
			std::string input;
			std::getline(std::cin, input);
			if (input.size()) {
				std::transform(input.begin(), input.end(), input.begin(), ::tolower);
				size_t i;
				for (i = 0; i < digests.size(); i++) {
					std::transform(digests[i].begin(), digests[i].end(), digests[i].begin(), ::tolower);
					if (input.compare(digests[i]) == 0) {
						break;
					}
				}
				if (i == digests.size()) {
					std::cout << "no match." << std::endl;
				} else {
					if (opt.hash->count()) {
						std::cout << crypt::help::getString(options.algorithm) << " matches." << std::endl;
					} else {
						std::cout << crypt::help::getString(thashes[i]) << " matches." << std::endl;
					}
				}
			}
		}
	}
}

void decrypt(Arguments& args, const CLIOptions& opt, const byte* input, size_t input_length)
{
	std::basic_string<byte>	outputData;
	crypt::Options::Crypt	options;
	CryptHeader::HMAC		hmac;
	CryptHeaderReader		header(options, hmac);
	crypt::InitData&		init(header.initData());
	BOM						bom = getBOM(input, input_length);

	if (bom == BOM::utf8) {
		input += BOMbytes[static_cast<unsigned>(bom)][0];
		input_length -= BOMbytes[static_cast<unsigned>(bom)][0];
	} else if(bom != BOM::none) {
		throw CExc(CExc::Code::only_utf8_decrypt);
	}

	checkPassword(opt.password, args.password, options);
	if (!options.password.size()) {
		if (*opt.nointeraction) {
			throw CExc(CExc::Code::password_missing);
		}
		if (!getUserInput("enter password", options.password, crypt::Encoding::ascii, 3, true, false)) {
			throw CExc(CExc::Code::password_missing);
		}
	}

	checkCipher(opt.cipher, args.cipher, options);
	checkKeyDerivation(opt.keyderivation, args.keyderivation, options);
	checkTag(opt.tag, args.tag, init);
	checkIV(opt.iv, args.iv, options, init);
	checkSalt(opt.salt, args.salt, init, options);

	if (header.parse(input, input_length)) {
		// ------ header present:
		if (!*opt.silent) {
			if (opt.output->count()) {
				std::cout << "output: " << args.output << std::endl;
			}
			printOptions(options);
		}
		if (!*opt.nointeraction) {
			if (!crypt::help::checkProperty(options.cipher, crypt::STREAM) && (options.mode == crypt::Mode::ccm || options.mode == crypt::Mode::gcm || options.mode == crypt::Mode::eax) && !init.tag.size()) {
				if (!getUserInput("please specify tag", init.tag, crypt::Encoding::base64, 2, false, true)) {
					throw CExc(CExc::Code::invalid_tag);
				}
			}
		}
		if (!*opt.silent) {
			printInitData(options, header.initData());
		}
		// hmac authentication of header & data
		if (hmac.enable) {
			if (hmac.keypreset_id >= 0) {
				// nppcrypt preferences file not present
				std::cout << "hmac authentication skipped (presets not available)." << std::endl;
			} else {
				checkHMACKey(opt.hmac_key, args.hmac_key, hmac);
				if (!hmac.hash.key.size()) {
					if (*opt.nointeraction) {
						throw CExc(CExc::Code::hmac_key_missing);
					}
					if (!getUserInput("enter HMAC key", hmac.hash.key, crypt::Encoding::ascii, 3, true, false)) {
						throw CExc(CExc::Code::hmac_key_missing);
					}
				}
				if (!header.checkHMAC()) {
					throw CExc(CExc::Code::hmac_auth_failed);
				}
			}
		}
		// decrypt
		crypt::decrypt(header.encryptedData(), header.encryptedDataLength(), outputData, options, header.initData());
	} else {
		// ------ no header present:
		if (!*opt.silent) {
			if (opt.output->count()) {
				std::cout << "output: " << args.output << std::endl;
			}
			printOptions(options);
		}
		if (!*opt.nointeraction) {
			if (options.key.salt_bytes > 0 && !init.salt.size()) {
				if (!getUserInput("salt data missing. please specify", init.salt, crypt::Encoding::base64, 2, false, true)) {
					throw CExc(CExc::Code::salt_missing);
				}
			}
			if (options.iv == crypt::IV::random && !init.iv.size()) {
				if (!getUserInput("IV data missing. please specify", init.iv, crypt::Encoding::base64, 2, false, true)) {
					throw CExc(CExc::Code::iv_missing);
				}
			}
			if (!crypt::help::checkProperty(options.cipher, crypt::STREAM) && (options.mode == crypt::Mode::ccm || options.mode == crypt::Mode::gcm || options.mode == crypt::Mode::eax) && !init.tag.size()) {
				if (!getUserInput("tag data missing. please specify", init.tag, crypt::Encoding::base64, 2, false, true)) {
					throw CExc(CExc::Code::iv_missing);
				}
			}
		}
		if(!*opt.silent) {
			printInitData(options, init);
		}
		// decrypt
		crypt::decrypt(input, input_length, outputData, options, init);
	}
	if (opt.output->count()) {
		if (!writeFile(args.output, bom, outputData.c_str(), outputData.size())) {
			throw CExc(CExc::Code::outputfile_write_fail);
		}
	} else {
		std::cout << outputData.c_str() << std::endl;
	}
}

void encrypt(Arguments& args, const CLIOptions& opt, const byte* input, size_t input_length)
{
	std::basic_string<byte>	outputData;
	crypt::Options::Crypt	options;
	CryptHeader::HMAC		hmac;
	CryptHeaderWriter		header(options, hmac);

	checkPassword(opt.password, args.password, options);

	if (!options.password.size()) {
		if (*opt.nointeraction) {
			throw CExc(CExc::Code::password_missing);
		}
		if (!getUserInput("enter password", options.password, crypt::Encoding::ascii, 3, true, false)) {
			throw CExc(CExc::Code::password_missing);
		}
	}
	
	checkCipher(opt.cipher, args.cipher, options);
	checkIV(opt.iv, args.iv, options, header.initData());
	checkKeyDerivation(opt.keyderivation, args.keyderivation, options);
	checkEncoding(opt.encoding, args.encoding, options);
	checkHMAC(opt.hmac, args.hmac, hmac);
	checkHMACKey(opt.hmac_key, args.hmac_key, hmac);

	if (hmac.enable && !hmac.hash.key.size()) {
		if (*opt.nointeraction) {
			throw CExc(CExc::Code::hmac_key_missing);
		}
		if (!getUserInput("enter HMAC key", hmac.hash.key, crypt::Encoding::ascii, 2, true, false)) {
			throw CExc(CExc::Code::hmac_key_missing);
		}
	}

	if (!*opt.silent) {
		if (opt.output->count()) {
			std::cout << "output: " << args.output << std::endl;
		}
		printOptions(options);
	}
	
	crypt::encrypt(input, input_length, outputData, options, header.initData());

	if (!*opt.noheader) {
		header.create(outputData.c_str(), outputData.size());
	}
	if (opt.output->count()) {
		if (!writeFile(args.output, BOM::none, outputData.c_str(), outputData.size(), header.c_str(), header.size())) {
			throw CExc(CExc::Code::outputfile_write_fail);
		}
		if (!*opt.silent || *opt.noheader) {
			printInitData(options, header.initData());
		}
	} else {
		if (header.size()) {
			std::cout << header.c_str();
		}
		if (!*opt.silent && *opt.noheader) {
			printInitData(options, header.initData());
		}
		std::cout << outputData.c_str() << std::endl;
	}
}



int main(int argc, char** argv)
{
	setLocale();
	CLI::App app{ "nppcrypt" };

	try {
		Action		action;
		Arguments	args;
		CLIOptions	opt;
		// setup CLI11 parser
		opt.action = app.add_option("action", args.action, "(enc|dec|hash)");
		opt.hash = app.add_option("--hash", args.hash, "hash algorithm: (adler32|blake2b|blake2s|cmac_aes|crc32|keccak|md2|md4|md5|ripemd|sha1|sha2|sha3|siphash24|siphash48|sm3|tiger|whirlpool)[:Digestlength] i.e.: sha3:512");
		opt.password = app.add_option("-p,--password", args.password, "password [(utf8(default)|hex|base32|base64):]password");
		opt.input = app.add_option("input", args.input, "input (file or string)");
		opt.output = app.add_option("-o,--output", args.output, "output file");
		opt.cipher = app.add_option("-c,--cipher", args.cipher, "cipher[:keylength[:mode]] i.e. camellia:256:cbc, default: rijndael:256:gcm\nciphers: (threeway|aria|blowfish|btea|camellia|cast128|cast256|chacha20|des|des_ede2|des_ede3|desx|gost|idea|kalyna128|kalyna256|kalyna512|mars|panama|rc2|rc4|rc5|rc6|rijndael|saferk|safersk|salsa20|seal|seed|serpent|shacal2|shark|simon128|skipjack|sm4|sosemanuk|speck128|square|tea|threefish256|threefish512|threefish1024|twofish|wake|xsalsa20|xtea),\nmodes: (ecb|cbc|cbc_cts|cfb|ofb|ctr|eax|ccm|gcm)");
		opt.keyderivation = app.add_option("-k,--key-derivation", args.keyderivation, "key derivation algorithm [default:scrypt]: (pbkdf2|bcrypt|scrypt)[:*option1*[:*option2*[:*option3*]]]");
		opt.encoding = app.add_option("-e,--encoding", args.encoding, "encoding [default:base64]: (ascii|base16|base32|base64)[:(windows|unix)[:*linelength*[:*uppercase(true|false)*]]]");
		opt.tag = app.add_option("-t,--tag", args.tag, "tag-value: [(utf8|hex|base32|base64(default)):]tagdata");
		opt.salt = app.add_option("-s,--salt", args.salt, "salt-value: [(utf8|hex|base32|base64(default)):]saltdata");
		opt.iv = app.add_option("-v,--iv", args.iv, "IV: (random|keyderivation|zero) or [(utf8|hex|base32|base64(default)):]ivdata");
		opt.hmac = app.add_option("--hmac", args.hmac, "create hmac to authenticate header and encrypted data: hash:length i.e. sha3:256");
		opt.hmac_key = app.add_option("--hmac-key", args.hmac_key, "hmac-key: [(utf8(default)|hex|base32|base64):]*key*");
		opt.noheader = app.add_flag("--noheader", "no header output");
		opt.silent = app.add_flag("--silent", "silent mode");
		opt.nointeraction = app.add_flag("--auto", "no user interaction");
		opt.input->required();

		app.parse(argc, argv);

		if (!*opt.action) {
			action = Action::hash;
		} else {
			if (args.action.compare("hash") == 0) {
				action = Action::hash;
			} else if (args.action.compare("dec") == 0) {
				action = Action::decrypt;
			} else if (args.action.compare("enc") == 0) {
				action = Action::encrypt;
			} else {
				throw CExc(CExc::Code::invalid_crypt_action);
			}
		}
		
		std::basic_string<byte>	inputData;

		if (file_exists(args.input)) {
			if (action != Action::hash) {
				if (!readFile(args.input, inputData)) {
					throw CExc(CExc::Code::inputfile_read_fail);
				}
			}
			if (!*opt.silent) {
				std::cout << "input (file): " << args.input << std::endl;
			}
		} else {
			inputData.assign(args.input.begin(), args.input.end());
			if (!*opt.silent) {
				std::cout << "input (string): " << args.input << std::endl;
			}
		}

		switch (action) {
		case Action::hash:
		{
			if (file_exists(args.input)) {
				hash(args, opt, (const byte*)args.input.c_str(), args.input.size(), true);
			} else {
				hash(args, opt, inputData.c_str(), inputData.size());
			}
			break;
		}
		case Action::decrypt:
		{
			decrypt(args, opt, inputData.c_str(), inputData.size());
			break;
		}
		case Action::encrypt:
		{
			encrypt(args, opt, inputData.c_str(), inputData.size());
			break;
		}
		}

	} catch (const CLI::ParseError &e) {
		return app.exit(e);
	} catch (CExc& e) {
		std::cerr << "error: " << e.what() << std::endl;
	} catch (std::exception& e)	{
		std::cerr << "error:" << e.what() << std::endl;
	} catch (...) {
		std::cerr << "unexpected error." << std::endl;
	}
	return 0;
}
