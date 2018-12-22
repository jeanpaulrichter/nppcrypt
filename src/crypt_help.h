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

#ifndef CRYPT_HELP_H_DEF
#define CRYPT_HELP_H_DEF

#include "crypt.h"

namespace crypt
{
    enum Properties { WEAK = 1, EAX = 2, CCM = 4, GCM = 8, BLOCK = 16, STREAM = 32, HMAC_SUPPORT = 64, KEY_SUPPORT = 128, KEY_REQUIRED = 256 };

    class help
    {
    public:
        static const char*  getString(Cipher cipher);
        static const char*  getString(Mode mode);
        static const char*  getString(Encoding enc);
        static const char*  getString(KeyDerivation k);
        static const char*  getString(IV iv);
        static const char*  getString(Hash h);
        static const char*  getString(UserData::Restriction r);
        static const char*  getString(EOL eol);
        static const char*  getString(bool v);

        static bool         getCipher(const char* s, Cipher& c);
        static bool         getCipherMode(const char* s, Mode& m);
        static bool         getKeyDerivation(const char*s, KeyDerivation& v);
        static bool         getEncoding(const char* s, Encoding& e);
        static bool         getIVMode(const char* s, IV& iv);
        static bool         getHash(const char* s, Hash& h);
        static bool         getRandomRestriction(const char* s, UserData::Restriction& r);
        static bool         getEOL(const char* s, EOL& eol);
        static bool         getUnsigned(const char* s, size_t& i);
        static bool         getInteger(const char* s, int& i, bool log2 = false);
        static bool         getBoolean(const char* s, bool& b);

        static bool         checkCipherMode(Cipher cipher, Mode mode);
        static bool         checkProperty(Cipher cipher, int filter);
        static bool         checkProperty(Hash h, int filter);
        static bool         checkHashDigest(Hash h, unsigned int digest);
        static bool         checkCipherKeylength(Cipher cipher, size_t keylength);

        static void         validate(Options::Crypt options, bool exceptions = true);
        static void         validate(Options::Hash options, bool exceptions = true);
        static void         validate(Options::Convert options, bool exceptions = true);

        static Mode         getModeByIndex(Cipher cipher, int index);
        static int          getModeIndex(Cipher cipher, Mode mode);
        static int          getCipherCategory(Cipher cipher);
        static Cipher       getCipherByIndex(size_t category, size_t index);
        static int          getCipherIndex(Cipher cipher);
        static size_t       getCipherKeylengthByIndex(Cipher cipher, size_t index);
        static Hash         getHashByIndex(size_t index, int filter);
        static int          getHashIndex(Hash h, int filter);
        static size_t       getHashDigestByIndex(Hash h, unsigned int index);
        static int          getHashDigestIndex(Hash h, unsigned int digest);

        static const char*  getHelpURL(Encoding enc);
        static const char*  getHelpURL(Cipher cipher);
        static const char*  getHelpURL(Mode m);
        static const char*  getHelpURL(Hash h);
        static const char*  getHelpURL(KeyDerivation k);

        static const char*  getInfo(Cipher c);
        static const char*  getInfo(Mode m);
        static const char*  getInfo(Hash h);
        static const char*  getInfo(IV iv);
        static const char*  getInfo(KeyDerivation k);
        static const char*  getInfo(Encoding e);

        class CipherCategories
        {
        public:
            CipherCategories();
            CipherCategories& operator++();
            const char* operator*() const;
        private:
            int i;
        };

        class CipherNames
        {
        public:
            CipherNames(int category);
            CipherNames& operator++();
            const char* operator*() const;
        private:
            int i;
            int c;
        };

        class CipherModes
        {
        public:
            CipherModes(crypt::Cipher c);
            CipherModes& operator++();
            const char* operator*() const;
        private:
            int i;
            size_t cipher_index;
        };

        class CipherKeys
        {
        public:
            CipherKeys(crypt::Cipher c);
            CipherKeys& operator++();
            int operator*() const;
        private:
            int i;
            size_t cipher_index;
        };

        class Hashnames
        {
        public:
            Hashnames(int filter = 0);
            Hashnames& operator++();
            const char* operator*() const;
        private:
            void checkfilter();
            int i;
            int f;
        };

        class HashDigests
        {
        public:
            HashDigests(crypt::Hash h);
            HashDigests& operator++();
            int operator*() const;
        private:
            void getLength();
            int cur_length;
            int i;
            size_t hash_index;
        };
    };
}

#endif