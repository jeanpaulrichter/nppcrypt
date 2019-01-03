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

    namespace help
    {
        const char*  getString(Cipher cipher);
        const char*  getString(Mode mode);
        const char*  getString(Encoding enc);
        const char*  getString(KeyDerivation k);
        const char*  getString(IV iv);
        const char*  getString(Hash h);
        const char*  getString(UserData::Restriction r);
        const char*  getString(EOL eol);
        const char*  getString(bool v);

        bool         getCipher(const char* s, Cipher& c);
        bool         getCipherMode(const char* s, Mode& m);
        bool         getKeyDerivation(const char*s, KeyDerivation& v);
        bool         getEncoding(const char* s, Encoding& e);
        bool         getIVMode(const char* s, IV& iv);
        bool         getHash(const char* s, Hash& h);
        bool         getRandomRestriction(const char* s, UserData::Restriction& r);
        bool         getEOL(const char* s, EOL& eol);
        bool         getUnsigned(const char* s, size_t& i);
        bool         getInteger(const char* s, int& i, bool log2 = false);
        bool         getBoolean(const char* s, bool& b);

        bool         checkCipherMode(Cipher cipher, Mode mode);
        bool         checkProperty(Cipher cipher, int filter);
        bool         checkProperty(Hash h, int filter);
        bool         checkHashDigest(Hash h, unsigned int digest);
        bool         checkCipherKeylength(Cipher cipher, size_t keylength);

        void         validate(Options::Crypt options, bool exceptions = true);
        void         validate(Options::Hash options, bool exceptions = true);
        void         validate(Options::Convert options, bool exceptions = true);

        Mode         getModeByIndex(Cipher cipher, int index);
        int          getModeIndex(Cipher cipher, Mode mode);
        int          getCipherCategory(Cipher cipher);
        Cipher       getCipherByIndex(size_t category, size_t index);
        int          getCipherIndex(Cipher cipher);
        size_t       getCipherKeylengthByIndex(Cipher cipher, size_t index);
        Hash         getHashByIndex(size_t index, int filter);
        int          getHashIndex(Hash h, int filter);
        size_t       getHashDigestByIndex(Hash h, unsigned int index);
        int          getHashDigestIndex(Hash h, unsigned int digest);

        const char*  getHelpURL(Encoding enc);
        const char*  getHelpURL(Cipher cipher);
        const char*  getHelpURL(Mode m);
        const char*  getHelpURL(Hash h);
        const char*  getHelpURL(KeyDerivation k);

        const char*  getInfo(Cipher c);
        const char*  getInfo(Mode m);
        const char*  getInfo(Hash h);
        const char*  getInfo(IV iv);
        const char*  getInfo(KeyDerivation k);
        const char*  getInfo(Encoding e);

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
    }
}

#endif