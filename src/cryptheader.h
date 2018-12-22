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

#ifndef HEADER_H_DEF
#define HEADER_H_DEF

#include "crypt.h"
#include "mdef.h"

class CryptHeader
{
public:

    struct HMAC {
        HMAC() : enable(false), keypreset_id(-1) {};

        bool                    enable;
        int                     keypreset_id;
        crypt::Options::Hash    hash;
    };

        CryptHeader(HMAC& h) : version(NPPC_VERSION), hmac(h) {};
    int getVersion() { return version; };

protected:

    struct DataPointer {
        DataPointer() : start(NULL), length(0) {};

        const crypt::byte* start;
        size_t             length;
    };

    HMAC&       hmac;
    int         version;
    DataPointer body;
};

class CryptHeaderReader : public CryptHeader
{
public:
                        CryptHeaderReader(HMAC& hmac) : CryptHeader(hmac) {};
    bool                parse(crypt::Options::Crypt& options, crypt::InitData& initdata, const crypt::byte* in, size_t in_len);
    const crypt::byte*  getEncrypted() { return encrypted.start; };
    size_t              getEncryptedLength() { return encrypted.length; };
    bool                checkHMAC();

private:
    crypt::UserData     hmac_digest;
    DataPointer          encrypted;
};

class CryptHeaderWriter : public CryptHeader
{
public:
                CryptHeaderWriter(HMAC& hmac) : CryptHeader(hmac) {};
    void        create(const crypt::Options::Crypt& options, const crypt::InitData& initdata, const crypt::byte* data, size_t data_length);
    const char* c_str() { return buffer.c_str(); };
    size_t      size() { return buffer.size(); };

private:
    size_t      base64length(size_t bin_length, bool linebreaks=false, size_t line_length=0, bool windows=false);

    std::string buffer;
};

#endif