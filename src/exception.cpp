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


#include "exception.h"

static const TCHAR* error_msgs[] = { TEXT("Unexspected exception."), TEXT("Failed to encrypt."), TEXT("Failed to decrypt."), TEXT("Failed to read hex."), 
									TEXT("File is empty."), TEXT("Failed to parse header."), TEXT("Data authentication failed."), TEXT("String-conversion to utf8 failed."),
									TEXT("Sorry, this file is no longer supported.\nPlease download v1.009 at www.cerberus-design.de/downloads."), 
									TEXT("Sorry, this file is no longer supported.\nPlease download v1.007 at www.cerberus-design.de/downloads.")};

const TCHAR* CExc::getErrorMsg() const throw()
{
	if(msg.size())
		return &msg[0];
	else
		return error_msgs[code];
}

CExc::~CExc() throw()
{
}

CExc::CExc(const TCHAR* what)
{
	code = ErrCode::unexspected;
	if(!what)
		return;
	size_t slen = lstrlen(what);
	if(!slen)
		return;
	if(slen <= 128) {
		msg.resize(slen+1);
		lstrcpy(&msg[0], what);
	} else {
		msg.resize(129);
		msg[128]=0;
		memcpy(&msg[0], what, 128*sizeof(TCHAR));
	}
}

CExc::CExc(ErrCode err_code)
{
	code = err_code;
}

CExc::CExc(File file, int line, const TCHAR* what)
{
	if(what) {
		size_t slen = lstrlen(what);
		if(slen) {
			if(slen <= 118) {
				msg.resize(slen+11);
				lstrcpy(&msg[10], what);
			} else {
				msg.resize(129);
				msg[128]=0;
				memcpy(&msg[10], what, 118*sizeof(TCHAR));
			}
		}
	}
	if(!msg.size()) {
		msg.resize(40);
		lstrcpy(&msg[10],error_msgs[0]);
		msg[32] = 0;
	}

	msg[0] = '('; msg[3] = '/'; msg[8] = ')'; msg[9] = ' ';
	msg[1] = 48+(file/10);
	msg[2] = 48+(file%10);
	msg[7] = (line % 10) + '0';  line /= 10;
    msg[6] = (line % 10) + '0';  line /= 10;
    msg[5] = (line % 10) + '0';  line /= 10;
    msg[4] = (line % 10) + '0';
}

CExc::CExc(File file, int line, ErrCode err_code)
{
	msg.resize(11+lstrlen(error_msgs[err_code]));
	lstrcpy(&msg[10], error_msgs[err_code]);

	msg[0] = '('; msg[3] = '/'; msg[8] = ')'; msg[9] = ' ';
	msg[1] = 48+(file/10);
	msg[2] = 48+(file%10);
	msg[7] = (line % 10) + '0';  line /= 10;
    msg[6] = (line % 10) + '0';  line /= 10;
    msg[5] = (line % 10) + '0';  line /= 10;
    msg[4] = (line % 10) + '0';

	code = err_code;
}