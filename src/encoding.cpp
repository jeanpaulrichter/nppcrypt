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


#include "encoding.h"

bool Encode::Options::Base16::spaces = false;
Encode::Options::Base16::Case Encode::Options::Base16::letter_case = lower;
unsigned int Encode::Options::Base16::vpl = 64;
unsigned int  Encode::Options::Base64::cpl = 128;
Encode::Options::Common::EOL Encode::Options::Common::eol = windows;

inline const char* linebreak()
{
	static const char win[] = { '\r', '\n', 0 };
	if (Encode::Options::Common::eol == Encode::Options::Common::EOL::windows)
		return win;
	else
		return &win[1];
}

/* ================================================================================================================================
The following code is part of the libb64 project, and has been placed in the public domain.
For details, see http://sourceforge.net/projects/libb64
================================================================================================================================= */

typedef enum
{
	step_a, step_b, step_c, step_d
} base64_decodestep;

typedef struct
{
	base64_decodestep step;
	char plainchar;
} base64_decodestate;

typedef enum
{
	step_A, step_B, step_C
} base64_encodestep;

typedef struct
{
	base64_encodestep step;
	char result;
	int stepcount;
} base64_encodestate;

void base64_init_encodestate(base64_encodestate* state_in)
{
	state_in->step = step_A;
	state_in->result = 0;
	state_in->stepcount = 0;
}

char base64_encode_value(char value_in)
{
	static const char* encoding = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	if (value_in > 63) return '=';
	return encoding[(int)value_in];
}

int base64_encode_block(const char* plaintext_in, int length_in, char* code_out, base64_encodestate* state_in, bool no_linebreaks)
{
	const char* plainchar = plaintext_in;
	const char* const plaintextend = plaintext_in + length_in;
	char* codechar = code_out;
	char result;
	char fragment;

	int chars_p_line = (no_linebreaks ? 0 : Encode::Options::Base64::cpl);

	result = state_in->result;

	switch (state_in->step)
	{
		while (1)
		{
	case step_A:
		if (plainchar == plaintextend)
		{
			state_in->result = result;
			state_in->step = step_A;
			return codechar - code_out;
		}
		fragment = *plainchar++;
		result = (fragment & 0x0fc) >> 2;
		*codechar++ = base64_encode_value(result);

		++(state_in->stepcount);
		if (chars_p_line && state_in->stepcount == chars_p_line)
		{
			if (Encode::Options::Common::eol == Encode::Options::Common::EOL::windows) {
				*codechar++ = '\r';
				*codechar++ = '\n';
			}
			else {
				*codechar++ = '\n';
			}
			state_in->stepcount = 0;
		}

		result = (fragment & 0x003) << 4;
	case step_B:
		if (plainchar == plaintextend)
		{
			state_in->result = result;
			state_in->step = step_B;
			return codechar - code_out;
		}
		fragment = *plainchar++;
		result |= (fragment & 0x0f0) >> 4;
		*codechar++ = base64_encode_value(result);

		++(state_in->stepcount);
		if (chars_p_line && state_in->stepcount == chars_p_line)
		{
			if (Encode::Options::Common::eol == Encode::Options::Common::EOL::windows) {
				*codechar++ = '\r';
				*codechar++ = '\n';
			}
			else {
				*codechar++ = '\n';
			}
			state_in->stepcount = 0;
		}

		result = (fragment & 0x00f) << 2;
	case step_C:
		if (plainchar == plaintextend)
		{
			state_in->result = result;
			state_in->step = step_C;
			return codechar - code_out;
		}
		fragment = *plainchar++;
		result |= (fragment & 0x0c0) >> 6;
		*codechar++ = base64_encode_value(result);

		++(state_in->stepcount);
		if (chars_p_line && state_in->stepcount == chars_p_line)
		{
			if (Encode::Options::Common::eol == Encode::Options::Common::EOL::windows) {
				*codechar++ = '\r';
				*codechar++ = '\n';
			}
			else {
				*codechar++ = '\n';
			}
			state_in->stepcount = 0;
		}

		result = (fragment & 0x03f) >> 0;
		*codechar++ = base64_encode_value(result);

		++(state_in->stepcount);
		if (chars_p_line && state_in->stepcount == chars_p_line)
		{
			if (Encode::Options::Common::eol == Encode::Options::Common::EOL::windows) {
				*codechar++ = '\r';
				*codechar++ = '\n';
			}
			else {
				*codechar++ = '\n';
			}
			state_in->stepcount = 0;
		}
		}
	}
	/* control should not reach here */
	return codechar - code_out;
}

int base64_encode_blockend(char* code_out, base64_encodestate* state_in)
{
	char* codechar = code_out;
	
	switch (state_in->step)
	{
	case step_B:
		*codechar++ = base64_encode_value(state_in->result);
		*codechar++ = '=';
		*codechar++ = '=';
		break;
	case step_C:
		*codechar++ = base64_encode_value(state_in->result);
		*codechar++ = '=';
		break;
	case step_A:
		break;
	}
	//*codechar++ = '\n';	
	return codechar - code_out;
}

int base64_decode_value(char value_in)
{
	static const char decoding[] = {62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51};
	static const char decoding_size = sizeof(decoding);
	value_in -= 43;
	if (value_in < 0 || value_in >= decoding_size)
		return -1;
	return decoding[(int)value_in];
}

void base64_init_decodestate(base64_decodestate* state_in)
{
	state_in->step = step_a;
	state_in->plainchar = 0;
}

int base64_decode_block(const char* code_in, const int length_in, char* plaintext_out, base64_decodestate* state_in)
{
	const char* codechar = code_in;
	char* plainchar = plaintext_out;
	char fragment;
	
	*plainchar = state_in->plainchar;
	
	switch (state_in->step)
	{
		while (1)
		{
	case step_a:
			do {
				if (codechar == code_in+length_in)
				{
					state_in->step = step_a;
					state_in->plainchar = *plainchar;
					return plainchar - plaintext_out;
				}
				fragment = (char)base64_decode_value(*codechar++);
			} while (fragment < 0);
			*plainchar    = (fragment & 0x03f) << 2;
	case step_b:
			do {
				if (codechar == code_in+length_in)
				{
					state_in->step = step_b;
					state_in->plainchar = *plainchar;
					return plainchar - plaintext_out;
				}
				fragment = (char)base64_decode_value(*codechar++);
			} while (fragment < 0);
			*plainchar++ |= (fragment & 0x030) >> 4;
			if(*codechar=='=')
				return plainchar - plaintext_out;
			*plainchar    = (fragment & 0x00f) << 4;
	case step_c:
			do {
				if (codechar == code_in+length_in)
				{
					state_in->step = step_c;
					state_in->plainchar = *plainchar;
					return plainchar - plaintext_out;
				}
				fragment = (char)base64_decode_value(*codechar++);
			} while (fragment < 0);
			*plainchar++ |= (fragment & 0x03c) >> 2;
			if(*codechar=='=')
				return plainchar - plaintext_out;
			*plainchar    = (fragment & 0x003) << 6;
	case step_d:
			do {
				if (codechar == code_in+length_in)
				{
					state_in->step = step_d;
					state_in->plainchar = *plainchar;
					return plainchar - plaintext_out;
				}
				fragment = (char)base64_decode_value(*codechar++);
			} while (fragment < 0);
			*plainchar++   |= (fragment & 0x03f);
		}
	}
	/* control should not reach here */
	return plainchar - plaintext_out;
}

// =========================================================================================================================================================================
// =========================================================================================================================================================================


size_t Encode::bin_to_hex(const unsigned char* src, unsigned int len, char* dest)
{
	if(!dest) {
		if (!len)
			return 0;
		size_t lines = (Options::Base16::vpl) ? (len - 1) / Options::Base16::vpl + 1 : 1;
		if (Options::Base16::spaces) {
			if (Options::Common::eol == Options::Common::EOL::windows)
				return len * 3 - 1 + (lines - 1);
			else
				return len * 3 - 1;
		}
		else {
			if (Options::Common::eol == Options::Common::EOL::windows)
				return len * 2 + (lines - 1) * 2;
			else
				return len * 2 + (lines - 1);
		}
	} else {

		static const char* const hex_chars_upper = "0123456789ABCDEF";
		static const char* const hex_chars_lower = "0123456789abcdef";
		const char* const hex_chars = (Options::Base16::letter_case == Options::Base16::Case::lower) ? hex_chars_lower : hex_chars_upper;

		size_t i_out=0;
		size_t i_out_line=0;
		for(size_t i=0; i<len; i++) {
			
			dest[i_out] = hex_chars[(src[i]>>4)];
			dest[i_out+1] = hex_chars[(src[i] & 15)];

			i_out+=2;
			i_out_line++;

			if (i + 1 != len) {
				if (Options::Base16::vpl && i_out_line >= Options::Base16::vpl) {
					i_out_line = 0;
					if (Options::Common::eol == Options::Common::EOL::windows) {
						dest[i_out] = '\r';
						dest[i_out + 1] = '\n';
						i_out += 2;
					}
					else {
						dest[i_out] = '\n';
						i_out++;
					}
				}
				else if (Options::Base16::spaces) {
					dest[i_out] = ' ';
					i_out++;
				}
			}
		}
		return i_out;
	}
}

size_t Encode::hex_to_bin(const char* src, unsigned int len, unsigned char* dest)
{
	size_t i=0;
	size_t i_out=0;

	if(!dest) {
		if(len==0||!src)
			return 0;
		while(i<len) {
			if(src[i]<48 || src[i]>102 || (src[i]>57 && src[i]<65) || (src[i]>70 && src[i]<97))
				return 0;
			if(src[i+1]<48 || src[i+1]>102 || (src[i+1]>57 && src[i+1]<65) || (src[i+1]>70 && src[i+1]<97))
				return 0;

			i_out++;
			i+=2;
			while(src[i]==' ' || src[i]=='\n' || src[i]=='\r')
				i++;
		}
		return i_out;
	} else {
		while(i<len) {

			dest[i_out]=0;

			if(src[i]>=48 && src[i]<=57) { //0-9
				dest[i_out]+=((src[i]-48)*16);
			} else if(src[i]>=65 && src[i]<=70) { //A-F
				dest[i_out]+=((src[i]-55)*16);
			} else { //a-f
				dest[i_out]+=((src[i]-87)*16);
			}
			if(src[i+1]>=48 && src[i+1]<=57) { //0-9
				dest[i_out]+=(src[i+1]-48);
			} else if(src[i+1]>=65 && src[i+1]<=70) { //A-F
				dest[i_out]+=(src[i+1]-55);
			} else { //a-f
				dest[i_out]+=(src[i+1]-87);
			}
			i_out++;
			i+=2;

			while(src[i]==' ' || src[i]=='\n' || src[i]=='\r')
				i++;
		}
		return i_out;
	}
    
}

size_t Encode::bin_to_base64(const unsigned char* src, unsigned int len, char* dest, bool no_linebreaks)
{
	if(!dest) {
		if (len == 0)
			return 0;

		unsigned int chars = 4 * (len + 2 - ((len + 2) % 3)) / 3;
		if (!no_linebreaks && Options::Base64::cpl) {
			if (Options::Common::eol == Options::Common::EOL::windows)
				return chars + (((chars - 1) / Options::Base64::cpl + 1) - 1) * 2;
			else
				return chars + (((chars - 1) / Options::Base64::cpl + 1) - 1);
		}
		else {
			return chars;
		}
	} else {
		char* c = dest;
		int cnt = 0;
		base64_encodestate s;

		base64_init_encodestate(&s);
		cnt = base64_encode_block((const char*)src, len, c, &s, no_linebreaks);
		c += cnt;
		return size_t(cnt + base64_encode_blockend(c, &s));
	}
}

size_t Encode::base64_to_bin(const char* src, unsigned int len, unsigned char* dest)
{
	if(!dest) {
		if(len==0||!src)
			return 0;
		const char* codechar = src;

		size_t i_out=0;
		base64_decodestep step=step_a;
		char fragment;

		switch (step)
		{
			while (1)
			{
		case step_a:
				do {
					if (codechar == (src+len))
						return i_out;
					fragment = (char)base64_decode_value(*codechar++);
				} while (fragment < 0);
		case step_b:
				do {
					if (codechar == (src+len))
						return i_out;
					fragment = (char)base64_decode_value(*codechar++);
				} while (fragment < 0);
				i_out++;
		case step_c:
				do {
					if (codechar == (src+len))
						return i_out;
					fragment = (char)base64_decode_value(*codechar++);
				} while (fragment < 0);
				i_out++;
		case step_d:
				do {
					if (codechar == (src+len))
						return i_out;
					fragment = (char)base64_decode_value(*codechar++);
				} while (fragment < 0);
				i_out++;
			}
		}
		return i_out;

	} else {
		base64_decodestate s;
		int cnt = 0;
		base64_init_decodestate(&s);
		cnt = base64_decode_block(src, len, (char*)dest, &s);
		return size_t(cnt);
	}
}

void Encode::wchar_to_utf8(const wchar_t* i, int i_len, std::string& o)
{
	if (i_len < -1)
		i_len = -1;
	int bytelen = WideCharToMultiByte(CP_UTF8, 0, i, i_len, NULL, 0, NULL, false);
	if (bytelen < 1)
		throw CExc(CExc::Code::utf8conversion);
	o.resize((size_t)bytelen);
	if (!WideCharToMultiByte(CP_UTF8, 0, i, i_len, &o[0], bytelen, NULL, false))
		throw CExc(CExc::Code::utf8conversion);
	if (i_len == -1)
		o.pop_back();
}

void Encode::utf8_to_wchar(const char* i, int i_len, std::wstring& o)
{
	if (i_len < -1)
		i_len = -1;
	int charlen = ::MultiByteToWideChar(CP_UTF8, 0, i, i_len, NULL, 0);
	if(charlen < 1)
		throw CExc(CExc::Code::utf8conversion);
	o.resize((size_t)charlen);
	if (!MultiByteToWideChar(CP_UTF8, 0, i, i_len, &o[0], charlen))
		throw CExc(CExc::Code::utf8conversion);
	if (i_len == -1)
		o.pop_back();
}