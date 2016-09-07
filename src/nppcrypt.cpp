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

#include <string>
#include <fstream>
#include <sstream>
#include <map>
#include "npp\Definitions.h"
#include "nppcrypt.h"
#include "exception.h"
#include "unicode.h"
#include "preferences.h"
#include "crypt.h"
#include "dlg_crypt.h"
#include "dlg_hash.h"
#include "dlg_random.h"
#include "dlg_about.h"
#include "dlg_preferences.h"
#include "dlg_auth.h"
#include "dlg_convert.h"
#include "dlg_initdata.h"
#include "cryptheader.h"
#include "resource.h"
#include "help.h"

typedef std::map<string, crypt::Options::Crypt> cryptfilemap;

const TCHAR				NPP_PLUGIN_NAME[] = TEXT(NPPC_NAME);
const int				NPPCRYPT_VERSION = NPPC_VERSION;

FuncItem				funcItem[NPPC_FUNC_COUNT];
NppData					nppData;
HINSTANCE				m_hInstance;
CurrentOptions			current;
cryptfilemap			crypt_files;
bool					UndoFileEncryption = false;

DlgCrypt				dlg_crypt;
DlgHash					dlg_hash(current.hash);
DlgRandom				dlg_random(current.random);
DlgAuth					dlg_auth;
DlgPreferences			dlg_preferences;
DlgAbout				dlg_about;
DlgConvert				dlg_convert(current.convert);
DlgInitdata				dlg_initdata;


BOOL APIENTRY DllMain( HANDLE hModule, DWORD reasonForCall, LPVOID lpReserved )
{
	switch (reasonForCall)
    {
	case DLL_PROCESS_ATTACH:
	{
		#ifdef _DEBUG
		_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
		#endif
		m_hInstance = (HINSTANCE)hModule;
		break;
	}
	case DLL_PROCESS_DETACH:
	{
		try {
			preferences.save(current);
		} catch (CExc& exc) {
			::MessageBox(nppData._nppHandle, exc.getMsg(), TEXT("nppcrypt error"), MB_OK);
		}
		dlg_random.destroy();
		dlg_hash.destroy();
		dlg_crypt.destroy();
		dlg_about.destroy();
		dlg_preferences.destroy();
		dlg_auth.destroy();
		dlg_convert.destroy();
		dlg_initdata.destroy();
		break;
	}
	case DLL_THREAD_ATTACH:
	{
		break;
	}
	case DLL_THREAD_DETACH:
	{
		break;
	}
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void setInfo(NppData notpadPlusData)
{
	nppData = notpadPlusData;

	helper::NPP::setCommand(0, TEXT("Encrypt"), EncryptDlg, NULL, false);
	helper::NPP::setCommand(1, TEXT("Decrypt"), DecryptDlg, NULL, false);
	helper::NPP::setCommand(2, TEXT("Hash"), HashDlg, NULL, false);
	helper::NPP::setCommand(3, TEXT("Random"), RandomDlg, NULL, false);
	helper::NPP::setCommand(4, TEXT("Convert"), ConvertDlg, NULL, false);
	helper::NPP::setCommand(5, TEXT("---"), NULL, NULL, false);
	helper::NPP::setCommand(6, TEXT("Preferences"), PreferencesDlg, NULL, false);
	helper::NPP::setCommand(7, TEXT("---"), NULL, NULL, false);
	helper::NPP::setCommand(8, TEXT("About"), AboutDlg, NULL, false);

	dlg_random.init(m_hInstance, nppData._nppHandle);
	dlg_hash.init(m_hInstance, nppData._nppHandle);
	dlg_crypt.init(m_hInstance, nppData._nppHandle, IDD_CRYPT, IDC_OK);
	dlg_about.init(m_hInstance, nppData._nppHandle, IDD_ABOUT, IDC_OK);
	dlg_preferences.init(m_hInstance, nppData._nppHandle, IDD_PREFERENCES, IDC_OK);
	dlg_auth.init(m_hInstance, nppData._nppHandle, IDD_AUTH, IDC_OK);
	dlg_convert.init(m_hInstance, nppData._nppHandle);
	dlg_initdata.init(m_hInstance, nppData._nppHandle, IDD_INITDATA, IDC_OK);

	TCHAR preffile_s[MAX_PATH];
	::SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)preffile_s);
	int preffile_len = lstrlen(preffile_s);
	if (preffile_len + 16 < MAX_PATH) {
		lstrcpy(preffile_s + preffile_len, TEXT("\\nppcrypt.conf"));
		try {
			preferences.load(preffile_s, current);
		} catch (CExc& exc) {
			if (exc.getCode() != CExc::Code::preffile_missing) {
				::MessageBox(nppData._nppHandle, exc.getMsg(), TEXT("nppcrypt error"), MB_OK);
			}
		}
	}
}

extern "C" __declspec(dllexport) BOOL isUnicode()
{
	#ifdef UNICODE
	return TRUE;
	#else
	return FALSE;
	#endif
}

extern "C" __declspec(dllexport) const TCHAR * getName()
{
	return NPP_PLUGIN_NAME;
}

extern "C" __declspec(dllexport) FuncItem * getFuncsArray(int *nbF)
{
	*nbF = int(NPPC_FUNC_COUNT);
	return funcItem;
}

extern "C" __declspec(dllexport) LRESULT messageProc(UINT Message, WPARAM wParam, LPARAM lParam)
{
	return TRUE;
}

extern "C" __declspec(dllexport) void beNotified(SCNotification *notifyCode)
{
	switch (notifyCode->nmhdr.code) 
	{
	case NPPN_FILEOPENED:
	{
		if (!preferences.files.enable) {
			return;
		}
		try {
			string path, filename, extension;
			helper::Buffer::getPath(notifyCode->nmhdr.idFrom, path, filename, extension);

			if(preferences.files.extension.compare(extension) == 0) {
				::SendMessage(nppData._nppHandle, NPPM_SWITCHTOFILE, 0, (LPARAM)path.c_str());
				HWND hCurScintilla = helper::Scintilla::getCurrent();

				int data_length = (int)::SendMessage(hCurScintilla, SCI_GETLENGTH , 0, 0);
				if (data_length <= 0) {
					throw CExc(CExc::Code::file_empty);
				}

				crypt::Options::Crypt	options;
				byte*					pData = (byte*)::SendMessage(hCurScintilla, SCI_GETCHARACTERPOINTER , 0, 0);
				CryptHeaderReader		header(options);

				if (!header.parse(pData, data_length)) {
					throw CExc(CExc::Code::parse_header);
				}

				if(options.hmac.enable) {
					crypt::Options::Crypt::HMAC hmac = options.hmac;
					if (hmac.key_id == -1) {
						if (!dlg_auth.doDialog()) {
							return;
						}
						dlg_auth.getKeyString(hmac.key_input);
					}
					helper::BC::prepareHMAC(hmac, header.getVersion());
					std::string s_hmac_cmp;
					crypt::hmac_header(header.body(), header.body_size(), header.cdata(), header.cdata_size(), hmac, s_hmac_cmp);
					if (!header.checkHMAC(s_hmac_cmp)) {
						throw CExc(CExc::Code::authentication);
					}
				}

				int encoding = (int)::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, notifyCode->nmhdr.idFrom, 0);
				bool no_ascii = (encoding != uni8Bit && encoding != uniUTF8 && encoding != uniCookie) ? true : false;

				if(dlg_crypt.doDialog(DlgCrypt::Operation::Dec, &options, no_ascii, &filename)) {
					std::basic_string<byte> buffer;
					helper::BC::preparePassword(options.password, header.getVersion());
					crypt::decrypt(header.cdata(), header.cdata_size(), buffer, options, header.init_strings());

					::SendMessage(hCurScintilla, SCI_CLEARALL, 0, 0);
					::SendMessage(hCurScintilla, SCI_APPENDTEXT, buffer.size(), (LPARAM)&buffer[0]);
					::SendMessage(hCurScintilla, SCI_GOTOPOS, 0, 0);
					::SendMessage(hCurScintilla, SCI_EMPTYUNDOBUFFER, 0, 0);
					::SendMessage(hCurScintilla, SCI_SETSAVEPOINT, 0, 0);

					crypt_files.insert(std::pair<string, crypt::Options::Crypt>(path, options));
				}
			}
		} catch(CExc& exc) {
			::MessageBox(nppData._nppHandle, exc.getMsg(), TEXT("Error"), MB_OK);
		} catch(...) {
			::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
		}
		break;
	}
	/* Why NPPN_FILESAVED instead of NPPN_FILEBEFORESAVE thus effectivly saving the file twice? 
		Because if the user chooses "save as" there is no way of knowing the new filename in NPPN_FILEBEFORESAVE 
		Btw: "Save a Copy as..." does trigger neither NPPN_FILESAVED nor NPPN_FILEBEFORESAVE. same goes for automatic backup saves.*/
	case NPPN_FILESAVED: case NPPN_FILERENAMED:
	{
		try	{
			if (!preferences.files.enable) {
				return;
			}

			if (UndoFileEncryption) {
				HWND hCurScintilla = helper::Scintilla::getCurrent();
				::SendMessage(hCurScintilla, SCI_UNDO, 0, 0);
				::SendMessage(hCurScintilla, SCI_GOTOPOS, 0, 0);
				::SendMessage(hCurScintilla, SCI_EMPTYUNDOBUFFER, 0, 0);
				::SendMessage(hCurScintilla, SCI_SETSAVEPOINT, 0, 0);
				UndoFileEncryption = false;
			} else {
				string path, filename, extension;
				helper::Buffer::getPath(notifyCode->nmhdr.idFrom, path, filename, extension);

				if (preferences.files.extension.compare(extension) == 0) {
					cryptfilemap::iterator fiter = crypt_files.find(path);
					crypt::Options::Crypt& options = (fiter != crypt_files.end()) ? fiter->second : current.crypt;

					::SendMessage(nppData._nppHandle, NPPM_SWITCHTOFILE, 0, (LPARAM)path.c_str());
					HWND hCurScintilla = helper::Scintilla::getCurrent();

					int data_length = (int)::SendMessage(hCurScintilla, SCI_GETLENGTH , 0, 0);
					if (data_length <= 0) {
						throw CExc(CExc::Code::file_empty);
					}

					byte* pData = (byte*)::SendMessage(hCurScintilla, SCI_GETCHARACTERPOINTER , 0, 0);
					if (!pData) {
						throw CExc(CExc::File::nppcrypt, __LINE__);
					}

					CryptHeaderWriter		header(options);
					std::basic_string<byte>	buffer;
					bool					autoencrypt = false;

					if(fiter != crypt_files.end()) {					
						if(preferences.files.askonsave)	{
							string	asksave_msg;
							if (filename.size() > 32) {
								asksave_msg = TEXT("change encryption of ") + filename.substr(0,32) + TEXT("...?");
							} else {
								asksave_msg = TEXT("change encryption of ") + filename + TEXT("?");
							}
							if (::MessageBox(nppData._nppHandle, asksave_msg.c_str(), TEXT("nppcrypt"), MB_YESNO | MB_ICONQUESTION) != IDYES) {
								autoencrypt = true;
							}
						} else {
							autoencrypt = true;
						}
						if(autoencrypt)	{
							helper::BC::preparePassword(options.password, NPPCRYPT_VERSION);
							crypt::encrypt(pData, data_length, buffer, options, header.init_strings());
							header.create();
							if(options.hmac.enable)	{
								std::string s_hmac;
								helper::BC::prepareHMAC(options.hmac, NPPCRYPT_VERSION);
								crypt::hmac_header(header.body(), header.body_size(), &buffer[0], buffer.size(), options.hmac, s_hmac);
								header.updateHMAC(s_hmac);
							}
						}
					}						
					if(!autoencrypt) {
						int encoding = (int)::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, notifyCode->nmhdr.idFrom, 0);
						bool no_ascii = (encoding != uni8Bit && encoding != uniUTF8 && encoding != uniCookie) ? true : false;

						if(dlg_crypt.doDialog(DlgCrypt::Operation::Enc, &options, no_ascii, &filename)) {
							helper::BC::preparePassword(options.password, NPPCRYPT_VERSION);
							crypt::encrypt(pData, data_length, buffer, options, header.init_strings());
							header.create();
							if(options.hmac.enable) {
								std::string s_hmac;
								helper::BC::prepareHMAC(options.hmac, NPPCRYPT_VERSION);
								crypt::hmac_header(header.body(), header.body_size(), &buffer[0], buffer.size(), options.hmac, s_hmac);
								header.updateHMAC(s_hmac);
							}
							if(fiter!=crypt_files.end()) {
								crypt_files.insert(std::pair<string, crypt::Options::Crypt>(path, current.crypt));
							}
						} else {
							return;
						}
					}
					::SendMessage(hCurScintilla, SCI_BEGINUNDOACTION, 0, 0);
					::SendMessage(hCurScintilla, SCI_CLEARALL, 0, 0);
					::SendMessage(hCurScintilla, SCI_APPENDTEXT, header.size(), (LPARAM)header.c_str());
					::SendMessage(hCurScintilla, SCI_APPENDTEXT, buffer.size(), (LPARAM)&buffer[0]);
					::SendMessage(hCurScintilla, SCI_ENDUNDOACTION, 0, 0);

					UndoFileEncryption = true;
					::SendMessage(nppData._nppHandle, NPPM_SAVECURRENTFILE, 0, 0);
				}
			}
		} catch(CExc& exc) {
			::MessageBox(nppData._nppHandle, exc.getMsg(), TEXT("Error"), MB_OK);
		} catch(...) {
			::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
		}
		break;
	}
	}
}

// ====================================================================================================================================================================

void EncryptDlg()
{
	try {
		const byte*	pData;
		size_t		data_length;
		size_t		sel_start;

		if (!helper::Scintilla::getSelection(&pData, &data_length, &sel_start)) {
			return;
		}
	
		if(dlg_crypt.doDialog(DlgCrypt::Operation::Enc, &current.crypt, helper::Buffer::isCurrent8Bit())) {
			CryptHeaderWriter			header(current.crypt);
			std::basic_string<byte>		buffer;

			helper::BC::preparePassword(current.crypt.password, NPPCRYPT_VERSION);
			crypt::encrypt(pData, data_length, buffer, current.crypt, header.init_strings());

			header.create();
			if(current.crypt.hmac.enable) {
				helper::BC::prepareHMAC(current.crypt.hmac, NPPCRYPT_VERSION);
				std::string s_hmac;
				crypt::hmac_header(header.body(), header.body_size(), &buffer[0], buffer.size(), current.crypt.hmac, s_hmac);
				header.updateHMAC(s_hmac);
			}

			HWND hCurScintilla = helper::Scintilla::getCurrent();
			::SendMessage(hCurScintilla, SCI_BEGINUNDOACTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_TARGETFROMSELECTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_REPLACETARGET, header.size(), (LPARAM)header.c_str());
			::SendMessage(hCurScintilla, SCI_SETSEL, sel_start + header.size(), sel_start + header.size());
			::SendMessage(hCurScintilla, SCI_TARGETFROMSELECTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_REPLACETARGET, buffer.size(), (LPARAM)&buffer[0]);	
			::SendMessage(hCurScintilla, SCI_SETSEL, sel_start, sel_start + header.size() +buffer.size());
			::SendMessage(hCurScintilla, SCI_ENDUNDOACTION, 0, 0);

			for (size_t i = 0; i < current.crypt.password.size(); i++) {
				current.crypt.password[i] = 0;
			}
			current.crypt.password.clear();
		}
	} catch (CExc& exc) {
		::MessageBox(nppData._nppHandle, exc.getMsg(), TEXT("Error"), MB_OK);
	} catch (...) {
		::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
	}
}

void DecryptDlg()
{
	try
	{
		const byte*	pData;
		size_t		data_length;
		size_t		sel_start;

		if (!helper::Scintilla::getSelection(&pData, &data_length, &sel_start)) {
			return;
		}
		CryptHeaderReader	header(current.crypt);
		bool				found_header = header.parse(pData, data_length);
		if(found_header && current.crypt.hmac.enable) {
			crypt::Options::Crypt::HMAC hmac = current.crypt.hmac;
			if(hmac.key_id == -1) {
				if (!dlg_auth.doDialog()) {
					return;
				}
				dlg_auth.getKeyString(hmac.key_input);
			}
			helper::BC::prepareHMAC(hmac, header.getVersion());
			std::string s_hmac_cmp;
			crypt::hmac_header((const char*)header.body(), header.body_size(), header.cdata(), header.cdata_size(), hmac, s_hmac_cmp);
			if (!header.checkHMAC(s_hmac_cmp)) {
				throw CExc(CExc::Code::authentication);
			}
		}

		if(dlg_crypt.doDialog(DlgCrypt::Operation::Dec, &current.crypt, helper::Buffer::isCurrent8Bit()))	{
			crypt::InitStrings& s_init = header.init_strings();
			bool need_salt = (current.crypt.key.salt_bytes > 0 && s_init.salt.size() == 0);
			bool need_iv = (current.crypt.iv == crypt::IV::random && s_init.iv.size() == 0);
			bool need_tag = ((current.crypt.mode == crypt::Mode::gcm || current.crypt.mode == crypt::Mode::ccm || current.crypt.mode == crypt::Mode::eax) && s_init.tag.size() == 0);
			if (need_salt || need_iv || need_tag) {
				if (!dlg_initdata.doDialog(&s_init, need_salt, need_iv, need_tag)) {
					return;
				}
			}

			std::basic_string<byte>	buffer;
			helper::BC::preparePassword(current.crypt.password, header.getVersion());
			decrypt(header.cdata(), header.cdata_size(), buffer, current.crypt, header.init_strings());
			helper::Scintilla::replaceSelection(buffer);

			for (size_t i = 0; i < current.crypt.password.size(); i++) {
				current.crypt.password[i] = 0;
			}
			current.crypt.password.clear();
		}
	} catch(CExc& exc) {
		::MessageBox(nppData._nppHandle, exc.getMsg(), TEXT("Error"), MB_OK);
	} catch(...) {
		::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
	}
}

void HashDlg()
{
	try	{
		if (!dlg_hash.isCreated()) {
			tTbData	data = { 0 };
			dlg_hash.create(&data);
			data.uMask = DWS_DF_FLOATING;
			data.pszModuleName = dlg_hash.getPluginFileName();
			data.dlgID = NPPC_FUNC_HASH_ID;
			::SendMessage(nppData._nppHandle, NPPM_DMMREGASDCKDLG, 0, (LPARAM)&data);
		}
		dlg_hash.display();
	} catch (CExc& exc) {
		::MessageBox(nppData._nppHandle, exc.getMsg(), TEXT("Error"), MB_OK);
	} catch (...) {
		::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
	}
}

void RandomDlg()
{
	try	{
		if (!dlg_random.isCreated()) {
			tTbData	data = { 0 };
			dlg_random.create(&data);
			data.uMask = DWS_DF_FLOATING;
			data.pszModuleName = dlg_random.getPluginFileName();
			data.dlgID = NPPC_FUNC_RANDOM_ID;
			::SendMessage(nppData._nppHandle, NPPM_DMMREGASDCKDLG, 0, (LPARAM)&data);
		}
		dlg_random.display();
	} catch (CExc& exc) {
		::MessageBox(nppData._nppHandle, exc.getMsg(), TEXT("Error"), MB_OK);
	} catch (...) {
		::MessageBox(nppData._nppHandle, TEXT("Unkown exception!"), TEXT("Error"), MB_OK);
	}
}

void ConvertDlg()
{
	try	{
		if (!dlg_convert.isCreated()) {
			tTbData	data = { 0 };
			dlg_convert.create(&data);
			data.uMask = DWS_DF_FLOATING;
			data.pszModuleName = dlg_convert.getPluginFileName();
			data.dlgID = NPPC_FUNC_CONVERT_ID;
			::SendMessage(nppData._nppHandle, NPPM_DMMREGASDCKDLG, 0, (LPARAM)&data);
		}
		dlg_convert.display();
	} catch (CExc& exc) {
		::MessageBox(nppData._nppHandle, exc.getMsg(), TEXT("Error"), MB_OK);
	} catch (...) {
		::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
	}
}

void PreferencesDlg()
{
	dlg_preferences.doDialog();
}

void AboutDlg()
{
	dlg_about.doDialog();
}
