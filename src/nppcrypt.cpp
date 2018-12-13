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

#include <string>
#include <fstream>
#include <sstream>
#include <map>
#include "npp/Definitions.h"
#include "nppcrypt.h"
#include "exception.h"
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

typedef std::map<std::wstring, CryptInfo> cryptfilemap;

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
		preferences.save(current);
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

	dlg_random.init(m_hInstance, nppData._nppHandle, IDD_RANDOM, IDC_OK);
	dlg_hash.init(m_hInstance, nppData._nppHandle, IDD_HASH, IDC_OK);
	dlg_crypt.init(m_hInstance, nppData._nppHandle, IDD_CRYPT, IDC_OK);
	dlg_about.init(m_hInstance, nppData._nppHandle, IDD_ABOUT, IDC_OK);
	dlg_preferences.init(m_hInstance, nppData._nppHandle, IDD_PREFERENCES, IDC_OK);
	dlg_auth.init(m_hInstance, nppData._nppHandle, IDD_AUTH, IDC_OK);
	dlg_convert.init(m_hInstance, nppData._nppHandle, IDD_CONVERT, IDC_OK);
	dlg_initdata.init(m_hInstance, nppData._nppHandle, IDD_INITDATA, IDC_OK);

	TCHAR preffile_s[MAX_PATH];
	::SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)preffile_s);
	int preffile_len = lstrlen(preffile_s);
	if (preffile_len + 16 < MAX_PATH) {
		lstrcpy(preffile_s + preffile_len, TEXT("\\nppcrypt.xml"));
		preferences.load(preffile_s, current);
	}
}

extern "C" __declspec(dllexport) BOOL isUnicode()
{
	return TRUE;
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
			std::wstring path, filename, extension;
			helper::Buffer::getPath(notifyCode->nmhdr.idFrom, path, filename, extension);

			if(preferences.files.extension.compare(extension) == 0) {
				::SendMessage(nppData._nppHandle, NPPM_SWITCHTOFILE, 0, (LPARAM)path.c_str());
				HWND hCurScintilla = helper::Scintilla::getCurrent();

				int data_length = (int)::SendMessage(hCurScintilla, SCI_GETLENGTH , 0, 0);
				if (data_length <= 0) {
					throw CExc(CExc::Code::input_null);
				}
				byte* pData = (byte*)::SendMessage(hCurScintilla, SCI_GETCHARACTERPOINTER, 0, 0);
				if (!pData) {
					throw CExc(CExc::Code::unexpected);
				}

				CryptInfo				crypt;
				CryptHeaderReader		header(crypt.options, crypt.hmac);

				if (!header.parse(pData, data_length)) {
					throw CExc(CExc::Code::header_not_found);
				}

				if(crypt.hmac.enable) {
					if (crypt.hmac.keypreset_id < 0) {
						if (!dlg_auth.doDialog()) {
							return;
						}
						crypt.hmac.hash.key.set(dlg_auth.getInput());
						if (!header.checkHMAC()) {
							throw CExc(CExc::Code::hmac_auth_failed);
						}
					} else {
						if (crypt.hmac.keypreset_id >= preferences.getKeyNum()) {
							throw CExc(CExc::Code::invalid_presetkey);
						} else {
							crypt.hmac.hash.key.set(preferences.getKey(crypt.hmac.keypreset_id), 16);
							if (!header.checkHMAC()) {
								throw CExc(CExc::Code::hmac_auth_failed);
							}
						}
					}
				}

				if (dlg_crypt.doDialog(DlgCrypt::Operation::Dec, &crypt, &header.initData().iv, &filename)) {
					std::basic_string<byte> buffer;
					crypt::decrypt(header.getEncrypted(), header.getEncryptedLength(), buffer, crypt.options, header.initData());

					::SendMessage(hCurScintilla, SCI_CLEARALL, 0, 0);
					::SendMessage(hCurScintilla, SCI_APPENDTEXT, buffer.size(), (LPARAM)&buffer[0]);
					::SendMessage(hCurScintilla, SCI_GOTOPOS, 0, 0);
					::SendMessage(hCurScintilla, SCI_EMPTYUNDOBUFFER, 0, 0);
					::SendMessage(hCurScintilla, SCI_SETSAVEPOINT, 0, 0);

					crypt_files.insert(std::pair<std::wstring, CryptInfo>(path, crypt));
				}
			}
		} catch(CExc& exc) {
			helper::Windows::error(nppData._nppHandle, exc.what());
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
				std::wstring path, filename, extension;
				helper::Buffer::getPath(notifyCode->nmhdr.idFrom, path, filename, extension);

				if (preferences.files.extension.compare(extension) == 0) {

					cryptfilemap::iterator	fiter = crypt_files.find(path);
					CryptInfo& crypt = (fiter != crypt_files.end()) ? fiter->second : current.crypt;

					::SendMessage(nppData._nppHandle, NPPM_SWITCHTOFILE, 0, (LPARAM)path.c_str());
					HWND hCurScintilla = helper::Scintilla::getCurrent();

					int data_length = (int)::SendMessage(hCurScintilla, SCI_GETLENGTH , 0, 0);
					if (data_length <= 0) {
						throw CExc(CExc::Code::input_null);
					}

					byte* pData = (byte*)::SendMessage(hCurScintilla, SCI_GETCHARACTERPOINTER , 0, 0);
					if (!pData) {
						throw CExc(CExc::Code::unexpected);
					}

					CryptHeaderWriter		header(crypt.options, crypt.hmac);
					std::basic_string<byte>	buffer;
					bool					autoencrypt = false;

					if(fiter != crypt_files.end()) {					
						if(preferences.files.askonsave)	{
							std::wstring asksave_msg;
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
							crypt::encrypt(pData, data_length, buffer, crypt.options, header.initData());
							header.create(&buffer[0], buffer.size());
						}
					}						
					if(!autoencrypt) {
						int encoding = (int)::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, notifyCode->nmhdr.idFrom, 0);
						bool no_ascii = (encoding != uni8Bit && encoding != uniUTF8 && encoding != uniCookie) ? true : false;

						if(dlg_crypt.doDialog(DlgCrypt::Operation::Enc, &crypt, &header.initData().iv, &filename)) {
							crypt::encrypt(pData, data_length, buffer, crypt.options, header.initData());
							header.create(&buffer[0], buffer.size());
							if(fiter == crypt_files.end()) {
								crypt_files.insert(std::pair<std::wstring, CryptInfo>(path, crypt));
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
			helper::Windows::error(nppData._nppHandle, exc.what());
		} catch(...) {
			::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
		}
		break;
	}
	case NPPN_FILEBEFORECLOSE:
	{
		std::wstring path, filename, extension;
		helper::Buffer::getPath(notifyCode->nmhdr.idFrom, path, filename, extension);
		if (preferences.files.extension.compare(extension) == 0) {
			crypt_files.erase(path);
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
		CryptHeaderWriter			header(current.crypt.options, current.crypt.hmac);

		if(dlg_crypt.doDialog(DlgCrypt::Operation::Enc, &current.crypt, &header.initData().iv)) {			
			std::basic_string<byte>		buffer;

			crypt::encrypt(pData, data_length, buffer, current.crypt.options, header.initData());
			header.create(&buffer[0], buffer.size());

			HWND hCurScintilla = helper::Scintilla::getCurrent();
			::SendMessage(hCurScintilla, SCI_BEGINUNDOACTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_TARGETFROMSELECTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_REPLACETARGET, header.size(), (LPARAM)header.c_str());
			::SendMessage(hCurScintilla, SCI_SETSEL, sel_start + header.size(), sel_start + header.size());
			::SendMessage(hCurScintilla, SCI_TARGETFROMSELECTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_REPLACETARGET, buffer.size(), (LPARAM)&buffer[0]);	
			::SendMessage(hCurScintilla, SCI_SETSEL, sel_start, sel_start + header.size() +buffer.size());
			::SendMessage(hCurScintilla, SCI_ENDUNDOACTION, 0, 0);

			current.crypt.options.password.clear();
		}
	} catch (CExc& exc) {
		helper::Windows::error(nppData._nppHandle, exc.what());
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

		CryptHeaderReader	header(current.crypt.options, current.crypt.hmac);		

		/* parse header and check hmac if present */
		if (header.parse(pData, data_length)) {
			if (current.crypt.hmac.enable) {
				if (current.crypt.hmac.keypreset_id < 0) {
					if (!dlg_auth.doDialog()) {
						return;
					}
					current.crypt.hmac.hash.key.set(dlg_auth.getInput());
					if (!header.checkHMAC()) {
						throw CExc(CExc::Code::hmac_auth_failed);
					}
				} else {
					if (current.crypt.hmac.keypreset_id >= preferences.getKeyNum()) {
						throw CExc(CExc::Code::invalid_presetkey);
					} else {
						current.crypt.hmac.hash.key.set(preferences.getKey(current.crypt.hmac.keypreset_id), 16);
						if (!header.checkHMAC()) {
							throw CExc(CExc::Code::hmac_auth_failed);
						}
					}
				}
			}
		}

		if(dlg_crypt.doDialog(DlgCrypt::Operation::Dec, &current.crypt, &header.initData().iv)) {
			crypt::InitData& s_init = header.initData();

			/* check if salt or tag data is mising */
			size_t need_salt_len = (current.crypt.options.key.salt_bytes > 0 && s_init.salt.size() != current.crypt.options.key.salt_bytes) ? current.crypt.options.key.salt_bytes : 0;
			size_t need_tag_len = 0;
			if (current.crypt.options.mode == crypt::Mode::gcm && s_init.tag.size() != crypt::Constants::gcm_tag_size) {
				need_tag_len = crypt::Constants::gcm_tag_size;
			}
			if (current.crypt.options.mode == crypt::Mode::ccm && s_init.tag.size() != crypt::Constants::ccm_tag_size) {
				need_tag_len = crypt::Constants::gcm_tag_size;
			}
			if (current.crypt.options.mode == crypt::Mode::eax && s_init.tag.size() != crypt::Constants::eax_tag_size) {
				need_tag_len = crypt::Constants::gcm_tag_size;
			}
			if (need_salt_len > 0 || need_tag_len > 0) {
				if (!dlg_initdata.doDialog(&s_init, need_salt_len, need_tag_len)) {
					return;
				}
			}

			std::basic_string<byte>	buffer;
			decrypt(header.getEncrypted(), header.getEncryptedLength(), buffer, current.crypt.options, s_init);
			helper::Scintilla::replaceSelection(buffer);

			current.crypt.options.password.clear();
		}
	} catch(CExc& exc) {
		helper::Windows::error(nppData._nppHandle, exc.what());
	} catch(...) {
		::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
	}
}

void HashDlg()
{
	try	{
		dlg_hash.doDialog();
	} catch (CExc& exc) {
		helper::Windows::error(nppData._nppHandle, exc.what());
	} catch (...) {
		::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
	}
}

void RandomDlg()
{
	try	{
		dlg_random.doDialog();
	} catch (CExc& exc) {
		helper::Windows::error(nppData._nppHandle, exc.what());
	} catch (...) {
		::MessageBox(nppData._nppHandle, TEXT("Unkown exception!"), TEXT("Error"), MB_OK);
	}
}

void ConvertDlg()
{
	try	{
		if (helper::Scintilla::getSelectionLength()) {
			dlg_convert.doDialog();
		}
	} catch (CExc& exc) {
		helper::Windows::error(nppData._nppHandle, exc.what());
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
