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

#include "nppcrypt.h"
#include "header.h"

FuncItem				funcItem[8];
NppData					nppData;
HINSTANCE				m_hInstance;

// dialog-objects:
DlgCrypt&				dlg_crypt = DlgCrypt::Instance();
DlgHash&				dlg_hash = DlgHash::Instance();
DlgRandom&				dlg_random = DlgRandom::Instance();
DlgAuth&				dlg_auth = DlgAuth::Instance();
DlgPreferences&			dlg_preferences = DlgPreferences::Instance();
DlgAbout&				dlg_about = DlgAbout::Instance();

// to store the current (last used) options for encryption etc.:
namespace current 
{
	NppCryptOptions			crypt;
	crypt::Options::Hash	hash;
	crypt::Options::Random	random;
}

// map to store information about opened nppcrypt-files. (to allow saving without user input):
std::map<string , NppCryptOptions> crypt_files;
bool UndoFileEncryption = false;

// encodings enum (from Parameters.h):
enum UniMode { uni8Bit = 0, uniUTF8 = 1, uni16BE = 2, uni16LE = 3, uniCookie = 4, uni7Bit = 5, uni16BE_NoBOM = 6, uni16LE_NoBOM = 7, uniEnd };

// ====================================================================================================================================================================
// ====================================================================================================================================================================

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  reasonForCall, 
                       LPVOID lpReserved )
{
	switch (reasonForCall)
    {
		case DLL_PROCESS_ATTACH:
			#ifdef _DEBUG
			_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
			#endif

			m_hInstance = (HINSTANCE)hModule;
			break;

		case DLL_PROCESS_DETACH:
			// save current preferences:
			if(!preferences.save(current::crypt, current::hash, current::random))
				::MessageBox(nppData._nppHandle, TEXT("failed to save preferences!"), TEXT("nppcrypt error"), MB_OK);
			// destroy windows
			dlg_random.destroy();
			dlg_hash.destroy();
			dlg_crypt.destroy();
			dlg_about.destroy();
			dlg_preferences.destroy();
			dlg_auth.destroy();
			break;

		case DLL_THREAD_ATTACH:
			break;

		case DLL_THREAD_DETACH:
			break;
    }

    return TRUE;
}

// ====================================================================================================================================================================

extern "C" __declspec(dllexport) void setInfo(NppData notpadPlusData)
{
	nppData = notpadPlusData;

	// init menu commands
	help::setCommand(0, TEXT("Encrypt"), EncryptDlg, NULL, false);
	help::setCommand(1, TEXT("Decrypt"), DecryptDlg, NULL, false);
	help::setCommand(2, TEXT("Hash"), HashDlg, NULL, false);
	help::setCommand(3, TEXT("Random"), RandomDlg, NULL, false);
	help::setCommand(4, TEXT("---"), NULL, NULL, false);
	help::setCommand(5, TEXT("Preferences"), PreferencesDlg, NULL, false);
	help::setCommand(6, TEXT("---"), NULL, NULL, false);
	help::setCommand(7, TEXT("About"), AboutDlg, NULL, false);

	// initialize dialogs
	dlg_random.init(m_hInstance, nppData._nppHandle, &current::random);
	dlg_hash.init(m_hInstance, nppData._nppHandle, &current::hash);
	dlg_crypt.init(m_hInstance, nppData._nppHandle);
	dlg_about.init(m_hInstance, nppData._nppHandle);
	dlg_preferences.init(m_hInstance, nppData._nppHandle);
	dlg_auth.init(m_hInstance, nppData._nppHandle);

	// get path of config-file and load preferances
	// (no error-msg on fail because it could be the first start)
	TCHAR configFile[MAX_PATH];
	::SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)configFile);
	int tlen = lstrlen(configFile);
	for(int i=0; i< tlen; i++)
		if(configFile[i] == '\\')
			configFile[i] = '/';
	lstrcpy(configFile+tlen, TEXT("/nppcrypt.conf"));
	preferences.load(configFile, current::crypt, current::hash, current::random);
}

// ====================================================================================================================================================================

extern "C" __declspec(dllexport) const TCHAR * getName()
{
	return NPP_PLUGIN_NAME;
}

// ====================================================================================================================================================================

extern "C" __declspec(dllexport) FuncItem * getFuncsArray(int *nbF)
{
	*nbF = 8;
	return funcItem;
}

// ====================================================================================================================================================================

extern "C" __declspec(dllexport) void beNotified(SCNotification *notifyCode)
{
	switch (notifyCode->nmhdr.code) 
	{
		// ------------------------------------------------------------------------------------------------------------------------------------------------------------
		// ------------------------------------------------------------------------------------------------------------------------------------------------------------
		case NPPN_FILEOPENED:
		{
			if(!preferences.files.enable)
				return;

			try 
			{
				string path;
				string filename;
				string extension;

				help::getPath(notifyCode->nmhdr.idFrom, path, filename, extension);

				if(preferences.files.extension.compare(extension) == 0) 
				{
					::SendMessage(nppData._nppHandle, NPPM_SWITCHTOFILE, 0, (LPARAM)path.c_str());
					HWND hCurScintilla = help::getCurScintilla();

					int data_length = ::SendMessage(hCurScintilla, SCI_GETLENGTH , 0, 0);
					if(!data_length)
						throw CExc(CExc::Code::file_empty);

					NppCryptOptions	options;
					unsigned char*	pData = (unsigned char*)::SendMessage(hCurScintilla, SCI_GETCHARACTERPOINTER , 0, 0);
					HeaderReader	header(options);

					if(!header.parse(pData, data_length))
						throw CExc(CExc::Code::parse_header);

					// ------------ hmac check
					if(options.hmac.enable) 
					{
						if (options.hmac.key_id == -1)
						{
							if (!dlg_auth.doDialog())
								return;
							dlg_auth.getKeyString(options.hmac.key_input);
						}
						options.setupHMAC(header.getVersion());
						std::string s_hmac_cmp;
						crypt::hmac_header(header.body(), header.body_size(), header.cdata(), header.cdata_size(), options.hmac.hash, &options.hmac.key[0], options.hmac.key.size(), s_hmac_cmp);
						if(!header.checkHMAC(s_hmac_cmp))
							throw CExc(CExc::Code::authentication);
					}

					int encoding = ::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, notifyCode->nmhdr.idFrom, 0);
					bool no_ascii = (encoding != uni8Bit && encoding != uniUTF8 && encoding != uniCookie) ? true : false;

					// ------------ dialog
					if(dlg_crypt.doDialog(DlgCrypt::Decryption, &options, no_ascii, filename.c_str()))
					{
						// --------- decrypt data
						std::vector<unsigned char> buffer;
						options.setupPassword(header.getVersion());
						crypt::decrypt(header.cdata(), header.cdata_size(), buffer, options, header.init_strings());

						// --------- replace text with decrypted data
						::SendMessage(hCurScintilla, SCI_CLEARALL, 0, 0);
						::SendMessage(hCurScintilla, SCI_APPENDTEXT, buffer.size(), (LPARAM)&buffer[0]);
						::SendMessage(hCurScintilla, SCI_GOTOPOS, 0, 0);
						::SendMessage(hCurScintilla, SCI_EMPTYUNDOBUFFER, 0, 0);
						::SendMessage(hCurScintilla, SCI_SETSAVEPOINT, 0, 0);

						// --------- save current NppOptions for automatic save without user input.
						crypt_files.insert(std::pair<string, NppCryptOptions>(path, options));
					}
				}
			} catch(CExc& exc) {
				::MessageBox(nppData._nppHandle, exc.getErrorMsg(), TEXT("Error"), MB_OK);
			} catch(...) {
				::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
			}
		} break;

		// ------------------------------------------------------------------------------------------------------------------------------------------------------------
		// ------------------------------------------------------------------------------------------------------------------------------------------------------------

		/* Why NPPN_FILESAVED instead of NPPN_FILEBEFORESAVE thus effectivly saving the file twice? 
		   Because if the user chooses "save as" there is no way of knowing the new filename in NPPN_FILEBEFORESAVE 
		   Btw: "Save a Copy as..." does trigger neither NPPN_FILESAVED nor NPPN_FILEBEFORESAVE. same goes for automatic backup saves.*/

		case NPPN_FILESAVED: 
		{				
			try
			{
				if (!preferences.files.enable)
					return;

				if (UndoFileEncryption) 
				{
					// --------- after the encrypted file was saved: undo everthing. (maybe SCI_EMPTYUNDOBUFFER should be optional)
					HWND hCurScintilla = help::getCurScintilla();
					::SendMessage(hCurScintilla, SCI_UNDO, 0, 0);
					::SendMessage(hCurScintilla, SCI_GOTOPOS, 0, 0);
					::SendMessage(hCurScintilla, SCI_EMPTYUNDOBUFFER, 0, 0);
					::SendMessage(hCurScintilla, SCI_SETSAVEPOINT, 0, 0);
					UndoFileEncryption = false;
				}
				else 
				{
					string path;
					string filename;
					string extension;

					help::getPath(notifyCode->nmhdr.idFrom, path, filename, extension);

					if (preferences.files.extension.compare(extension) == 0)
					{
						std::map<string, NppCryptOptions>::iterator fiter = crypt_files.find(path);
						NppCryptOptions& options = (fiter != crypt_files.end()) ? fiter->second : current::crypt;

						// --------- switch to file and get scintilla-handle
						::SendMessage(nppData._nppHandle, NPPM_SWITCHTOFILE, 0, (LPARAM)path.c_str());
						HWND hCurScintilla = help::getCurScintilla();

						int data_length = ::SendMessage(hCurScintilla, SCI_GETLENGTH , 0, 0);
						if(!data_length)
							throw CExc(CExc::Code::file_empty);

						// --------- get pointer to data
						unsigned char* pData = (unsigned char*)::SendMessage(hCurScintilla, SCI_GETCHARACTERPOINTER , 0, 0);
						if(!pData)
							throw CExc(CExc::File::nppcrypt, __LINE__);

						HeaderWriter header(options);
						std::vector<unsigned char>	buffer;

						// --------------------------------- auto-encrypt is possible
						if(fiter != crypt_files.end()) 
						{
							bool autoencrypt=false;

							if(preferences.files.askonsave)
							{
								string msg = TEXT("change encryption of ") + filename + TEXT("?");

								if(::MessageBox(nppData._nppHandle, msg.c_str(), TEXT("nppcrypt"), MB_YESNO|MB_ICONQUESTION)!=IDYES)
									autoencrypt = true;
							} else {
								autoencrypt = true;
							}

							if(autoencrypt)
							{
								options.setupPassword(NPPCRYPT_VERSION);
								crypt::encrypt(pData, data_length, buffer, options, header.init_strings());
								header.create();

								if(options.hmac.enable)
								{
									std::string s_hmac;
									options.setupHMAC(NPPCRYPT_VERSION);
									crypt::hmac_header(header.body(), header.body_size(), &buffer[0], buffer.size(), fiter->second.hmac.hash, &options.hmac.key[0], options.hmac.key.size(), s_hmac);
									header.updateHMAC(s_hmac);
								}
							}
						}						
						
						// --------- no encrypted data yet therefore crypt dialog is needed:
						if(!buffer.size())
						{
							int encoding = ::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, notifyCode->nmhdr.idFrom, 0);
							bool no_ascii = (encoding != uni8Bit && encoding != uniUTF8 && encoding != uniCookie) ? true : false;

							if(dlg_crypt.doDialog(DlgCrypt::Encryption, &options, no_ascii, filename.c_str()))
							{
								// --------- encrypt data and setup header-string
								options.setupPassword(NPPCRYPT_VERSION);
								crypt::encrypt(pData, data_length, buffer, options, header.init_strings());
								header.create();

								// --------- if activated: create hmac and insert copy it into the header
								if(options.hmac.enable) {
									std::string s_hmac;
									options.setupHMAC(NPPCRYPT_VERSION);
									crypt::hmac_header(header.body(), header.body_size(), &buffer[0], buffer.size(), options.hmac.hash, &options.hmac.key[0], options.hmac.key.size(), s_hmac);
									header.updateHMAC(s_hmac);
								}

								// --------- update existing cryptoptions or save the current one as new
								if(fiter!=crypt_files.end()) {
									crypt_files.insert(std::pair<string, NppCryptOptions>(path, current::crypt));
								}
							} else {
								return;
							}
						}

						// --------- replace text with headerinformation and encrypted data:
						::SendMessage(hCurScintilla, SCI_BEGINUNDOACTION, 0, 0);
						::SendMessage(hCurScintilla, SCI_CLEARALL, 0, 0);
						::SendMessage(hCurScintilla, SCI_APPENDTEXT, header.size(), (LPARAM)header.c_str());
						::SendMessage(hCurScintilla, SCI_APPENDTEXT, buffer.size(), (LPARAM)&buffer[0]);
						::SendMessage(hCurScintilla, SCI_ENDUNDOACTION, 0, 0);

						// --------- save file again:
						UndoFileEncryption = true;
						::SendMessage(nppData._nppHandle, NPPM_SAVECURRENTFILE, 0, 0);
					}
				}
			} catch(CExc& exc) {
				::MessageBox(nppData._nppHandle, exc.getErrorMsg(), TEXT("Error"), MB_OK);
			} catch(...) {
				::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
			}
		} break;
			
		default:
			return;
	}
}

// ====================================================================================================================================================================

extern "C" __declspec(dllexport) LRESULT messageProc(UINT Message, WPARAM wParam, LPARAM lParam)
{
	return TRUE;
}

// ====================================================================================================================================================================

extern "C" __declspec(dllexport) BOOL isUnicode()
{
	#ifdef UNICODE
    return TRUE;
	#else
	return FALSE;
	#endif
}

// ====================================================================================================================================================================
// ====================================================================================================================================================================

void EncryptDlg()
{
	try 
	{
		HWND hCurScintilla = help::getCurScintilla();

		size_t selStart = ::SendMessage(hCurScintilla, SCI_GETSELECTIONSTART, 0, 0);
		size_t selEnd = ::SendMessage(hCurScintilla, SCI_GETSELECTIONEND, 0, 0);
		size_t data_length = selEnd - selStart;
		if(!data_length)
			return;
	
		// --------- if the file was saved with utf16 encoding, ascii data in scintilla would be corrupted
		int file_encoding = ::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, ::SendMessage(nppData._nppHandle, NPPM_GETCURRENTBUFFERID, 0, 0), 0);
		bool no_ascii = (file_encoding != uni8Bit && file_encoding != uniUTF8 && file_encoding != uniCookie) ? true : false;

		// ---------show dialog with current default options:
		if(dlg_crypt.doDialog(DlgCrypt::Encryption, &current::crypt, no_ascii))
		{
			// --------- get pointer to selected data:
			unsigned char* pData = (unsigned char*)::SendMessage(hCurScintilla, SCI_GETRANGEPOINTER , selStart, selEnd);
			HeaderWriter header(current::crypt);
			std::vector<unsigned char>	buffer;

			// --------- encrypt data:
			current::crypt.setupPassword(NPPCRYPT_VERSION);
			crypt::encrypt(pData, data_length, buffer, current::crypt, header.init_strings());

			// --------- create header
			header.create();
			if(current::crypt.hmac.enable) 
			{
				// get hmac of header-body + encrypted data
				current::crypt.setupHMAC(NPPCRYPT_VERSION);
				std::string s_hmac;
				crypt::hmac_header(header.body(), header.body_size(), &buffer[0], buffer.size(), current::crypt.hmac.hash, &current::crypt.hmac.key[0], 16, s_hmac);
				header.updateHMAC(s_hmac);
			}

			// --------- replace current selection with header and encrypted data:
			::SendMessage(hCurScintilla, SCI_BEGINUNDOACTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_TARGETFROMSELECTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_REPLACETARGET, header.size(), (LPARAM)header.c_str());
			::SendMessage(hCurScintilla, SCI_SETSEL, selStart + header.size(), selStart + header.size());
			::SendMessage(hCurScintilla, SCI_TARGETFROMSELECTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_REPLACETARGET, buffer.size(), (LPARAM)&buffer[0]);	
			::SendMessage(hCurScintilla, SCI_SETSEL, selStart, selStart + header.size() +buffer.size());
			::SendMessage(hCurScintilla, SCI_ENDUNDOACTION, 0, 0);

			for(size_t i=0; i<current::crypt.password.size(); i++)
				current::crypt.password[i]=0;
			current::crypt.password.clear();
		}
	}
	catch (CExc& exc) {
		::MessageBox(nppData._nppHandle, exc.getErrorMsg(), TEXT("Error"), MB_OK);
	}
	catch (...) {
		::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
	}
}

// ====================================================================================================================================================================

void DecryptDlg()
{
	try
	{
		HWND hCurScintilla = help::getCurScintilla();
		size_t selStart = ::SendMessage(hCurScintilla, SCI_GETSELECTIONSTART, 0, 0);
		size_t selEnd = ::SendMessage(hCurScintilla, SCI_GETSELECTIONEND, 0, 0);
		size_t data_length = selEnd - selStart;
		if(!data_length)
			return;
	
		// --------- get pointer to data
		const unsigned char* pData = (unsigned char*)::SendMessage(hCurScintilla, SCI_GETRANGEPOINTER, selStart, selEnd);
		HeaderReader header(current::crypt);

		// --------- hmac-check if nessecary:
		bool found_header = header.parse(pData, data_length);
		if(found_header && current::crypt.hmac.enable)
		{
			if(current::crypt.hmac.key_id == -1)
			{
				if(!dlg_auth.doDialog())
					return;
				dlg_auth.getKeyString(current::crypt.hmac.key_input);
			}
			current::crypt.setupHMAC(header.getVersion());
			std::string s_hmac_cmp;
			crypt::hmac_header((const char*)header.body(), header.body_size(), header.cdata(), header.cdata_size(), current::crypt.hmac.hash, &current::crypt.hmac.key[0], current::crypt.hmac.key.size(), s_hmac_cmp);
			if(!header.checkHMAC(s_hmac_cmp))
				throw CExc(CExc::Code::authentication);
		}

		int file_encoding = ::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, ::SendMessage(nppData._nppHandle, NPPM_GETCURRENTBUFFERID, 0, 0), 0);
		bool no_ascii = (file_encoding != uni8Bit && file_encoding != uniUTF8 && file_encoding != uniCookie) ? true : false;

		if(dlg_crypt.doDialog(DlgCrypt::Decryption, &current::crypt, no_ascii))
		{
			// --------- decrypt data
			std::vector<unsigned char>	buffer;
			current::crypt.setupPassword(header.getVersion());
			crypt::decrypt(header.cdata(), header.cdata_size(), buffer, current::crypt, header.init_strings());

			// --------- replace current selection with decrypted data
			::SendMessage(hCurScintilla, SCI_BEGINUNDOACTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_TARGETFROMSELECTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_REPLACETARGET, buffer.size(), (LPARAM)&buffer[0]);	
			::SendMessage(hCurScintilla, SCI_SETSEL, selStart, selStart+buffer.size());
			::SendMessage(hCurScintilla, SCI_ENDUNDOACTION, 0, 0);

			for(size_t i=0; i<current::crypt.password.size(); i++)
				current::crypt.password[i]=0;
			current::crypt.password.clear();
		}
	} catch(CExc& exc) {
		::MessageBox(nppData._nppHandle, exc.getErrorMsg(), TEXT("Error"), MB_OK);
	} catch(...) {
		::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
	}
}

// ====================================================================================================================================================================

void HashDlg()
{
	try
	{
		int file_encoding = ::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, ::SendMessage(nppData._nppHandle, NPPM_GETCURRENTBUFFERID, 0, 0), 0);
		bool no_ascii = (file_encoding != uni8Bit && file_encoding != uniUTF8 && file_encoding != uniCookie) ? true : false;

		if (dlg_hash.doDialog(no_ascii))
		{
			HWND hCurScintilla = help::getCurScintilla();
			size_t selStart = ::SendMessage(hCurScintilla, SCI_GETSELECTIONSTART, 0, 0);
			size_t selEnd = ::SendMessage(hCurScintilla, SCI_GETSELECTIONEND, 0, 0);
			size_t data_length = selEnd - selStart;

			unsigned char*				data = NULL;
			std::vector<unsigned char>	buffer;

			if (data_length > 0) 
			{
				data = (unsigned char*)::SendMessage(hCurScintilla, SCI_GETRANGEPOINTER, selStart, selEnd);
				if (!data)
					throw CExc(CExc::File::nppcrypt, __LINE__);
			}
			if (current::hash.use_key)
			{
				if (current::hash.key_id >= 0)
				{
					current::hash.key.resize(16);
					const unsigned char* tkey = preferences.getKey(current::hash.key_id);
					current::hash.key.assign(tkey, tkey + 16);
				}
				else {
					current::hash.key.resize(16);
					crypt::shake128((const unsigned char*)current::hash.key_input.c_str(), current::hash.key_input.size(), &current::hash.key[0], 16);
				}
				crypt::hmac(data, data_length, current::hash, buffer);
			} else {
				crypt::hash(data, data_length, buffer, current::hash);
			}

			::SendMessage(hCurScintilla, SCI_BEGINUNDOACTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_TARGETFROMSELECTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_REPLACETARGET, buffer.size(), (LPARAM)&buffer[0]);
			::SendMessage(hCurScintilla, SCI_SETSEL, selStart, selStart + buffer.size());
			::SendMessage(hCurScintilla, SCI_ENDUNDOACTION, 0, 0);
		}
	}
	catch (CExc& exc) {
		::MessageBox(nppData._nppHandle, exc.getErrorMsg(), TEXT("Error"), MB_OK);
	}
	catch (...) {
		::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
	}
}

// ====================================================================================================================================================================

void RandomDlg()
{
	try
	{
		int file_encoding = ::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, ::SendMessage(nppData._nppHandle, NPPM_GETCURRENTBUFFERID, 0, 0), 0);
		bool no_ascii = (file_encoding != uni8Bit && file_encoding != uniUTF8 && file_encoding != uniCookie) ? true : false;

		if(dlg_random.doDialog(no_ascii))
		{
			HWND hCurScintilla = help::getCurScintilla();
			size_t selStart = ::SendMessage(hCurScintilla, SCI_GETSELECTIONSTART, 0, 0);

			std::vector<unsigned char> buffer;
			crypt::random(current::random, buffer);

			::SendMessage(hCurScintilla, SCI_BEGINUNDOACTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_TARGETFROMSELECTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_REPLACETARGET, buffer.size(), (LPARAM)&buffer[0]);	
			::SendMessage(hCurScintilla, SCI_SETSEL, selStart, selStart+buffer.size());
			::SendMessage(hCurScintilla, SCI_ENDUNDOACTION, 0, 0);
		}
	}
	catch (CExc& exc) {
		::MessageBox(nppData._nppHandle, exc.getErrorMsg(), TEXT("Error"), MB_OK);
	}
	catch (...) {
		::MessageBox(nppData._nppHandle, TEXT("Unkown exception!"), TEXT("Error"), MB_OK);
	}
}

// ====================================================================================================================================================================

void PreferencesDlg()
{
	dlg_preferences.doDialog();
}

// ====================================================================================================================================================================

void AboutDlg()
{
	dlg_about.doDialog();
}

// ====================================================================================================================================================================
// ====================================================================================================================================================================

void NppCryptOptions::setupHMAC(int header_version)
{
	if (hmac.enable) {
		if (hmac.key_id >= 0) {
			const unsigned char* tkey = preferences.getKey(hmac.key_id);
			hmac.key.assign(tkey, tkey + 16);
		}
		else {
			hmac.key.resize(16);
			if (header_version <= 101)
				hmac.key_input.push_back(0);
			crypt::shake128((const unsigned char*)hmac.key_input.c_str(), hmac.key_input.size(), &hmac.key[0], 16);
			if (header_version <= 101)
				hmac.key_input.pop_back();
		}
	}
}

// ====================================================================================================================================================================

void NppCryptOptions::setupPassword(int header_version)
{
	if (header_version <= 101) {
		password.push_back(0);
	}
	else {
		if (password.size() > 0 && password.back() == 0)
			password.pop_back();
	}
}

// ====================================================================================================================================================================
// ====================================================================================================================================================================

bool help::setCommand(size_t index, TCHAR *cmdName, PFUNCPLUGINCMD pFunc, ShortcutKey *sk, bool check0nInit) 
{
    if (index >= 8)
        return false;

    if (!pFunc)
        return false;

    lstrcpy(funcItem[index]._itemName, cmdName);
    funcItem[index]._pFunc = pFunc;
    funcItem[index]._init2Check = check0nInit;
    funcItem[index]._pShKey = sk;

    return true;
}

// ====================================================================================================================================================================

HWND help::getCurScintilla()
{
    int which = -1;
    ::SendMessage(nppData._nppHandle, NPPM_GETCURRENTSCINTILLA, 0, (LPARAM)&which);
	if (which == 0)
	{
		return nppData._scintillaMainHandle;
	}
	else if (which == 1) 
	{
		return nppData._scintillaSecondHandle;
	}
	else {
		throw CExc(CExc::File::nppcrypt, __LINE__);
	}
}

// ====================================================================================================================================================================

void help::getPath(int bufferid, string& path, string& filename, string& extension)
{
	int path_length = ::SendMessage(nppData._nppHandle, NPPM_GETFULLPATHFROMBUFFERID, bufferid, NULL);
	if (path_length <= 0)
		throw CExc(CExc::File::nppcrypt, __LINE__);
	path.resize(path_length + 1);
	::SendMessage(nppData._nppHandle, NPPM_GETFULLPATHFROMBUFFERID, bufferid, (LPARAM)&path[0]);
	path.pop_back();
	size_t x = path.find_last_of('/');
	size_t x2 = path.find_last_of('\\');
	if (x2 > x)
		x = x2;
	filename = path.substr(x + 1);
	x = filename.find_last_of('.');
	extension = filename.substr(x + 1);
}