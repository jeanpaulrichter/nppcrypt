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

// plugin-menu items:
enum class Menu: unsigned {
	encrypt=0,
	decrypt,
	hash,
	random,
	spacer1,
	preferences,
	spacer2,
	about,
	COUNT
};

FuncItem				funcItem[Menu::COUNT];
NppData					nppData;
HINSTANCE				m_hInstance;

// dialog-objects:
DlgCrypt&				dlg_crypt = DlgCrypt::Instance();
DlgHash&				dlg_hash = DlgHash::Instance();
DlgRandom&				dlg_random = DlgRandom::Instance();
DlgAuth&				dlg_auth = DlgAuth::Instance();
DlgConfig&				dlg_config = DlgConfig::Instance();
DlgAbout&				dlg_about = DlgAbout::Instance();

// to store the current (last used) options for encryption etc.:
namespace current 
{
	Crypt::Options		crypt;
	Crypt::HashOptions	hash;
	Crypt::RandOptions	random;
}

// map to store information about opened nppcrypt-files. (to allow saving without user input):
std::map<std::vector<TCHAR> , Crypt::Options> crypt_files;

// encodings enum (from Parameters.h):
enum UniMode {uni8Bit=0, uniUTF8=1, uni16BE=2, uni16LE=3, uniCookie=4, uni7Bit=5, uni16BE_NoBOM=6, uni16LE_NoBOM=7, uniEnd};

// ====================================================================================================================================================================
// ====================================================================================================================================================================

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  reasonForCall, 
                       LPVOID lpReserved )
{
	switch (reasonForCall)
    {
		case DLL_PROCESS_ATTACH:
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
			dlg_config.destroy();
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
	setCommand(0, TEXT("Encrypt"), EncryptDlg, NULL, false);
    setCommand(1, TEXT("Decrypt"), DecryptDlg, NULL, false);
    setCommand(2, TEXT("Hash"), HashDlg, NULL, false);
	setCommand(3, TEXT("Random"), RandomDlg, NULL, false);
	setCommand(4, TEXT("---"), NULL, NULL, false);
	setCommand(5, TEXT("Preferences"), PreferencesDlg, NULL, false);
	setCommand(6, TEXT("---"), NULL, NULL, false);
	setCommand(7, TEXT("About"), AboutDlg, NULL, false);

	// initialize dialogs
	dlg_random.init(m_hInstance, nppData._nppHandle, &current::random);
	dlg_hash.init(m_hInstance, nppData._nppHandle, &current::hash);
	dlg_crypt.init(m_hInstance, nppData._nppHandle);
	dlg_about.init(m_hInstance, nppData._nppHandle);
	dlg_config.init(m_hInstance, nppData._nppHandle);
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
	*nbF = static_cast<int>(Menu::COUNT);
	return funcItem;
}

// ====================================================================================================================================================================

extern "C" __declspec(dllexport) void beNotified(SCNotification *notifyCode)
{
	switch (notifyCode->nmhdr.code) 
	{
		// ------------------------------------------------------------------------------------------------------------------------------------------------------------
		// ------------------------------------------------------------------------------------------------------------------------------------------------------------

		case NPPN_FILEOPENED: {
			if(!preferences.files.enable)
				return;

			try {

				// get path of file
				int file_path_len = ::SendMessage(nppData._nppHandle, NPPM_GETFULLPATHFROMBUFFERID, notifyCode->nmhdr.idFrom, NULL);
				if(file_path_len == -1)
					throw CExc(CExc::nppcrypt, __LINE__);
				std::vector<TCHAR> file_path(file_path_len+1);
				::SendMessage(nppData._nppHandle, NPPM_GETFULLPATHFROMBUFFERID, notifyCode->nmhdr.idFrom, (LPARAM)&file_path[0]);

				// if Extension matches
				if((file_path_len - preferences.files.ext_length > 2) && lstrcmp(&file_path[file_path_len-preferences.files.ext_length],preferences.files.extension)==0) {

					// switch to file and get scintilla handle
					::SendMessage(nppData._nppHandle, NPPM_SWITCHTOFILE, 0, (LPARAM)&file_path[0]);
					HWND hCurScintilla = getCurScintilla();

					// data length
					int data_length = ::SendMessage(hCurScintilla, SCI_GETLENGTH , 0, 0);
					if(!data_length)
						throw CExc(CExc::file_empty);

					// get data pointer
					unsigned char* data = (unsigned char*)::SendMessage(hCurScintilla, SCI_GETCHARACTERPOINTER , 0, 0);
					if(!data)
						throw CExc(CExc::nppcrypt, __LINE__);

					Crypt::Options	options;
					HeaderInfo		header;

					// read header
					if(!readHeader(data, data_length, options, header))
						throw CExc(CExc::parse_header);

					// extract filename for dialog window
					TCHAR filename[40];
					getFilename(&file_path[0], filename, 40);

					// check hmac if enabled
					if(options.hmac.enable) {
						const unsigned char* pAuthkey;
						if(options.hmac.key_id == -1) {
							if(!dlg_auth.doDialog(filename))
								return;
							pAuthkey = dlg_auth.getKey();
							memcpy(options.hmac.key, pAuthkey, 16);
						} else {
							pAuthkey = preferences.getKey(options.hmac.key_id);
						}
						std::string s_hmac_cmp;
						Crypt::hmac((const char*)data+header.body_start, header.body_end-header.body_start, data+header.length, data_length-header.length, options.hmac.hash, pAuthkey, s_hmac_cmp);
						if(s_hmac_cmp.compare(header.s_hmac) != 0)
							throw CExc(CExc::authentication);
						
						dlg_auth.clearKey();
					}

					int encoding = ::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, notifyCode->nmhdr.idFrom, 0);
					preferences.no_ascii = (encoding != uni8Bit && encoding != uniUTF8 && encoding != uniCookie) ? true : false;

					// show password dialog
					if(dlg_crypt.doDialog(Crypt::Operation::Decryption, &options, filename)) {

						// decrypt data
						std::vector<unsigned char> buffer;
						Crypt::doCrypt(Crypt::Operation::Decryption, data+header.length, data_length-header.length, buffer, &options, header.s_iv, header.s_salt, header.s_tag);

						// replace text with decrypted data
						::SendMessage(hCurScintilla, SCI_CLEARALL, 0, 0);
						::SendMessage(hCurScintilla, SCI_APPENDTEXT, buffer.size(), (LPARAM)&buffer[0]);
						::SendMessage(hCurScintilla, SCI_GOTOPOS, 0, 0);
						::SendMessage(hCurScintilla, SCI_EMPTYUNDOBUFFER, 0, 0);
						::SendMessage(hCurScintilla, SCI_SETSAVEPOINT, 0, 0);

						// save current Crypt::Options for automatic save without user input.
						crypt_files.insert(std::pair<std::vector<TCHAR>, Crypt::Options>(file_path, options));
					}
				}
			} catch(CExc& exc) {
				::MessageBox(nppData._nppHandle, exc.getErrorMsg(), TEXT("Error"), MB_OK);
			} catch(...) {
				::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
			}
			break; }

		// ------------------------------------------------------------------------------------------------------------------------------------------------------------
		// ------------------------------------------------------------------------------------------------------------------------------------------------------------

		/* Why NPPN_FILESAVED instead of NPPN_FILEBEFORESAVE thus effectivly saving the file twice? 
		   Because if the user chooses "save as" there is no way of knowing the new filename in NPPN_FILEBEFORESAVE 
		   Btw: "Save a Copy as..." does trigger neither NPPN_FILESAVED nor NPPN_FILEBEFORESAVE. same goes for automatic backup saves.*/

		case NPPN_FILESAVED: {
			if(!preferences.files.enable)
				return;

			static bool UndoFileEncryption;

			if(UndoFileEncryption) {

				// after the encrypted file was saved: undo everthing. (maybe SCI_EMPTYUNDOBUFFER should be optional)
				HWND hCurScintilla = getCurScintilla();				
				::SendMessage(hCurScintilla, SCI_UNDO, 0, 0);
				::SendMessage(hCurScintilla, SCI_GOTOPOS, 0, 0);
				::SendMessage(hCurScintilla, SCI_EMPTYUNDOBUFFER, 0, 0);
				::SendMessage(hCurScintilla, SCI_SETSAVEPOINT, 0, 0);
				UndoFileEncryption = false;
			} else {
				
				try {
					// get path of file
					std::vector<TCHAR> file_path;
					int file_path_len = ::SendMessage(nppData._nppHandle, NPPM_GETFULLPATHFROMBUFFERID, notifyCode->nmhdr.idFrom, NULL);
					if(file_path_len == -1)
						throw CExc(CExc::nppcrypt, __LINE__);
					file_path.resize(file_path_len+1);
					::SendMessage(nppData._nppHandle, NPPM_GETFULLPATHFROMBUFFERID, notifyCode->nmhdr.idFrom, (LPARAM)&file_path[0]);

					// if Extension matches
					if((file_path_len - preferences.files.ext_length > 2) && lstrcmp(&file_path[file_path_len-preferences.files.ext_length], preferences.files.extension)==0) {

						// switch to file and get scintilla handle
						::SendMessage(nppData._nppHandle, NPPM_SWITCHTOFILE, 0, (LPARAM)&file_path[0]);
						HWND hCurScintilla = getCurScintilla();

						// get data length
						int data_length = ::SendMessage(hCurScintilla, SCI_GETLENGTH , 0, 0);
						if(!data_length)
							throw CExc(CExc::file_empty);

						// get pointer to data
						unsigned char* data = (unsigned char*)::SendMessage(hCurScintilla, SCI_GETCHARACTERPOINTER , 0, 0);
						if(!data)
							throw CExc(CExc::nppcrypt, __LINE__);

						// extract filename without path
						TCHAR filename[40];
						getFilename(&file_path[0], filename, 40);

						std::vector<unsigned char>	buffer;
						std::string					header;
						HeaderInfo					header_info;

						// does this file already exist?
						std::map<std::vector<TCHAR>, Crypt::Options>::iterator fiter= crypt_files.find(file_path);

						// yes it does:
						if(fiter != crypt_files.end()) {
							bool autoencrypt=false;

							if(preferences.files.askonsave) {
								TCHAR msg[70] = TEXT("change encryption of   ");
								lstrcpy(&msg[21], filename);
								msg[lstrlen(msg)]=TEXT('?');
								msg[lstrlen(msg)+1]=0;								

								if(::MessageBox(nppData._nppHandle, msg, TEXT("nppcrypt"), MB_YESNO|MB_ICONQUESTION)!=IDYES)
									autoencrypt = true;
							} else {
								autoencrypt = true;
							}

							if(autoencrypt) {
								// encrypt data and setup header-string
								Crypt::doCrypt(Crypt::Operation::Encryption, data, data_length, buffer, &fiter->second, header_info.s_iv, header_info.s_salt, header_info.s_tag);
								writeHeader(header, header_info, fiter->second);

								// if activated: create hmac and insert copy it into the header
								if(fiter->second.hmac.enable) {
									Crypt::hmac(&header[header_info.body_start], header_info.body_end-header_info.body_start, &buffer[0], buffer.size(), fiter->second.hmac.hash, fiter->second.hmac.key, header_info.s_hmac);
									std::copy(header_info.s_hmac.begin(), header_info.s_hmac.end(), header.begin()+header_info.hmac_start);
								}
							}
						}
						
						// no encrypted data yet therefore crypt dialog needed:
						if(!buffer.size()) {
							int encoding = ::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, notifyCode->nmhdr.idFrom, 0);
							preferences.no_ascii = (encoding != uni8Bit && encoding != uniUTF8 && encoding != uniCookie) ? true : false;

							if(dlg_crypt.doDialog(Crypt::Operation::Encryption, &current::crypt, filename))
							{
								// encrypt data and setup header-string
								Crypt::doCrypt(Crypt::Operation::Encryption, data, data_length, buffer, &current::crypt, header_info.s_iv, header_info.s_salt, header_info.s_tag);
								writeHeader(header, header_info, current::crypt);

								// if activated: create hmac and insert copy it into the header
								if(current::crypt.hmac.enable) {
									Crypt::hmac(&header[header_info.body_start], header_info.body_end-header_info.body_start, &buffer[0], buffer.size(), current::crypt.hmac.hash, current::crypt.hmac.key, header_info.s_hmac);
									std::copy(header_info.s_hmac.begin(), header_info.s_hmac.end(), header.begin()+header_info.hmac_start);
								}

								// update existing cryptoptions or save the current one as new
								if(fiter!=crypt_files.end()) {
									fiter->second = current::crypt;
								} else {
									crypt_files.insert(std::pair<std::vector<TCHAR>, Crypt::Options>(file_path, current::crypt));
								}
							} else {
								return;
							}
						}

						// replace text with headerinformation and encrypted data:
						::SendMessage(hCurScintilla, SCI_BEGINUNDOACTION, 0, 0);
						::SendMessage(hCurScintilla, SCI_CLEARALL, 0, 0);
						::SendMessage(hCurScintilla, SCI_APPENDTEXT, header.size(), (LPARAM)&header[0]);
						::SendMessage(hCurScintilla, SCI_APPENDTEXT, buffer.size(), (LPARAM)&buffer[0]);
						::SendMessage(hCurScintilla, SCI_ENDUNDOACTION, 0, 0);

						// save file again:
						UndoFileEncryption = true;
						::SendMessage(nppData._nppHandle, NPPM_SAVECURRENTFILE, 0, 0);
					}
				} catch(CExc& exc) {
					::MessageBox(nppData._nppHandle, exc.getErrorMsg(), TEXT("Error"), MB_OK);
				} catch(...) {
					::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
				}
			}
			
			break; }
			
		default:
			return;
	}
}

extern "C" __declspec(dllexport) LRESULT messageProc(UINT Message, WPARAM wParam, LPARAM lParam)
{
	return TRUE;
}


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
	HWND hCurScintilla = getCurScintilla();
	if(!hCurScintilla)
		return;

	size_t selStart = ::SendMessage(hCurScintilla, SCI_GETSELECTIONSTART, 0, 0);
	size_t selEnd = ::SendMessage(hCurScintilla, SCI_GETSELECTIONEND, 0, 0);
	size_t data_length = selEnd - selStart;
	if(!data_length)
		return;
	
	// if the file is saved with utf16 encoding, ascii data in scintilla would be corrupted
	int file_encoding = ::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, ::SendMessage(nppData._nppHandle, NPPM_GETCURRENTBUFFERID, 0, 0), 0);
	preferences.no_ascii = (file_encoding != uni8Bit && file_encoding != uniUTF8 && file_encoding != uniCookie) ? true : false;

	// show dialog with current default options:
	if(dlg_crypt.doDialog(Crypt::Operation::Encryption, &current::crypt)) {
		try {

			// -------------- get pointer to selected data:
			unsigned char* data = (unsigned char*)::SendMessage(hCurScintilla, SCI_GETRANGEPOINTER , selStart, selEnd);
			if(!data)
				throw CExc(CExc::nppcrypt, __LINE__);
			
			HeaderInfo					header_info;
			std::string					header;
			std::vector<unsigned char>	buffer;

			// -------------- encrypt data:
			Crypt::doCrypt(Crypt::Operation::Encryption, data, data_length, buffer, &current::crypt, header_info.s_iv, header_info.s_salt, header_info.s_tag);

			// -------------- create header -----------------------------------------------------------------------------------------------------------------------
			writeHeader(header, header_info, current::crypt);
			if(current::crypt.hmac.enable) {
				// get hmac of header-body + encrypted data
				Crypt::hmac(&header[header_info.body_start], header_info.body_end-header_info.body_start, &buffer[0], buffer.size(), current::crypt.hmac.hash, current::crypt.hmac.key, header_info.s_hmac);
				std::copy(header_info.s_hmac.begin(), header_info.s_hmac.end(), header.begin()+header_info.hmac_start);
			}
			// ------------------------------------------------------------------------------------------------------------------------------------------------

			// replace current selection with header and encrypted data:
			::SendMessage(hCurScintilla, SCI_BEGINUNDOACTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_TARGETFROMSELECTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_REPLACETARGET, header_info.length, (LPARAM)header.c_str());
			::SendMessage(hCurScintilla, SCI_SETSEL, selStart+header_info.length, selStart+header_info.length);
			::SendMessage(hCurScintilla, SCI_TARGETFROMSELECTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_REPLACETARGET, buffer.size(), (LPARAM)&buffer[0]);	
			::SendMessage(hCurScintilla, SCI_SETSEL, selStart, selStart+header_info.length+buffer.size());
			::SendMessage(hCurScintilla, SCI_ENDUNDOACTION, 0, 0);

			for(size_t i=0; i<current::crypt.password.size(); i++)
				current::crypt.password[i]=0;
			current::crypt.password.clear();

		} catch(CExc& exc) {
			::MessageBox(nppData._nppHandle, exc.getErrorMsg(), TEXT("Error"), MB_OK);
		} catch(...) {
			::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
		}
	}
}

// ====================================================================================================================================================================

void DecryptDlg()
{
	HWND hCurScintilla = getCurScintilla();
	if(!hCurScintilla)
		return;

	size_t selStart = ::SendMessage(hCurScintilla, SCI_GETSELECTIONSTART, 0, 0);
	size_t selEnd = ::SendMessage(hCurScintilla, SCI_GETSELECTIONEND, 0, 0);
	size_t data_length = selEnd - selStart;
	if(!data_length)
		return;

	try {
		// get pointer to data
		unsigned char* data = (unsigned char*)::SendMessage(hCurScintilla, SCI_GETRANGEPOINTER , selStart, selEnd);
		if(!data)
			throw CExc(CExc::nppcrypt, __LINE__);

		std::vector<unsigned char>	buffer;
		HeaderInfo					header_info;
		bool						found_header;

		// check for header
		found_header = readHeader(data, data_length, current::crypt, header_info);

		// hmac-check nessecary:
		if(found_header && current::crypt.hmac.enable) {
			const unsigned char* pAuthkey;
			// get key either by user input or preset:
			if(current::crypt.hmac.key_id == -1) {
				if(!dlg_auth.doDialog())
					return;
				pAuthkey = dlg_auth.getKey();
			} else {
				pAuthkey = preferences.getKey(current::crypt.hmac.key_id);
			}
			// calc hmac of header-body + data and compare it to header-hmac
			std::string s_hmac_cmp;
			Crypt::hmac((const char*)data+header_info.body_start, header_info.body_end-header_info.body_start, data+header_info.length, data_length-header_info.length, current::crypt.hmac.hash, pAuthkey, s_hmac_cmp);
			if(s_hmac_cmp.compare(header_info.s_hmac) != 0)
				throw CExc(CExc::authentication);
			dlg_auth.clearKey();
		}

		int file_encoding = ::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, ::SendMessage(nppData._nppHandle, NPPM_GETCURRENTBUFFERID, 0, 0), 0);
		preferences.no_ascii = (file_encoding != uni8Bit && file_encoding != uniUTF8 && file_encoding != uniCookie) ? true : false;

		// show decrypt-dialog
		if(dlg_crypt.doDialog(Crypt::Operation::Decryption, &current::crypt)) {

			// decrypt data
			Crypt::doCrypt(Crypt::Operation::Decryption, data+header_info.length, data_length-header_info.length, buffer, &current::crypt, header_info.s_iv, header_info.s_salt, header_info.s_tag);

			// replace current selection with decrypted data
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
	HWND hCurScintilla = getCurScintilla();
	if(!hCurScintilla)
		return;

	int file_encoding = ::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, ::SendMessage(nppData._nppHandle, NPPM_GETCURRENTBUFFERID, 0, 0), 0);
	preferences.no_ascii = (file_encoding != uni8Bit && file_encoding != uniUTF8 && file_encoding != uniCookie) ? true : false;

	if(dlg_hash.doDialog()) {

		size_t selStart = ::SendMessage(hCurScintilla, SCI_GETSELECTIONSTART, 0, 0);
		size_t selEnd = ::SendMessage(hCurScintilla, SCI_GETSELECTIONEND, 0, 0);
		size_t data_length = selEnd - selStart;

		try {
			unsigned char*				data = NULL;
			std::vector<unsigned char>	buffer;

			if(data_length > 0) {
				data = (unsigned char*)::SendMessage(hCurScintilla, SCI_GETRANGEPOINTER , selStart, selEnd);
				if(!data)
					throw CExc(CExc::nppcrypt, __LINE__);
			}
			if(current::hash.use_key)
				Crypt::hmac(data, data_length, current::hash, buffer);
			else
				Crypt::doHash(data, data_length, buffer, &current::hash);

			::SendMessage(hCurScintilla, SCI_BEGINUNDOACTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_TARGETFROMSELECTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_REPLACETARGET, buffer.size(), (LPARAM)&buffer[0]);	
			::SendMessage(hCurScintilla, SCI_SETSEL, selStart, selStart+buffer.size());
			::SendMessage(hCurScintilla, SCI_ENDUNDOACTION, 0, 0);

		} catch(CExc& exc) {
			::MessageBox(nppData._nppHandle, exc.getErrorMsg(), TEXT("Error"), MB_OK);
		} catch(...) {
			::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
		}
	}
}

// ====================================================================================================================================================================

void RandomDlg()
{
	HWND hCurScintilla = getCurScintilla();
	if(!hCurScintilla)
		return;

	int file_encoding = ::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, ::SendMessage(nppData._nppHandle, NPPM_GETCURRENTBUFFERID, 0, 0), 0);
	preferences.no_ascii = (file_encoding != uni8Bit && file_encoding != uniUTF8 && file_encoding != uniCookie) ? true : false;

	if(dlg_random.doDialog()) {
		size_t selStart = ::SendMessage(hCurScintilla, SCI_GETSELECTIONSTART, 0, 0);

		try {
			std::vector<unsigned char> buffer;
			Crypt::getRandom(&current::random, buffer);

			::SendMessage(hCurScintilla, SCI_BEGINUNDOACTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_TARGETFROMSELECTION, 0, 0);
			::SendMessage(hCurScintilla, SCI_REPLACETARGET, buffer.size(), (LPARAM)&buffer[0]);	
			::SendMessage(hCurScintilla, SCI_SETSEL, selStart, selStart+buffer.size());
			::SendMessage(hCurScintilla, SCI_ENDUNDOACTION, 0, 0);
		} catch(CExc& exc) {
			::MessageBox(nppData._nppHandle, exc.getErrorMsg(), TEXT("Error"), MB_OK);
		} catch(...) {
			::MessageBox(nppData._nppHandle, TEXT("Unkown Exception!"), TEXT("Error"), MB_OK);
		}
	}
}

// ====================================================================================================================================================================

void PreferencesDlg()
{
	dlg_config.doDialog();
}

// ====================================================================================================================================================================

void AboutDlg()
{
	dlg_about.doDialog();
}

// ====================================================================================================================================================================
// ====================================================================================================================================================================

void writeHeader(std::string& header, HeaderInfo& info, const Crypt::Options& options)
{
	std::ostringstream	ss_header;

	ss_header << "<nppcrypt version=\"" << NPPCRYPT_VERSION << "\"";
	if(options.hmac.enable) {
		if(options.hmac.key_id >= 0)
			ss_header << " auth-key=\"" << options.hmac.key_id << "\"";
		ss_header << " hmac-hash=\"" << Crypt::Strings::getHash(options.hmac.hash) << "\" hmac=\"";
		info.hmac_start = static_cast<size_t>(ss_header.tellp());
		ss_header << std::string(Encode::bin_to_base64(NULL, Crypt::getMDLength(options.hmac.hash), NULL, true),' ') << "\"";
	}
	ss_header << ">" << Encode::linebreak();
	info.body_start = static_cast<size_t>(ss_header.tellp());
	ss_header << "<encryption cipher=\"" << Crypt::Strings::Cipher(options.cipher) << "\" mode=\"" << Crypt::Strings::Mode(options.mode)
				<< "\" encoding=\"" << Crypt::Strings::Encoding(options.encoding) << "\" ";
	if(info.s_tag.size()) { ss_header << "tag=\"" << info.s_tag << "\" "; }
	ss_header << "/>" << Encode::linebreak();
	if((options.iv == Crypt::InitVector::random && info.s_iv.size()>0) || options.key.salt_bytes > 0) {
		ss_header << "<random ";
		if((options.iv == Crypt::InitVector::random && info.s_iv.size()>0))
			ss_header << "iv=\"" << info.s_iv << "\" ";
		if(options.key.salt_bytes > 0)
			ss_header << "salt=\"" << info.s_salt << "\" ";
		ss_header << "/>" << Encode::linebreak();
	}
	ss_header << "<key algorithm=\"" << Crypt::Strings::KeyAlgorithm(options.key.algorithm);
	switch(options.key.algorithm) {
	case Crypt::KeyDerivation::pbkdf2:
		ss_header << "\" hash=\"" << Crypt::Strings::getHash((Crypt::Hash)options.key.option1) << "\" iterations=\"" << options.key.option2 << "\" "; break;
	case Crypt::KeyDerivation::bcrypt:
		ss_header << "\" iterations=\"" << std::pow(2,options.key.option1) << "\" "; break;
	case Crypt::KeyDerivation::scrypt:
		ss_header << "\" N=\"" << std::pow(2, options.key.option1) << "\" r=\"" << options.key.option2 << "\" p=\"" << options.key.option3 << "\" "; break;
	}
	if(options.iv == Crypt::InitVector::keyderivation)
		ss_header << "generateIV=\"true\" />" << Encode::linebreak();
	else
		ss_header << "/>" << Encode::linebreak();
	info.body_end = static_cast<size_t>(ss_header.tellp());
	ss_header << "</nppcrypt>" << Encode::linebreak();
	header = ss_header.str();
	info.length = header.size();
}

// ====================================================================================================================================================================

bool readHeader(const unsigned char* in, unsigned int in_len, Crypt::Options& options, HeaderInfo& info)
{
	info.length = 0;
	info.body_end = 0;
	info.body_start = 0;
	info.hmac_start = 0;

	if(!in || in_len < 9 || in[0]!='<' || in[1]!='n' || in[2]!='p' || in[3]!='p' || in[4]!='c' || in[5]!='r' || in[6]!='y' || in[7]!='p' || in[8]!='t')
	{

		// -------------------------- OLD HEADER ---------------------------------------------------------------------------------------------------------------------------------------
		if(in[0]==110 && in[1]==112 && in[2]==112 && in[3]==99 && in[4]==114 && in[5]==121 && in[6]==112 && in[7]==116)
		{
			// 1.008/9
			if(in[8]==1 && in_len > 16) {

				Crypt::Cipher old_ciphers[] = { Crypt::Cipher::blowfish, Crypt::Cipher::des, Crypt::Cipher::rc2, Crypt::Cipher::idea, Crypt::Cipher::cast5, Crypt::Cipher::aes128, 
												Crypt::Cipher::aes256, Crypt::Cipher::des_ede, Crypt::Cipher::des_ede3, Crypt::Cipher::desx, Crypt::Cipher::rc4 };
				Crypt::Mode old_modes[] = { Crypt::Mode::cbc, Crypt::Mode::ecb, Crypt::Mode::cfb, Crypt::Mode::ofb, Crypt::Mode::ctr };

				if(in[9] < 0 || in[9] > 10)
					throw CExc(CExc::nppcrypt, __LINE__, CExc::parse_header);
				if(in[10] < 0 || in[10] > 4)
					throw CExc(CExc::nppcrypt, __LINE__, CExc::parse_header);
				options.cipher = old_ciphers[in[9]];
				options.mode = old_modes[in[10]];
				options.encoding = (in[13] == 1) ? Crypt::Encoding::hex : Crypt::Encoding::ascii;
				
				if(in[12] == 0) {
					options.key.algorithm = Crypt::KeyDerivation::pbkdf2;
					options.key.option1 = static_cast<int>(Crypt::Hash::md5);
					options.key.option2 = 1000;
				} else {
					throw CExc(CExc::ErrCode::nppfile1009);
				}

				info.length = 16;
				options.key.salt_bytes = 0;
				if(options.encoding == Crypt::Encoding::ascii) {
					if(in_len > 32 && strncmp((char*)in+16,"Salted__",8)==0) {
						info.s_salt.resize(13);
						info.s_salt[12]=0;
						Encode::bin_to_base64(in+24, 8, &info.s_salt[0], true);
						info.length = 32;
						options.key.salt_bytes = 8;						
					}
				} else {
					unsigned char t[8];
					if(in_len > 48 && strncmp((char*)in+16,"53616C7465645F5F", 16) == 0) {
						Encode::hex_to_bin((const char*)in+32, 16, t);
						info.length = 48;
						options.key.salt_bytes = 8;
					} else if(in_len > 64 && strncmp((char*)in+16,"53 61 6C 74 65 64 5F 5F ", 24) == 0) {
						Encode::hex_to_bin((const char*)in+40,24,t);
						info.length = 64;
						options.key.salt_bytes = 8;
					}
					if(options.key.salt_bytes == 8) {
						info.s_salt.resize(13);
						info.s_salt[12]=0;
						Encode::bin_to_base64(t, 8, &info.s_salt[0], true);
					}
				}

				options.hmac.enable = false;
				options.iv = Crypt::InitVector::keyderivation;
				return true;
			
			// 1.007
			} else {
				throw CExc(CExc::ErrCode::nppfile1007);
			}
		}
		// -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

		return false;
	}
	size_t offset = 10;

	// find header body start:
	while(offset < in_len-11 && in[offset] != '\n')
		offset++;
	info.body_start = offset+1;

	// find header end:
	while(offset < in_len-11 && !(in[offset]=='<' && in[offset+1]=='/' && 
			in[offset+2]=='n' && in[offset+3]=='p' && in[offset+4]=='p' &&
			in[offset+5]=='c' && in[offset+6]=='r' && in[offset+7]=='y' &&
			in[offset+8]=='p' && in[offset+9]=='t' && in[offset+10]=='>')) {
		offset++;
	}
	if(offset > in_len-12) {
		throw CExc(CExc::nppcrypt, __LINE__, CExc::parse_header);
	}
	info.body_end = offset;

	tinyxml2::XMLError		xml_err;
	tinyxml2::XMLDocument	xml_doc;
	
	// ------ parse header:
	xml_err = xml_doc.Parse((const char*)in, offset+11);
	if(xml_err != tinyxml2::XMLError::XML_NO_ERROR)
		throw CExc(CExc::nppcrypt, __LINE__, CExc::parse_header);
	tinyxml2::XMLElement* xml_nppcrypt = xml_doc.FirstChildElement();
	if(!xml_nppcrypt)
		throw CExc(CExc::nppcrypt, __LINE__, CExc::parse_header);

	// ------ check version:
	int version;
	xml_err = xml_nppcrypt->QueryIntAttribute( "version", &version );
	if(xml_err != tinyxml2::XMLError::XML_NO_ERROR)
		throw CExc(TEXT("Header: version missing."));
	if(version != NPPCRYPT_VERSION)
		throw CExc(TEXT("Header: wrong version."));

	Crypt::Options t_options;

	// ------ valid hmac present?
	const char* pHMAC = xml_nppcrypt->Attribute("hmac");
	if(pHMAC) {
		if(strlen(pHMAC) > 256)
			throw CExc(TEXT("Header: hmac data corrupted."));
		info.s_hmac = std::string(pHMAC);
		const char* pHMAC_hash = xml_nppcrypt->Attribute("hmac-hash");
		if(!Crypt::Strings::getHashByString(pHMAC_hash, t_options.hmac.hash) || t_options.hmac.hash == Crypt::Hash::sha3_256
				|| t_options.hmac.hash == Crypt::Hash::sha3_384  || t_options.hmac.hash == Crypt::Hash::sha3_512)
		{
			throw CExc(TEXT("Header: invalid hmac-hash."));
		}
		xml_err = xml_nppcrypt->QueryIntAttribute( "auth-key", &t_options.hmac.key_id );
		if(xml_err != tinyxml2::XMLError::XML_NO_ERROR)
			t_options.hmac.key_id = -1;
		if(t_options.hmac.key_id >= (int)preferences.getKeyNum() || t_options.hmac.key_id < -1) {
			throw CExc(TEXT("Header: invalid auth-key-id."));
		}
		t_options.hmac.enable = true;
	}

	// ------- valid IV or Salt present?
	tinyxml2::XMLElement* xml_random = xml_nppcrypt->FirstChildElement("random");
	t_options.key.salt_bytes = 0;
	if(xml_random) {
		const char* pSalt = xml_random->Attribute( "salt" );
		if(pSalt) {
			if(strlen(pSalt) > 2 * Crypt::Constants::salt_bytes_max)
				throw CExc(TEXT("Header: salt data corrupted."));
			info.s_salt = std::string(pSalt);
			t_options.key.salt_bytes = Encode::base64_to_bin(info.s_salt.c_str(), info.s_salt.size());
			if(t_options.key.salt_bytes < 1 || t_options.key.salt_bytes > Crypt::Constants::salt_bytes_max)
				throw CExc(TEXT("Header: salt data corrupted."));
		}
		const char* pIV = xml_random->Attribute( "iv" );
		if(pIV) {
			if(strlen(pIV) > 1024)
				throw CExc(TEXT("Header: iv data corrupted."));
			info.s_iv = std::string(pIV);
		}
	}
		
	// ------- valid Cipher information present?
	tinyxml2::XMLElement* xml_crypt = xml_nppcrypt->FirstChildElement("encryption");
	if(xml_crypt) {
		const char* t = xml_crypt->Attribute( "cipher" );
		if(!Crypt::Strings::getCipherByString(t, t_options.cipher))
			throw CExc(TEXT("Header: invalid cipher."));
		t = xml_crypt->Attribute( "mode" );
		if(!Crypt::Strings::getModeByString(t, t_options.mode))
			throw CExc(TEXT("Header: invalid mode."));
		t = xml_crypt->Attribute( "encoding" );
		if(!Crypt::Strings::getEncodingByString(t, t_options.encoding))
			throw CExc(TEXT("Header: invalid encoding."));
		if((t = xml_crypt->Attribute( "tag" ))!=NULL) {
			if(strlen(t) != 24)
				throw CExc(TEXT("Header: tag data corrupted."));
			info.s_tag = std::string(t);
		}
	}

	// ------- valid key derivation information present?
	tinyxml2::XMLElement* xml_key = xml_nppcrypt->FirstChildElement("key");
	if(xml_key) {
		const char* t = xml_key->Attribute( "algorithm" );
		if(!Crypt::Strings::getKeyDerivationByString(t, t_options.key.algorithm))
			throw CExc(TEXT("Header: invalid key-derivation"));

		switch(t_options.key.algorithm) {
		case Crypt::KeyDerivation::pbkdf2:
			{
			t = xml_key->Attribute( "hash" );
			Crypt::Hash thash;
			if(!Crypt::Strings::getHashByString(t, thash) || thash == Crypt::Hash::sha3_256 || thash == Crypt::Hash::sha3_384 || thash == Crypt::Hash::sha3_512)
				throw CExc(TEXT("Header: invalid hash-algorithm for pbkdf2."));
			t_options.key.option1 = static_cast<int>(thash);
			if(!(t = xml_key->Attribute( "iterations" )))
				throw CExc(TEXT("Header: missing iteration-count for pbkdf2."));
			t_options.key.option2 = std::atoi(t);
			if(t_options.key.option2 < Crypt::Constants::pbkdf2_iter_min || t_options.key.option2 > Crypt::Constants::pbkdf2_iter_max)
				throw CExc(TEXT("Header: invalid iteration-count for pbkdf2."));
			break;
			}
		case Crypt::KeyDerivation::bcrypt:
			if(!(t = xml_key->Attribute( "iterations" )))
				throw CExc(TEXT("Header: missing iteration-count for bcrypt."));
			t_options.key.option1 = std::atoi(t);
			if(!((t_options.key.option1 != 0) && !(t_options.key.option1 & (t_options.key.option1 - 1))))
				throw CExc(TEXT("Header: invalid iteration-count for bcrypt (must be power of two)."));
			t_options.key.option1 = static_cast<int>(std::log(t_options.key.option1)/std::log(2));
			if(t_options.key.option1 < Crypt::Constants::bcrypt_iter_min || t_options.key.option1 > Crypt::Constants::bcrypt_iter_max)
				throw CExc(TEXT("Header: invalid iteration-count for bcrypt."));
			break;
		case Crypt::KeyDerivation::scrypt:
			if(!(t = xml_key->Attribute( "N" )))
				throw CExc(TEXT("Header: missing attibute N for scrypt."));
			t_options.key.option1 = std::atoi(t);
			if(!((t_options.key.option1 != 0) && !(t_options.key.option1 & (t_options.key.option1 - 1))))
				throw CExc(TEXT("Header: invalid N-value for scrypt (must be power of two)."));
			t_options.key.option1 = static_cast<int>(std::log(t_options.key.option1)/std::log(2));
			if(t_options.key.option1 < Crypt::Constants::scrypt_N_min || t_options.key.option1 > Crypt::Constants::scrypt_N_max)
				throw CExc(TEXT("Header: invalid value N for scrypt."));
			if(!(t = xml_key->Attribute( "r" )))
				throw CExc(TEXT("Header: missing attibute r for scrypt."));
			t_options.key.option2 = std::atoi(t);
			if(t_options.key.option2 < Crypt::Constants::scrypt_r_min || t_options.key.option2 > Crypt::Constants::scrypt_r_max)
				throw CExc(TEXT("Header: invalid value r for scrypt."));
			if(!(t = xml_key->Attribute( "p" )))
				throw CExc(TEXT("Header: missing attibute p for scrypt."));
			t_options.key.option3 = std::atoi(t);
			if(t_options.key.option3 < Crypt::Constants::scrypt_p_min || t_options.key.option3 > Crypt::Constants::scrypt_p_max)
				throw CExc(TEXT("Header: invalid value p for scrypt."));
			break;
		}
		t = xml_key->Attribute( "generateIV" );
		if(t != NULL && strlen(t) == 4 && strcmp(t,"true")==0) {
			t_options.iv = Crypt::InitVector::keyderivation;
		} else {
			if(info.s_iv.size() > 0)
				t_options.iv = Crypt::InitVector::random;
			else
				t_options.iv = Crypt::InitVector::zero;
		}
	}

	options = t_options;
	if(in[offset+11] == '\r' && in[offset+12] == '\n')
		info.length = offset + 13;
	else if(in[offset+11] == '\n')
		info.length = offset + 12;
	else {
		info.length = offset + 11;
	}

	return true;
}

// ====================================================================================================================================================================
// ====================================================================================================================================================================

bool setCommand(size_t index, TCHAR *cmdName, PFUNCPLUGINCMD pFunc, ShortcutKey *sk, bool check0nInit) 
{
    if (index >= (size_t)Menu::COUNT)
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

HWND getCurScintilla()
{
    int which = -1;
    ::SendMessage(nppData._nppHandle, NPPM_GETCURRENTSCINTILLA, 0, (LPARAM)&which);
    if (which == -1)
        return NULL;
    return (which == 0)?nppData._scintillaMainHandle : nppData._scintillaSecondHandle;
}

// ====================================================================================================================================================================

void getFilename(const TCHAR* path, TCHAR* filename, int buf_size)
{
	if(!path || !filename || buf_size < 1)
		return;
	int path_len = lstrlen(path);
	if(path_len < 1 || path_len > 500)
		return;
	int xfind= path_len;
	for(;xfind > 0;xfind--)
		if(path[xfind]==TEXT('/') || path[xfind]==TEXT('\\'))
			break;
	int run;
	for(run=0; run<buf_size-1 && xfind+1+run < path_len; run++)
		filename[run] = path[xfind+1+run];
	filename[run]=0;
}