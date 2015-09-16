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


#include "dlg_crypt.h"
#include "preferences.h"

DlgCrypt::DlgCrypt(): Window(), hwnd_basic(NULL), hwnd_auth(NULL), hwnd_iv(NULL), hwnd_key(NULL)
{};

void DlgCrypt::init(HINSTANCE hInst, HWND parent)
{
	mHinstance = hInst;
	Window::init(hInst, parent);
};

void DlgCrypt::destroy()
{
	if(hwnd_basic)
		::DestroyWindow(hwnd_basic);
	if(hwnd_auth)
		::DestroyWindow(hwnd_auth);
	if(hwnd_key)
		::DestroyWindow(hwnd_key);
	if(hwnd_iv)
		::DestroyWindow(hwnd_iv);
	if(_hSelf)
		::DestroyWindow(_hSelf);
	hwnd_basic = hwnd_auth = hwnd_key = hwnd_iv = NULL;
	_hSelf = NULL;
};

bool DlgCrypt::doDialog(Crypt::Operation op, Crypt::Options* opt, const TCHAR* filename)
{
	operation = op;
	this->filename = filename;
	confirm_password = false;

	if(!opt)
		return false;
	options = opt;

	destroy();
	if(DialogBoxParam(_hInst, MAKEINTRESOURCE(IDD_CRYPT), _hParent,  (DLGPROC)dlgProc, (LPARAM)this)==IDC_OK)
		return true;
	return false;
}

BOOL CALLBACK DlgCrypt::dlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam) 
{
	switch (Message) 
	{
		case WM_INITDIALOG :
		{
			if(!lParam)
				return FALSE;
			DlgCrypt *pDlgCrypt = (DlgCrypt *)(lParam);
			::SetWindowLongPtr(hWnd, GWL_USERDATA, (long)lParam);
			if(pDlgCrypt->_hSelf == NULL) {
				pDlgCrypt->_hSelf = hWnd;			
				pDlgCrypt->run_dlgProc(Message, wParam, lParam);
			}
			return TRUE;
		}

		default :
		{
			DlgCrypt *pDlgCrypt = reinterpret_cast<DlgCrypt *>(::GetWindowLong(hWnd, GWL_USERDATA));
			if (!pDlgCrypt)
				return FALSE;
			return pDlgCrypt->run_dlgProc(Message, wParam, lParam);
		}

	}
	return FALSE;
}

BOOL CALLBACK DlgCrypt::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message) 
	{
        case WM_INITDIALOG :
		{
			// --------------------- Dialog Caption ----------------------------------------------------------------------------------------------------
			TCHAR caption[65];
			if(operation == Crypt::Operation::Encryption) {
				lstrcpy(caption,TEXT("nppcrypt - encryption   "));
			} else {
				lstrcpy(caption,TEXT("nppcrypt - decryption   "));
			}
			if(filename) {
				caption[22]=TEXT('(');
				lstrcpy(&caption[23],filename);
				caption[lstrlen(caption)+1]=0;
				caption[lstrlen(caption)]=TEXT(')');
			}
			SetWindowText (_hSelf, caption);

			// --------------------- Setup Tab-Control -------------------------------------------------------------------------------------------------

			HWND hTab = ::GetDlgItem(_hSelf, IDC_CRYPT_TAB);
			TCITEM tie = {0};
			tie.mask = TCIF_TEXT;
			tie.pszText = TEXT("basic");
			TabCtrl_InsertItem(hTab, 0, &tie);
			tie.pszText = TEXT("key-derivation");
			TabCtrl_InsertItem(hTab, 1, &tie);
			tie.pszText = TEXT("authentication");
			TabCtrl_InsertItem(hTab, 2, &tie);
			tie.pszText = TEXT("iv");
			TabCtrl_InsertItem(hTab, 3, &tie);

			hwnd_basic  = CreateDialogParam( mHinstance,  MAKEINTRESOURCE( IDD_CRYPT_BASIC ), hTab, (DLGPROC)dlgProc, (LPARAM)this);
			hwnd_key = CreateDialogParam( mHinstance, MAKEINTRESOURCE( IDD_CRYPT_KEY ), hTab, (DLGPROC)dlgProc, (LPARAM)this);
			hwnd_auth = CreateDialogParam( mHinstance, MAKEINTRESOURCE( IDD_CRYPT_AUTH ), hTab, (DLGPROC)dlgProc, (LPARAM)this);			
			hwnd_iv = CreateDialogParam( mHinstance, MAKEINTRESOURCE( IDD_CRYPT_IV ), hTab, (DLGPROC)dlgProc, (LPARAM)this);

			RECT rc;
			GetClientRect(hTab, &rc);
			TabCtrl_AdjustRect(hTab, FALSE, &rc);
			MoveWindow(hwnd_basic, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, TRUE);
			MoveWindow(hwnd_auth, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, FALSE);
			MoveWindow(hwnd_key, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, FALSE);
			MoveWindow(hwnd_iv, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, FALSE);

			// --------------------- Cipher/Mode Comboboxes --------------------------------------------------------------------------------------------
			Crypt::Strings::setup();
			while(Crypt::Strings::nextCipher()) {
				::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_CIPHER, CB_ADDSTRING, 0, (LPARAM)Crypt::Strings::Cipher());
			}
			temp.cipher = options->cipher;
			Crypt::Strings::setCipher(temp.cipher);
			size_t m_count=0;
			while(Crypt::Strings::nextMode()) {
				::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_ADDSTRING, 0, (LPARAM)Crypt::Strings::Mode());
				m_count++;
			}
			::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_CIPHER, CB_SETCURSEL, (int)temp.cipher, 0);
			if(!m_count) {
				::EnableWindow(::GetDlgItem(hwnd_basic,IDC_CRYPT_MODE),false);
			} else {
				::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_SETCURSEL, Crypt::Strings::getIndexByMode(temp.cipher, options->mode), 0);
			}

			// --------------------- Password --------------------------------------------------------------------------------------------
			::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_PASSWORD, EM_SETPASSWORDCHAR, '*', 0);
			::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_PASSWORD, EM_LIMITTEXT, Crypt::Constants::pw_length_max, 0);

			// --------------------- Encoding ----------------------------------------------------------------------------------------------------------
			if(preferences.no_ascii) {
				if(options->encoding == Crypt::Encoding::ascii) options->encoding = Crypt::Encoding::hex;
				::EnableWindow(::GetDlgItem(hwnd_basic,IDC_CRYPT_ENC_ASCII),false);
			}
			::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_ENC_ASCII, BM_SETCHECK, (options->encoding == Crypt::Encoding::ascii), 0);
			::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_ENC_HEX, BM_SETCHECK, (options->encoding == Crypt::Encoding::hex), 0);
			::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_ENC_BASE64, BM_SETCHECK, (options->encoding == Crypt::Encoding::base64), 0);

			// --------------------- Key-Derivation ----------------------------------------------------------------------------------------------------
			// setups controls:
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT_SPIN, UDM_SETRANGE, true, (LPARAM)MAKELONG(Crypt::Constants::salt_bytes_max, 1));
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(hwnd_key,IDC_CRYPT_SALT_BYTES), 0);
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT_SPIN, UDM_SETPOS32, 0, options->key.salt_bytes);
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT, BM_SETCHECK, (options->key.salt_bytes > 0), 0);
			while(Crypt::Strings::nextHash(true)) {
				::SendDlgItemMessage(hwnd_key, IDC_CRYPT_PBKDF2_HASH, CB_ADDSTRING, 0, (LPARAM)Crypt::Strings::getHash());
			}
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_PBKDF2_ITER_SPIN, UDM_SETRANGE, true, (LPARAM)MAKELONG(Crypt::Constants::pbkdf2_iter_max , Crypt::Constants::pbkdf2_iter_min));
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_PBKDF2_ITER_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(hwnd_key,IDC_CRYPT_PBKDF2_ITER), 0);
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_BCRYPT_ITER_SPIN, UDM_SETRANGE, true, (LPARAM)MAKELONG(Crypt::Constants::bcrypt_iter_max, Crypt::Constants::bcrypt_iter_min));
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_BCRYPT_ITER_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(hwnd_key,IDC_CRYPT_BCRYPT_ITER), 0);
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_N_SPIN, UDM_SETRANGE, true, (LPARAM)MAKELONG(Crypt::Constants::scrypt_N_max, Crypt::Constants::scrypt_N_min));
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_N_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_N), 0);
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_R_SPIN, UDM_SETRANGE, true, (LPARAM)MAKELONG(Crypt::Constants::scrypt_r_max, Crypt::Constants::scrypt_r_min));
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_R_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_R), 0);
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_P_SPIN, UDM_SETRANGE, true, (LPARAM)MAKELONG(Crypt::Constants::scrypt_p_max, Crypt::Constants::scrypt_p_min));
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_P_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_P), 0);

			// default values:
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_PBKDF2_HASH, CB_SETCURSEL, Crypt::Constants::pbkdf2_default_hash, 0);
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_PBKDF2_ITER_SPIN, UDM_SETPOS32, 0, Crypt::Constants::pbkdf2_iter_default);
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_BCRYPT_ITER_SPIN, UDM_SETPOS32, 0, Crypt::Constants::bcrypt_iter_default);
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_N_SPIN, UDM_SETPOS32, 0, Crypt::Constants::scrypt_N_default);
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_R_SPIN, UDM_SETPOS32, 0, Crypt::Constants::scrypt_r_default);
			::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_P_SPIN, UDM_SETPOS32, 0, Crypt::Constants::scrypt_p_default);

			// current options:
			temp.key_derivation = options->key.algorithm;
			switch(options->key.algorithm) {
			case Crypt::KeyDerivation::pbkdf2:
				::SendDlgItemMessage(hwnd_key, IDC_CRYPT_KEY_PBKDF2, BM_SETCHECK, true, 0);
				::SendDlgItemMessage(hwnd_key, IDC_CRYPT_PBKDF2_HASH, CB_SETCURSEL, options->key.option1, 0);
				::SendDlgItemMessage(hwnd_key, IDC_CRYPT_PBKDF2_ITER_SPIN, UDM_SETPOS32, 0, options->key.option2);
				break;
			case Crypt::KeyDerivation::bcrypt:
				::SendDlgItemMessage(hwnd_key, IDC_CRYPT_KEY_BCRYPT, BM_SETCHECK, true, 0);
				::SendDlgItemMessage(hwnd_key, IDC_CRYPT_BCRYPT_ITER_SPIN, UDM_SETPOS32, 0, options->key.option1);
				break;
			case Crypt::KeyDerivation::scrypt:
				::SendDlgItemMessage(hwnd_key, IDC_CRYPT_KEY_SCRYPT, BM_SETCHECK, true, 0);
				::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_N_SPIN, UDM_SETPOS32, 0, options->key.option1);
				::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_R_SPIN, UDM_SETPOS32, 0, options->key.option2);
				::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_P_SPIN, UDM_SETPOS32, 0, options->key.option3);
				break;
			}
			enableKeyDeriControls();

			// --------------------- IV ----------------------------------------------------------------------------------------------------------------
			if(options->mode == Crypt::Mode::gcm || options->mode == Crypt::Mode::xts) {
				if(options->iv == Crypt::InitVector::zero)
					options->iv = Crypt::InitVector::keyderivation;
				::EnableWindow(::GetDlgItem(hwnd_iv,IDC_CRYPT_IV_ZERO),false);
			}
			::SendDlgItemMessage(hwnd_iv, IDC_CRYPT_IV_RANDOM, BM_SETCHECK, (options->iv == Crypt::InitVector::random), 0);
			::SendDlgItemMessage(hwnd_iv, IDC_CRYPT_IV_KEY, BM_SETCHECK, (options->iv == Crypt::InitVector::keyderivation), 0);
			::SendDlgItemMessage(hwnd_iv, IDC_CRYPT_IV_ZERO, BM_SETCHECK, (options->iv == Crypt::InitVector::zero), 0);

			// --------------------- Auth --------------------------------------------------------------------------------------------------------------
			::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_HMAC_ENABLE, BM_SETCHECK, options->hmac.enable, 0);
			if (operation == Crypt::Operation::Encryption && options->hmac.enable && options->hmac.key_id == -1) {
				std::wstring tstr;
				Encode::utf8_to_wchar(options->hmac.key_input.c_str(), -1, tstr);
				::SetDlgItemText(hwnd_auth, IDC_CRYPT_AUTH_KEY_VALUE, tstr.c_str());
			}
			while(Crypt::Strings::nextHash(true)) {
				::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_HMAC_HASH, CB_ADDSTRING, 0, (LPARAM)Crypt::Strings::getHash());
			}
			for(size_t i=0; i<preferences.getKeyNum(); i++)
				::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_LIST, CB_ADDSTRING, 0, (LPARAM)preferences.getKeyLabel(i));

			::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_HMAC_HASH, CB_SETCURSEL, static_cast<int>(options->hmac.hash), 0);
			::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_PRESET, BM_SETCHECK, (options->hmac.key_id >= 0), 0);
			::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_CUSTOM, BM_SETCHECK, (options->hmac.key_id < 0), 0);
			if(options->hmac.key_id >= (int)preferences.getKeyNum())
				options->hmac.key_id = 0;
			if(options->hmac.key_id >= 0)
				::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_LIST, CB_SETCURSEL, options->hmac.key_id, 0);
			else
				::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_LIST, CB_SETCURSEL, 0, 0);
			::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_VALUE, EM_SETPASSWORDCHAR, '*', 0);
			::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_VALUE, EM_LIMITTEXT, 32, 0);

			if(operation == Crypt::Operation::Decryption) {
				::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_HMAC_ENABLE),false);
				::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_HMAC_HASH),false);
				::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_AUTH_KEY_PRESET),false);
				::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_AUTH_KEY_CUSTOM),false);
				::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_AUTH_KEY_LIST),false);
				::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_AUTH_KEY_VALUE),false);
				::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_AUTH_KEY_SHOW),false);
			} else {
				::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_HMAC_HASH), options->hmac.enable);
				::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_AUTH_KEY_PRESET), options->hmac.enable);
				::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_AUTH_KEY_CUSTOM), options->hmac.enable);
				::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_AUTH_KEY_LIST), options->hmac.enable);
				::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_AUTH_KEY_VALUE), options->hmac.enable);
				::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_AUTH_KEY_SHOW), options->hmac.enable);
			}

			// --------------------- Show Basic Tab ----------------------------------------------------------------------------------------------------
			ShowWindow( hwnd_basic, SW_SHOW );
			ShowWindow( hwnd_key, SW_HIDE );
			ShowWindow( hwnd_auth, SW_HIDE );			
			ShowWindow( hwnd_iv, SW_HIDE );

			PostMessage( hwnd_basic, WM_USER+1, 0, 0); 

			return TRUE;
		}
		case WM_USER+1:
			::SetFocus(::GetDlgItem(hwnd_basic, IDC_CRYPT_PASSWORD));
			break;
		case WM_SIZE:
		{
		}
		case WM_COMMAND : 
	    {
		    switch (LOWORD(wParam))
		    {
			case IDC_OK:
					{
					// encryption dialog: ask for the password a second time:
					if(operation == Crypt::Operation::Encryption && !confirm_password) {

						::GetDlgItemText(hwnd_basic, IDC_CRYPT_PASSWORD, temp.password, Crypt::Constants::pw_length_max+1);
						if(lstrlen(temp.password)>0) {
							::SetDlgItemText(hwnd_basic, IDC_CRYPT_STATIC_PASSWORD, TEXT("Confirm:"));						
							::SetDlgItemText(hwnd_basic, IDC_CRYPT_PASSWORD, TEXT(""));
							::SetFocus(::GetDlgItem(hwnd_basic, IDC_CRYPT_PASSWORD));
							confirm_password=true;
						}
					} else {

						if(operation == Crypt::Operation::Encryption) {
							// Encryption: check if both entered passwords are the same, then update options and end dialog
							TCHAR temp_pw[Crypt::Constants::pw_length_max+1];
							::GetDlgItemText(hwnd_basic, IDC_CRYPT_PASSWORD, temp_pw, Crypt::Constants::pw_length_max+1);
							if(lstrcmp(temp.password, temp_pw)==0) {
								if(updateOptions())
									EndDialog(_hSelf, IDC_OK);
							} else {
								// passwords are not the same: restart password selection:
								::SetDlgItemText(hwnd_basic, IDC_CRYPT_STATIC_PASSWORD, TEXT("Password:"));
								::SetDlgItemText(hwnd_basic, IDC_CRYPT_PASSWORD, TEXT(""));
								::SetFocus(::GetDlgItem(hwnd_basic, IDC_CRYPT_PASSWORD));
								confirm_password=false;
							}
						} else {
							// Decryption: if password > 0, update options and end dialog
							::GetDlgItemText(hwnd_basic, IDC_CRYPT_PASSWORD, temp.password, Crypt::Constants::pw_length_max+1);
							if(lstrlen(temp.password)>0 && updateOptions()) {
								EndDialog(_hSelf, IDC_OK);
							}
						}
					}
					return TRUE; 
					}
				case IDC_CANCEL :
				    EndDialog(_hSelf, IDC_CANCEL);
					return TRUE;

				// --------------------- Key-derivation change --------------------------------------------------------------------------------------------------------
				case IDC_CRYPT_KEY_PBKDF2:
					if(temp.key_derivation != Crypt::KeyDerivation::pbkdf2) {
						temp.key_derivation = Crypt::KeyDerivation::pbkdf2;
						enableKeyDeriControls();
					}
					break;
				case IDC_CRYPT_KEY_BCRYPT:
					if(temp.key_derivation != Crypt::KeyDerivation::bcrypt) {
						temp.key_derivation = Crypt::KeyDerivation::bcrypt;
						enableKeyDeriControls();
					}
					break;
				case IDC_CRYPT_KEY_SCRYPT:
					if(temp.key_derivation != Crypt::KeyDerivation::scrypt) {
						temp.key_derivation = Crypt::KeyDerivation::scrypt;
						enableKeyDeriControls();
					}
					break;

				// --------------------- Key-Salting (de)activated ----------------------------------------------------------------------------------------------------
				case IDC_CRYPT_SALT:
					if(temp.key_derivation != Crypt::KeyDerivation::bcrypt) {
						bool c = ::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT, BM_GETCHECK, 0, 0) ? true : false;
						::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SALT_BYTES), c);
						::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SALT_SPIN), c);
					}
					break;

				// --------------------- hmac (de)activated -----------------------------------------------------------------------------------------------------------
				case IDC_CRYPT_HMAC_ENABLE:
					if(operation == Crypt::Operation::Encryption) {
						bool c = ::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_HMAC_ENABLE, BM_GETCHECK, 0, 0) ? true : false;
						::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_HMAC_HASH), c);
						::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_AUTH_KEY_PRESET), c);
						::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_AUTH_KEY_CUSTOM), c);
						::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_AUTH_KEY_LIST), c);
						::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_AUTH_KEY_VALUE), c);
						::EnableWindow(::GetDlgItem(hwnd_auth,IDC_CRYPT_AUTH_KEY_SHOW), c);
					};
					break;

				// --------------------- auth key-list selchange ------------------------------------------------------------------------------------------------------
				case IDC_CRYPT_AUTH_KEY_LIST:
					if(HIWORD(wParam)==CBN_SELCHANGE) {
						::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_PRESET, BM_SETCHECK, true, 0);
						::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_CUSTOM, BM_SETCHECK, false, 0);
					}
					break;
				case IDC_CRYPT_AUTH_KEY_CUSTOM:
					SendMessage(hwnd_auth, WM_NEXTDLGCTL, (WPARAM)GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_VALUE), TRUE);
					break;

				// --------------------- auth key-value show clear check ----------------------------------------------------------------------------------------------
				case IDC_CRYPT_AUTH_KEY_SHOW: {
					char c = ::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_SHOW, BM_GETCHECK, 0, 0) ? 0 : '*';
					::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_VALUE, EM_SETPASSWORDCHAR, c, 0);
					InvalidateRect(::GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_VALUE), 0, TRUE);
					break; }

				// --------------------- auth key-editbox change ------------------------------------------------------------------------------------------------------
				case IDC_CRYPT_AUTH_KEY_VALUE:
					if(HIWORD(wParam)== EN_SETFOCUS) {
						::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_CUSTOM, BM_SETCHECK, true, 0);
						::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_PRESET, BM_SETCHECK, false, 0);
					}
					break;

				// --------------------- Cipher-Combobox-Selchange ----------------------------------------------------------------------------------------------------
				case IDC_CRYPT_CIPHER:
					if(HIWORD(wParam)==CBN_SELCHANGE) {

						Crypt::Mode old_mode = Crypt::Strings::getModeByIndex(temp.cipher, ::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_GETCURSEL, 0, 0));
						temp.cipher = (Crypt::Cipher)::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_CIPHER, CB_GETCURSEL, 0, 0);						

						// refill combobox with the modes available for the current cipher:
						::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_RESETCONTENT, 0, 0);
						Crypt::Strings::setCipher(temp.cipher);
						while(Crypt::Strings::nextMode()) {
							::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_ADDSTRING, 0, (LPARAM)Crypt::Strings::Mode());
						}

						int cur_mode_count = ::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_GETCOUNT, 0, 0);
						if(cur_mode_count == 0) {
							::EnableWindow(::GetDlgItem(hwnd_basic,IDC_CRYPT_MODE),false);
						} else {
							::EnableWindow(::GetDlgItem(hwnd_basic,IDC_CRYPT_MODE),true);
							// check if the current cipher supports the old mode:
							int i = Crypt::Strings::getIndexByMode(temp.cipher, old_mode);
							if(i != -1) {
								::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_SETCURSEL, i, 0);
							} else {
								::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_SETCURSEL, 0, 0);
								if(old_mode == Crypt::Mode::gcm || old_mode == Crypt::Mode::xts)
									::EnableWindow(::GetDlgItem(hwnd_iv,IDC_CRYPT_IV_ZERO),true);
							}
						}
					}
					break;
				// --------------------- Mode-Combobox-Selchange -----------------------------------------------------------------------------------------------------
				case IDC_CRYPT_MODE:
					if(HIWORD(wParam)==CBN_SELCHANGE) {
						Crypt::Mode tmode = Crypt::Strings::getModeByIndex(temp.cipher, ::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_GETCURSEL, 0, 0));
						// gcm and xts mode: zero-byte iv not possible.
						if(tmode == Crypt::Mode::gcm || tmode == Crypt::Mode::xts) {
							if(::SendDlgItemMessage(hwnd_iv, IDC_CRYPT_IV_ZERO, BM_GETCHECK, 0, 0)) {
								::SendDlgItemMessage(hwnd_iv, IDC_CRYPT_IV_RANDOM, BM_SETCHECK, false, 0);
								::SendDlgItemMessage(hwnd_iv, IDC_CRYPT_IV_KEY, BM_SETCHECK, true, 0);
								::SendDlgItemMessage(hwnd_iv, IDC_CRYPT_IV_ZERO, BM_SETCHECK, false, 0);
							}
							::EnableWindow(::GetDlgItem(hwnd_iv,IDC_CRYPT_IV_ZERO),false);
						} else {
							::EnableWindow(::GetDlgItem(hwnd_iv,IDC_CRYPT_IV_ZERO),true);
						}
					}
					break;

			    default :
				    break;
		    }
		    break;
	    }
		case WM_NOTIFY:
		{
			switch( ( (LPNMHDR) lParam) -> code ) {

				case TCN_SELCHANGE: {
					switch(TabCtrl_GetCurSel(((LPNMHDR) lParam)->hwndFrom)) {
					case 0: ShowWindow( hwnd_basic, SW_SHOW );
							ShowWindow( hwnd_key, SW_HIDE );
							ShowWindow( hwnd_auth, SW_HIDE );
							ShowWindow( hwnd_iv, SW_HIDE );
							::EnableWindow(::GetDlgItem(_hSelf,IDC_OK),true);
							::SetFocus(::GetDlgItem(hwnd_basic, IDC_CRYPT_PASSWORD));
							break;
					case 1: ShowWindow( hwnd_basic, SW_HIDE );
							ShowWindow( hwnd_key, SW_SHOW );
							ShowWindow( hwnd_auth, SW_HIDE );
							ShowWindow( hwnd_iv, SW_HIDE );
							::EnableWindow(::GetDlgItem(_hSelf,IDC_OK),false);
							break;
					case 2: ShowWindow( hwnd_basic, SW_HIDE );
							ShowWindow( hwnd_key, SW_HIDE );
							ShowWindow( hwnd_auth, SW_SHOW );
							ShowWindow( hwnd_iv, SW_HIDE );
							::EnableWindow(::GetDlgItem(_hSelf,IDC_OK),false);
							break;
					case 3: ShowWindow( hwnd_basic, SW_HIDE );
							ShowWindow( hwnd_key, SW_HIDE );
							ShowWindow( hwnd_auth, SW_HIDE );
							ShowWindow( hwnd_iv, SW_SHOW );
							::EnableWindow(::GetDlgItem(_hSelf,IDC_OK),false);
							break;
					}
					break;
				}
			}
			break;
		}
	}
	return FALSE;
}

void DlgCrypt::enableKeyDeriControls()
{
	switch(temp.key_derivation) {
	case Crypt::KeyDerivation::pbkdf2:
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_PBKDF2_HASH),true);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_PBKDF2_ITER),true);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_PBKDF2_ITER_SPIN),true);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_BCRYPT_ITER),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_BCRYPT_ITER_SPIN),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_N),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_N_SPIN),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_R),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_R_SPIN),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_P),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_P_SPIN),false);
		// the salt-bytes edit may have got deactivated because bcrypt was chosen:
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SALT_BYTES),::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT, BM_GETCHECK, 0, 0));
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SALT_SPIN),::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT, BM_GETCHECK, 0, 0));
		break;
	case Crypt::KeyDerivation::bcrypt:
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_PBKDF2_HASH),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_PBKDF2_ITER),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_PBKDF2_ITER_SPIN),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_BCRYPT_ITER),true);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_BCRYPT_ITER_SPIN),true);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_N),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_N_SPIN),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_R),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_R_SPIN),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_P),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_P_SPIN),false);
		// bcrypt allows only 16 bytes salt:
		::SetDlgItemInt(hwnd_key, IDC_CRYPT_SALT_BYTES, 16, false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SALT_BYTES),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SALT_SPIN),false);
		break;
	case Crypt::KeyDerivation::scrypt:
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_PBKDF2_HASH),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_PBKDF2_ITER),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_PBKDF2_ITER_SPIN),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_BCRYPT_ITER),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_BCRYPT_ITER_SPIN),false);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_N),true);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_N_SPIN),true);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_R),true);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_R_SPIN),true);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_P),true);
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SCRYPT_P_SPIN),true);
		// the salt-bytes edit may have got deactivated because bcrypt was chosen:
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SALT_BYTES),::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT, BM_GETCHECK, 0, 0));
		::EnableWindow(::GetDlgItem(hwnd_key,IDC_CRYPT_SALT_SPIN),::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT, BM_GETCHECK, 0, 0));
		break;
	}
}

bool DlgCrypt::updateOptions()
{
	try {

		// get current cipher, cipher_mode and encoding
		options->cipher = (Crypt::Cipher)::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_CIPHER, CB_GETCURSEL, 0, 0);
		int t_mode = ::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_GETCURSEL, 0, 0);
		if(t_mode >= 0)
			options->mode = Crypt::Strings::getModeByIndex(options->cipher, t_mode);
		else
			options->mode = Crypt::Mode::cbc;
		if(::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_ENC_ASCII, BM_GETCHECK, 0, 0))
			options->encoding = Crypt::Encoding::ascii;
		else if(::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_ENC_HEX, BM_GETCHECK, 0, 0))
			options->encoding = Crypt::Encoding::hex;
		else
			options->encoding = Crypt::Encoding::base64;

		// salt
		if(::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT, BM_GETCHECK, 0, 0)) {
			options->key.salt_bytes = ::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT_SPIN, UDM_GETPOS32, 0, 0);
		} else {
			options->key.salt_bytes = 0;
		}

		// key-derivation algo
		if(::SendDlgItemMessage(hwnd_key, IDC_CRYPT_KEY_PBKDF2, BM_GETCHECK, 0, 0)) {
			options->key.algorithm = Crypt::KeyDerivation::pbkdf2;
			options->key.option1 = ::SendDlgItemMessage(hwnd_key, IDC_CRYPT_PBKDF2_HASH, CB_GETCURSEL, 0, 0);
			options->key.option2 = ::SendDlgItemMessage(hwnd_key, IDC_CRYPT_PBKDF2_ITER_SPIN, UDM_GETPOS32, 0, 0);
			options->key.option3 = 0;
		} else if(::SendDlgItemMessage(hwnd_key, IDC_CRYPT_KEY_BCRYPT, BM_GETCHECK, 0, 0)) {
			options->key.algorithm = Crypt::KeyDerivation::bcrypt;
			options->key.option1 = ::SendDlgItemMessage(hwnd_key, IDC_CRYPT_BCRYPT_ITER_SPIN, UDM_GETPOS32, 0, 0);
			options->key.option2 = 0;
			options->key.option3 = 0;
		} else {
			options->key.algorithm = Crypt::KeyDerivation::scrypt;
			options->key.option1 = ::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_N_SPIN, UDM_GETPOS32, 0, 0);
			options->key.option2 = ::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_R_SPIN, UDM_GETPOS32, 0, 0);
			options->key.option3 = ::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_P_SPIN, UDM_GETPOS32, 0, 0);
		}

		// iv
		if(::SendDlgItemMessage(hwnd_iv, IDC_CRYPT_IV_RANDOM, BM_GETCHECK, 0, 0))
			options->iv = Crypt::InitVector::random;
		else if(::SendDlgItemMessage(hwnd_iv, IDC_CRYPT_IV_KEY, BM_GETCHECK, 0, 0))
			options->iv = Crypt::InitVector::keyderivation;
		else
			options->iv = Crypt::InitVector::zero;

		// auth
		if(operation == Crypt::Operation::Encryption) 
		{
			options->hmac.enable = (::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_HMAC_ENABLE, BM_GETCHECK, 0, 0) ? true: false);
			options->hmac.hash = static_cast<Crypt::Hash>(::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_HMAC_HASH, CB_GETCURSEL, 0, 0));
			if(::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_PRESET, BM_GETCHECK, 0, 0))
			{
				options->hmac.key_id = ::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_LIST, CB_GETCURSEL, 0, 0);
			} 
			else {
				TCHAR temp_key[33];

				options->hmac.key_id = -1;
				::GetDlgItemText(hwnd_auth, IDC_CRYPT_AUTH_KEY_VALUE, temp_key, 33);
			
				#ifdef UNICODE
				Encode::wchar_to_utf8(temp_key, -1, options->hmac.key_input);
				#else
				options->hmac.key_input.assign(temp_key);
				#endif
			}
		}

		// convert the password to utf8
		#ifdef UNICODE
		Encode::wchar_to_utf8(temp.password, -1, options->password);
		for(size_t i=0; i<Crypt::Constants::pw_length_max; i++)
			temp.password[i]=0;
		#else
		options->password = std::string(temp.password);
		#endif
	}
	catch (CExc& exc) {
		::MessageBox(_hSelf, exc.getErrorMsg(), TEXT("Error"), MB_OK);
		return false;
	}
	return true;
}