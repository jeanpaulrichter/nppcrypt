#include "help.h"
#include "exception.h"
#include "mdef.h"
#include "preferences.h"
#include "npp/PluginInterface.h"
#include "npp/Definitions.h"

extern NppData		nppData;
extern HINSTANCE	m_hInstance;
extern FuncItem		funcItem[NPPC_FUNC_COUNT];

HWND helper::Scintilla::getCurrent()
{
	int which = -1;
	::SendMessage(nppData._nppHandle, NPPM_GETCURRENTSCINTILLA, 0, (LPARAM)&which);
	if (which == 0)	{
		return nppData._scintillaMainHandle;
	} else if (which == 1) {
		return nppData._scintillaSecondHandle;
	} else {
		throw CExc(CExc::File::help, __LINE__);
	}
}

bool helper::Scintilla::getSelection(const byte** pdata, size_t* length, size_t* start, size_t* end)
{
	if (pdata == NULL || length == NULL) {
		return false;
	}
	*pdata = NULL;
	*length = 0;

	HWND hCurScintilla = helper::Scintilla::getCurrent();
	size_t selStart = ::SendMessage(hCurScintilla, SCI_GETSELECTIONSTART, 0, 0);
	size_t selEnd = ::SendMessage(hCurScintilla, SCI_GETSELECTIONEND, 0, 0);
	size_t data_length = selEnd - selStart;

	if (start != NULL) {
		*start = selStart;
	}
	if (end != NULL) {
		*end = selEnd;
	}
	if (data_length <= 0) {
		return false;
	}

	*pdata = (const byte*)::SendMessage(hCurScintilla, SCI_GETRANGEPOINTER, selStart, selEnd);
	if (pdata == NULL) {
		return false;
	}
	*length = data_length;

	return true;
}

void helper::Scintilla::replaceSelection(const std::basic_string<byte>& buffer)
{
	HWND hCurScintilla = helper::Scintilla::getCurrent();
	size_t selStart = ::SendMessage(hCurScintilla, SCI_GETSELECTIONSTART, 0, 0);
	::SendMessage(hCurScintilla, SCI_BEGINUNDOACTION, 0, 0);
	::SendMessage(hCurScintilla, SCI_TARGETFROMSELECTION, 0, 0);
	::SendMessage(hCurScintilla, SCI_REPLACETARGET, buffer.size(), (LPARAM)&buffer[0]);
	::SendMessage(hCurScintilla, SCI_SETSEL, selStart, selStart + buffer.size());
	::SendMessage(hCurScintilla, SCI_ENDUNDOACTION, 0, 0);
}

// ---------------------------------------------------------------------------------------------------------------------

uptr_t helper::Buffer::getCurrent()
{
	return ::SendMessage(nppData._nppHandle, NPPM_GETCURRENTBUFFERID, 0, 0);
}

bool helper::Buffer::is8Bit(uptr_t id)
{
	int cur_buffer_enc = (int)::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, id, 0);
	return (cur_buffer_enc == uni8Bit || cur_buffer_enc == uniUTF8 || cur_buffer_enc == uniCookie);
}

bool helper::Buffer::isCurrent8Bit()
{
	int cur_buffer_enc = (int)::SendMessage(nppData._nppHandle, NPPM_GETBUFFERENCODING, ::SendMessage(nppData._nppHandle, NPPM_GETCURRENTBUFFERID, 0, 0), 0);
	return (cur_buffer_enc == uni8Bit || cur_buffer_enc == uniUTF8 || cur_buffer_enc == uniCookie);
}

void helper::Buffer::getPath(uptr_t bufferid, string& path, string& filename, string& extension)
{
	int path_length = (int)::SendMessage(nppData._nppHandle, NPPM_GETFULLPATHFROMBUFFERID, bufferid, NULL);
	if (path_length <= 0)
		throw CExc(CExc::File::nppcrypt, __LINE__);
	path.resize(path_length + 1);
	::SendMessage(nppData._nppHandle, NPPM_GETFULLPATHFROMBUFFERID, bufferid, (LPARAM)&path[0]);
	path.pop_back();
	size_t x = path.find_last_of('/');
	size_t x2 = path.find_last_of('\\');
	if (x2 > x || x == std::string::npos) {
		x = x2;
	}
	filename = path.substr(x + 1);
	x = filename.find_last_of('.');
	if (x != std::string::npos && filename.size() > x) {
		extension = filename.substr(x + 1);
	}
}

// ---------------------------------------------------------------------------------------------------------------------

void helper::Windows::copyToClipboard(const std::basic_string<byte>& buffer)
{
	if (!OpenClipboard(NULL)) {
		return;
	}
	EmptyClipboard();

	HGLOBAL hglbCopy = GlobalAlloc(GMEM_MOVEABLE, (buffer.size() + 1) * sizeof(byte));
	if (hglbCopy == NULL) {
		CloseClipboard();
		return;
	}

	unsigned char *lpucharCopy = (unsigned char *)GlobalLock(hglbCopy);
	memcpy(lpucharCopy, buffer.c_str(), buffer.size() * sizeof(byte));
	lpucharCopy[buffer.size()] = 0;
	GlobalUnlock(hglbCopy);

	SetClipboardData(CF_TEXT, hglbCopy);

	HGLOBAL hglbLenCopy = GlobalAlloc(GMEM_MOVEABLE, sizeof(unsigned long));
	if (hglbLenCopy == NULL) {
		CloseClipboard();
		return;
	}

	unsigned long *lpLenCopy = (unsigned long *)GlobalLock(hglbLenCopy);
	*lpLenCopy = (unsigned long)buffer.size();
	GlobalUnlock(hglbLenCopy);

	UINT f = RegisterClipboardFormat(CF_NPPTEXTLEN);
	SetClipboardData(f, hglbLenCopy);

	CloseClipboard();
}

// ---------------------------------------------------------------------------------------------------------------------

HINSTANCE helper::NPP::getDLLHandle()
{
	return m_hInstance;
}

HWND helper::NPP::getWindow()
{
	return nppData._nppHandle;
}

bool helper::NPP::setCommand(size_t index, TCHAR *cmdName, PFUNCPLUGINCMD pFunc, ShortcutKey *sk, bool check0nInit)
{
	if (index >= NPPC_FUNC_COUNT) {
		return false;
	}
	if (!pFunc) {
		return false;
	}

	lstrcpy(funcItem[index]._itemName, cmdName);
	funcItem[index]._pFunc = pFunc;
	funcItem[index]._init2Check = check0nInit;
	funcItem[index]._pShKey = sk;

	return true;
}

// ---------------------------------------------------------------------------------------------------------------------

void helper::BC::prepareHMAC(crypt::Options::Crypt::HMAC& hmac, int header_version)
{
	if (hmac.enable) {
		if (hmac.key_id >= 0) {
			const unsigned char* tkey = preferences.getKey(hmac.key_id);
			hmac.key.assign(tkey, tkey + 16);
		} else {
			hmac.key.resize(16);
			if (header_version <= 101) {
				hmac.key_input.push_back(0);
			}
			crypt::shake128((const unsigned char*)hmac.key_input.c_str(), hmac.key_input.size(), &hmac.key[0], 16);
			if (header_version <= 101) {
				hmac.key_input.pop_back();
			}
		}
	}
}

void helper::BC::preparePassword(std::string& password, int header_version)
{
	if (header_version <= 101) {
		password.push_back(0);
	}
	else {
		if (password.size() > 0 && password.back() == 0)
			password.pop_back();
	}
}
