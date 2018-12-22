/*
This file is part of the nppcrypt
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

#include <string>
#include <iostream>
#include <clocale>
#include "clihelp.h"
#ifdef _WIN32
#include <windows.h>
#else
#undef __USE_CRYPT
#include <termios.h>
#include <unistd.h>
#endif

void setEcho(bool enable)
{
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    if (!enable) {
        mode &= ~ENABLE_ECHO_INPUT;
    } else {
        mode |= ENABLE_ECHO_INPUT;
    }
    SetConsoleMode(hStdin, mode);
#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable) {
        tty.c_lflag &= ~ECHO;
    } else {
        tty.c_lflag |= ECHO;
    }
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

bool setLocale()
{
    bool ret = true;
#ifdef WIN32
    if (IsValidCodePage(CP_UTF8)) {
        if (!SetConsoleCP(CP_UTF8)) {
            ret = false;
        }
        if (!SetConsoleOutputCP(CP_UTF8)) {
            ret = false;
        }
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        typedef BOOL(WINAPI * pfSetCurrentConsoleFontEx)(HANDLE, BOOL, PCONSOLE_FONT_INFOEX);
        HMODULE hMod = GetModuleHandle(TEXT("kernel32.dll"));
        pfSetCurrentConsoleFontEx pfSCCFX = (pfSetCurrentConsoleFontEx)GetProcAddress(hMod, "SetCurrentConsoleFontEx");

        CONSOLE_FONT_INFOEX cfix;
        cfix.cbSize = sizeof(cfix);
        cfix.nFont = 12;
        cfix.dwFontSize.X = 8;
        cfix.dwFontSize.Y = 14;
        cfix.FontFamily = FF_DONTCARE;
        cfix.FontWeight = 400;
        lstrcpy(cfix.FaceName, TEXT("Lucida Console"));

        pfSCCFX(hConsole, FALSE, &cfix);
        //setlocale(LC_ALL, "de_DE.UTF-8");
        //std::setlocale(LC_ALL, "de_DE.UTF-8");
    }
#endif
    
    return ret;
}

void readLine(crypt::secure_string& out)
{
#ifdef WIN32
    HANDLE hConsole = GetStdHandle(STD_INPUT_HANDLE);
    wchar_t buf[512];
    unsigned long read;
    ReadConsole(hConsole, buf, 512, &read, nullptr);
    int bytelen = WideCharToMultiByte(CP_UTF8, 0, buf, read, NULL, 0, NULL, false);
    if (bytelen > 0) {
        out.resize((size_t)bytelen);
        if (!WideCharToMultiByte(CP_UTF8, 0, buf, read, &out[0], bytelen, NULL, false)) {
            out.clear();
        }
        while (out.size() && (out.back() == '\n' || out.back() == '\r')) {
            out.pop_back();
        }
    }
    for (size_t i = 0; i < 512; i++) {
        buf[i] = 0;
    }
#else
    std::getline(std::cin, out);
#endif
}