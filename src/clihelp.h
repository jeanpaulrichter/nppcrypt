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

#ifndef CLIHELP_H_DEF
#define CLIHELP_H_DEF

#include "crypt.h"

/* Set console echo (in own file because unistd.h pollutes the global namespace...) */
void setEcho(bool enable = true);
bool setLocale();
void readLine(crypt::secure_string& out);

#endif
