/*
This file is part of the nppcrypt
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

#define VS_VERSION_INFO                 1
#define IDD_ABOUT                       101
#define IDD_HASH                        102
#define IDD_RANDOM                      103
#define IDD_PREFERENCES                 104
#define IDD_CRYPT                       105
#define IDD_CRYPT_BASIC                 106
#define IDD_CRYPT_AUTH                  107
#define IDD_CRYPT_KEY                   108
#define IDD_CRYPT_IV                    109
#define IDD_CRYPT_ENCODING              110
#define IDD_AUTH                        111
#define IDD_CONVERT                     112
#define IDD_INITDATA                    113

#define IDC_STATIC                      -1
#define IDC_OK                          998
#define IDC_CANCEL                      999

#define IDC_CRYPT_TAB                   1000
#define IDC_CRYPT_CIPHER                1001
#define IDC_CRYPT_CIPHER_TYPE           1002
#define IDC_CRYPT_CIPHER_INFO           1003
#define IDC_CRYPT_MODE                  1004
#define IDC_CRYPT_STATIC_PASSWORD       1005
#define IDC_CRYPT_PASSWORD              1006
#define IDC_CRYPT_ENC_ASCII             1007
#define IDC_CRYPT_ENC_BASE64            1008
#define IDC_CRYPT_ENC_LINEBREAK         1009
#define IDC_CRYPT_ENC_LINELEN           1010
#define IDC_CRYPT_ENC_LINELEN_SPIN      1011
#define IDC_CRYPT_ENC_BASE16            1012
#define IDC_CRYPT_ENC_BASE32            1013
#define IDC_CRYPT_ENC_HELP              1014
#define IDC_CRYPT_ENC_LB_WIN            1015
#define IDC_CRYPT_ENC_LB_UNIX           1016
#define IDC_CRYPT_ENC_UPPERCASE         1017
#define IDC_CRYPT_SALT                  1018
#define IDC_CRYPT_SALT_BYTES            1019
#define IDC_CRYPT_SALT_SPIN             1020
#define IDC_CRYPT_KEY_PBKDF2            1021
#define IDC_CRYPT_KEY_BCRYPT            1022
#define IDC_CRYPT_KEY_SCRYPT            1023
#define IDC_CRYPT_PBKDF2_HASH           1024
#define IDC_CRYPT_PBKDF2_ITER           1025
#define IDC_CRYPT_PBKDF2_ITER_SPIN      1026
#define IDC_CRYPT_BCRYPT_ITER           1027
#define IDC_CRYPT_BCRYPT_ITER_SPIN      1028
#define IDC_CRYPT_SCRYPT_N              1029
#define IDC_CRYPT_SCRYPT_R              1030
#define IDC_CRYPT_SCRYPT_P              1031
#define IDC_CRYPT_SCRYPT_R_SPIN         1032
#define IDC_CRYPT_SCRYPT_P_SPIN         1033
#define IDC_CRYPT_SCRYPT_N_SPIN         1034
#define IDC_CRYPT_HMAC_ENABLE           1035
#define IDC_CRYPT_HMAC_HASH             1036
#define IDC_CRYPT_AUTH_KEY_LIST         1037
#define IDC_CRYPT_AUTH_KEY_PRESET       1038
#define IDC_CRYPT_AUTH_KEY_CUSTOM       1039
#define IDC_CRYPT_AUTH_PW_VALUE			1040
#define IDC_CRYPT_AUTH_KEY_SHOW         1041
#define IDC_CRYPT_IV_RANDOM             1042
#define IDC_CRYPT_IV_KEY                1043
#define IDC_CRYPT_IV_ZERO               1044
#define IDC_CRYPT_HELP_MODE             1045
#define IDC_CRYPT_HELP_CIPHER           1046
#define IDC_CRYPT_HELP_SALT             1047
#define IDC_CRYPT_HELP_IV               1048
#define IDC_CRYPT_HELP_KEYALGO          1049
#define IDC_CRYPT_HELP_HMAC             1050
#define IDC_CRYPT_PASSWORD_ENC          1051
#define IDC_CRYPT_IV_ENC				1052
#define IDC_CRYPT_IV_INPUT				1053
#define IDC_CRYPT_IV_CUSTOM				1054
#define IDC_CRYPT_AUTH_PW_ENC			1055
#define IDC_CRYPT_AUTH_STATIC			1056
#define IDC_CRYPT_ENC_STATIC			1057
#define IDC_AUTH_KEY_ENC				1058

#define IDC_HASH_ALGO                   1000
#define IDC_HASH_ENC_ASCII              1001
#define IDC_HASH_KEYLIST                1002
#define IDC_HASH_ENC_BASE16             1003
#define IDC_HASH_ENC_BASE64             1004
#define IDC_HASH_USE_KEY                1005
#define IDC_HASH_KEY                    1006
#define IDC_HASH_KEYRADIO1              1007
#define IDC_HASH_KEYRADIO2              1008
#define IDC_HASH_PWEDIT                 1009
#define IDC_HASH_HELP_HASH              1010
#define IDC_HASH_ENC_BASE32             1011
#define IDC_HASH_TOCLIPBOARD			1012
#define IDC_HASH_PW_STATIC				1013
#define IDC_HASH_KEY_STATIC				1014

#define IDC_RANDOM_EDIT                 1000
#define IDC_RANDOM_SPIN                 1001
#define IDC_RANDOM_R1                   1002
#define IDC_RANDOM_R2                   1003
#define IDC_RANDOM_R3                   1004
#define IDC_RANDOM_R4                   1005
#define IDC_RANDOM_R5                   1006
#define IDC_RANDOM_R6                   1007
#define IDC_RANDOM_TOCLIPBOARD			1008

#define IDC_PREF_FILES_ENABLE           1000
#define IDC_PREF_FILES_EXT              1001
#define IDC_PREF_FILES_ASK              1002
#define IDC_PREF_KEYS_LIST              1003
#define IDC_PREF_KEYS_LABEL             1004
#define IDC_PREF_KEYS_VALUE             1005
#define IDC_PREF_KEYS_ADD               1006
#define IDC_PREF_KEYS_DEL               1007
#define IDC_PREF_KEYS_RANDOM            1008
#define IDC_PREF_ERROR					1009

#define IDC_CONVERT_FROM_ASCII          1000
#define IDC_CONVERT_FROM_BASE16         1001
#define IDC_CONVERT_FROM_BASE32         1002
#define IDC_CONVERT_FROM_BASE64         1003
#define IDC_CONVERT_TO_ASCII            1004
#define IDC_CONVERT_TO_BASE16           1005
#define IDC_CONVERT_TO_BASE32           1006
#define IDC_CONVERT_TO_BASE64           1007
#define IDC_CONVERT_LINEBREAKS          1008
#define IDC_CONVERT_LINELENGTH          1009
#define IDC_CONVERT_LINELENGTH_SPIN     1010
#define IDC_CONVERT_LB_WINDOWS          1011
#define IDC_CONVERT_LB_UNIX             1012
#define IDC_CONVERT_UPPERCASE           1013
#define IDC_CONVERT_TOCLIPBOARD			1014

#define IDC_INITDATA_SALT               1000
#define IDC_INITDATA_IV                 1001
#define IDC_INITDATA_TAG                1002

#define IDC_AUTH_KEY                    1000
#define IDC_AUTH_SHOW                   1001

#define IDC_ABOUT_VERSION				1000
#define IDC_ABOUT_GITHUB				1001
#define IDC_ABOUT_CRYPTOPP				1002
#define IDC_ABOUT_TINYXML2				1003
#define IDC_ABOUT_BCRYPT				1004
#define IDC_ABOUT_SCRYPT				1005
