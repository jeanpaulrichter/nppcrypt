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

#define IDI_HELPCTRL_NORMAL				201
#define IDI_HELPCTRL_NORMAL_HOVER		202
#define IDI_HELPCTRL_WARNING			203
#define IDI_HELPCTRL_WARNING_HOVER		204
#define IDI_HELPCTRL_DISABLED			205

#define IDC_CRYPT_TAB                   1000
#define IDC_CRYPT_CIPHER                1001
#define IDC_CRYPT_CIPHER_TYPE           1002
#define IDC_CRYPT_CIPHER_INFO           1003
#define IDC_CRYPT_MODE                  1004
#define IDC_CRYPT_PASSWORD_STATIC       1005
#define IDC_CRYPT_PASSWORD              1006
#define IDC_CRYPT_PASSWORD_ENC          1007
#define IDC_CRYPT_PASSWORD_SHOW			1008
#define IDC_CRYPT_ENC_ASCII             1009
#define IDC_CRYPT_ENC_BASE64            1010
#define IDC_CRYPT_ENC_LINEBREAK         1011
#define IDC_CRYPT_ENC_LINELEN           1012
#define IDC_CRYPT_ENC_LINELEN_SPIN      1013
#define IDC_CRYPT_ENC_BASE16            1014
#define IDC_CRYPT_ENC_BASE32            1015
#define IDC_CRYPT_ENC_HELP              1016
#define IDC_CRYPT_ENC_LB_WIN            1017
#define IDC_CRYPT_ENC_LB_UNIX           1018
#define IDC_CRYPT_ENC_UPPERCASE         1019
#define IDC_CRYPT_ENC_STATIC			1020
#define IDC_CRYPT_SALT                  1021
#define IDC_CRYPT_SALT_BYTES            1022
#define IDC_CRYPT_SALT_SPIN             1023
#define IDC_CRYPT_SALT_STATIC			1024
#define IDC_CRYPT_KEY_PBKDF2            1025
#define IDC_CRYPT_KEY_BCRYPT            1026
#define IDC_CRYPT_KEY_SCRYPT            1027
#define IDC_CRYPT_PBKDF2_HASH           1028
#define IDC_CRYPT_PBKDF2_ITER           1029
#define IDC_CRYPT_PBKDF2_ITER_SPIN      1030
#define IDC_CRYPT_BCRYPT_ITER           1032
#define IDC_CRYPT_BCRYPT_ITER_SPIN      1033
#define IDC_CRYPT_BCRYPT_STATIC1		1034
#define IDC_CRYPT_BCRYPT_STATIC2		1035
#define IDC_CRYPT_SCRYPT_N              1036
#define IDC_CRYPT_SCRYPT_R              1037
#define IDC_CRYPT_SCRYPT_P              1038
#define IDC_CRYPT_SCRYPT_R_SPIN         1039
#define IDC_CRYPT_SCRYPT_P_SPIN         1040
#define IDC_CRYPT_SCRYPT_N_SPIN         1041
#define IDC_CRYPT_SCRYPT_STATIC1		1042
#define IDC_CRYPT_SCRYPT_STATIC2		1043
#define IDC_CRYPT_SCRYPT_STATIC3		1044
#define IDC_CRYPT_AUTH_ENABLE           1045
#define IDC_CRYPT_AUTH_HASH             1046
#define IDC_CRYPT_AUTH_KEY_LIST         1047
#define IDC_CRYPT_AUTH_KEY_PRESET       1048
#define IDC_CRYPT_AUTH_KEY_CUSTOM       1049
#define IDC_CRYPT_AUTH_PW_VALUE			1050
#define IDC_CRYPT_AUTH_PW_ENC			1051
#define IDC_CRYPT_AUTH_PW_SHOW			1052
#define IDC_CRYPT_AUTH_STATIC1			1053
#define IDC_CRYPT_IV_RANDOM             1054
#define IDC_CRYPT_IV_KEY                1055
#define IDC_CRYPT_IV_ZERO               1056
#define IDC_CRYPT_IV_CUSTOM				1057
#define IDC_CRYPT_IV_ENC				1058
#define IDC_CRYPT_IV_INPUT				1059
#define IDC_CRYPT_HELP_MODE             1060
#define IDC_CRYPT_HELP_CIPHER           1061
#define IDC_CRYPT_HELP_SALT             1062
#define IDC_CRYPT_HELP_IV               1063
#define IDC_CRYPT_HELP_KEYALGO          1064
#define IDC_CRYPT_AUTH_HELP             1065
#define IDC_CRYPT_KEYLENGTH				1066
#define IDC_CRYPT_PBKDF2_HASH_LENGTH	1067
#define IDC_CRYPT_PBKDF2_STATIC1		1068
#define IDC_CRYPT_PBKDF2_STATIC3		1070
#define IDC_CRYPT_AUTH_HASH_LENGTH		1071

#define IDC_HASH_ALGO                   1000
#define IDC_HASH_ENC_ASCII              1001
#define IDC_HASH_KEYLIST                1002
#define IDC_HASH_ENC_BASE16             1003
#define IDC_HASH_ENC_BASE64             1004
#define IDC_HASH_USE_KEY                1005
#define IDC_HASH_KEY                    1006
#define IDC_HASH_KEYRADIO1              1007
#define IDC_HASH_KEYRADIO2              1008
#define IDC_HASH_ALGO_HELP				1009
#define IDC_HASH_ENC_BASE32             1010
#define IDC_HASH_TOCLIPBOARD			1011
#define IDC_HASH_KEY_ENC				1012
#define IDC_HASH_KEY_SHOW				1013
#define IDC_HASH_DIGESTS				1014
#define IDC_HASH_ENC_HELP				1015

#define IDC_RANDOM_EDIT                 1000
#define IDC_RANDOM_SPIN                 1001
#define IDC_RANDOM_ENC_BINARY           1002
#define IDC_RANDOM_ENC_BASE16           1003
#define IDC_RANDOM_ENC_BASE32           1004
#define IDC_RANDOM_ENC_BASE64           1005
#define IDC_RANDOM_ENC_HELP             1006
#define IDC_RANDOM_BINARY               1007
#define IDC_RANDOM_DIGITS               1008
#define IDC_RANDOM_LETTERS              1009
#define IDC_RANDOM_ALPHANUM             1010
#define IDC_RANDOM_PASSWORD             1011
#define IDC_RANDOM_SPECIALS             1012
#define IDC_RANDOM_TOCLIPBOARD			1013
#define IDC_RANDOM_HELP					1014

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
#define IDC_CONVERT_STATIC1				1015

#define IDC_INITDATA_SALT               1000
#define IDC_INITDATA_TAG                1002
#define IDC_INITDATA_SALT_ENC			1003
#define IDC_INITDATA_TAG_ENC			1004

#define IDC_AUTH_KEY                    1000
#define IDC_AUTH_KEY_ENC				1001
#define IDC_AUTH_SHOW                   1002

#define IDC_ABOUT_VERSION				1000
#define IDC_ABOUT_GITHUB				1001
#define IDC_ABOUT_CRYPTOPP				1002
#define IDC_ABOUT_TINYXML2				1003
#define IDC_ABOUT_BCRYPT				1004
#define IDC_ABOUT_SCRYPT				1005
