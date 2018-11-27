## nppcrypt
[![Build status](https://ci.appveyor.com/api/projects/status/x5fsebx1ofk0qync?svg=true)](https://ci.appveyor.com/project/jeanpaulrichter/nppcrypt)

encryption-tool / plugin for notepad++ (https://notepad-plus-plus.org).

features: encryption/decryption with symmetric ciphers like aes. hash-functions like sha3. generation of random values (i.e. for passwords), various encoding options.

##### download:
1.0.1.5 from github:
* x64:: [download](https://github.com/jeanpaulrichter/nppcrypt/releases/download/1.0.1.5/nppcrypt_1.0.1.5_x64.zip)
* x86:: [download](https://github.com/jeanpaulrichter/nppcrypt/releases/download/1.0.1.5/nppcrypt_1.0.1.5_x86.zip)
* Linux version: see [FAQ: compiling nppcrypt](#faq_6)
###### old versions:
* 1.0.1.4: [x86](http://www.cerberus-design.de/nppcrypt_1.0.1.4_x86.zip) (md5: 038E4EF7D01858A3ED32F49ACAAADAC5), [x64](http://www.cerberus-design.de/nppcrypt_1.0.1.4_x64.zip) (md5: 0CE1EE405A930D083F74CB085667E73F)
* 1.0.1.3: [x86](http://www.cerberus-design.de/nppcrypt_1.0.1.3_x86.zip) (md5: 0191B7DA5389CE95D637705F13154ED6), [x64](http://www.cerberus-design.de/nppcrypt_1.0.1.3_x64.zip) (md5: B4F6C5BF060E9F5491EF5E7DF37D8D55)
* 1.0.1.2: [x86](http://www.cerberus-design.de/nppcrypt_1.0.1.2.zip) (md5: 08255E55BB4F5FD4ACED2E5849F0FAFA)
* 1.0.1.0: [x86](http://www.cerberus-design.de/nppcrypt_1.0.1.0.zip) (md5: B1260E531C39DD1E342D2CE5D85095C2)

##### email:
kontakt (at) cerberus-design . de

##### this software uses:

- [1] [crypto++](https://www.cryptopp.com) version 3.6.5, part of this project under [crypto++](src/cryptopp) ( base64.h and base64.cpp were modified to allow custom linebreaks )
- [2] [tinyxml2](http://www.grinninglizard.com/tinyxml2) version 2.1.0, part of this project under [tinyxml2](src/tinyxml2)
- [3] [bcrypt](http://www.openwall.com/crypt/) version 1.3, part of this project under [bcrypt](src/bcrypt)
- [4] [scrypt](https://www.tarsnap.com/scrypt.html) version 1.2.1, part of this project under [scrypt](src/scrypt)
- [5] [cli11](https://github.com/CLIUtils/CLI11)  part of this project under [cli11](src/cli11)

#### important:
This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

#### changelog
###### v1.0.1.5:
- see About 1.0.1.5
###### v1.0.1.4:
 - added ChaCha cipher & BLAKE2 hashes (cryptopp >v.5.6.3 needed)
 - interface improvements
 - major bcrypt bug fixed.
###### v1.0.1.3:
 - several dialogs (random/covert/hash) are now non-modal and dockable
 - added copy to clipboard buttons


----------
### FAQ


  - [What is this strange xml-stuff above my encrypted data all about?](#faq_1)
  - [What is a nppcrypt-file?](#faq_2)
  - [What are good options for strong encryption?](#faq_3)
  - [This version fails to decrypt stuff i encrypted with an older version!](#faq_4)
  - [nppcrypt shows me most of what went into the encryption (header), but is there other stuff i might want to know?](#faq_5)
  - [compiling nppcrypt](#faq_6)
  - [the commandline tool](#faq_7)
  - [text encodings](#faq_8)


##### <a name="faq_1"></a> 1. What is this strange xml-stuff above my encrypted data all about?
Well, first of all it would be quite hard to remember all the different options that were used for different encryptions. Secondly a lot of encryptions need additional data (IV, Salt, tag). Select this header together with your encrypted data and all this stuff will be read automaticly. Of course you can just delete the header and only select the encrypted data for decryption. But in this case you have to select all the right options yourself and provide the missing data (i.e. iv).

##### <a name="faq_2"></a>2. What is a nppcrypt-file?
In the preferences-dialog you can specify a nppcrypt-file-extension (like mp3 doc etc.). If you futhermore check the "enable" box nppcrypt will now monitor all files you open and save with notepad++. for example: you specified the nppcrypt-file-extension "nbak" and now you save a file as "secret.nbak": the encryption dialog will automaticly open and you 
can choose the encryption-method of your liking. the next time you open this file you will be automaticly asked for your password. #IMPORTANT#: nppcrypt does NOT monitor the auto-backup-feature of notepad++.

##### <a name="faq_3"></a>3. What are good options for strong encryption?
for example: aes/rijndael 256, gcm , 16-byte salt, scrypt (at least N=14, r=8, p=1, see google), random iv

##### <a name="faq_4"></a>4. This version fails to decrypt stuff i encrypted with an older version!
well, that should not happen, but... please downgrade to the older version (www.cerberus-design.de/downloads), decrypt and then reupdate. you might also send the exact problematic encryption-options to kontakt (at) cerberus-design . de

##### <a name="faq_5"></a>5. nppcrypt shows me most of what went into the encryption (header), but is there other stuff i might want to know?
1) all user input (passwords...) is converted to utf8.
2) bcrypt output is always 23 bytes long ( [wikipedia](https://en.wikipedia.org/wiki/Bcrypt) ). therefore it is hashed by keccak-shake128 to get the needed key-length.
3) some cipher modes provide authentication (gcm/ccm/eax). nppcrypt authenticates the IV and Salt data (as base64 strings) and the encrypted data.
4) nppcrypt can add an additional hmac value to authenticate the data (see auth-tab in encryption-dialog). for this purpose everything beween <nppcrypt> and </nppcrypt> in the header and the encrypted data is hashed.

##### <a name="faq_6"></a>6. compiling nppcrypt
- *Windows*: 

Download repository, open nppcrypt.sln under projects/msvc2017 and compile the project "nppcrypt" or the project "cmdline" (Microsoft Visual Studio 2017 needed)


- *Linux*:
```
git clone https://github.com/jeanpaulrichter/nppcrypt.git
cd nppcrypt
make
sudo make install
(OR: sudo make install target=global to copy nppcrypt to /usr/bin instead of /usr/local/bin)
```

##### <a name="faq_7"></a>7. the commandline tool
the two most basic options are: -a --action , where you can specify if you want to "hash", "encrypt" or "decrypt" and -o --output, where you specify an output file. Some options allow for additonal information to be passed via the seperator ":". i.e. "-k scrypt:16:9:2" means scrypt with (N=2^16,r=9,p=2) instead of the default values (N=14,r=8,p=1) you would get with "-k scrypt". see --help for more information.
examples:

decrypt .nppcrypt file:
```
nppcrypt -a decrypt test.nppcrypt
```
encrypt file "test.txt" with default settings:
```
nppcrypt -a encrypt -o test.nppcrypt test.txt
```
get md5, sha1 and sha3 hash of file "download.zip" (and optionally check hex-string against it):
```
nppcrypt download.zip
```
get blake2s hash of "teststring"
```
nppcrypt --hash blake2s teststring
```

##### <a name="faq_8"></a>8. text encodings
the notepad++ plugin will work with utf16/ucs-2 files, but if you want to use nppcrypt it is recommended that you only use utf8 files. the commandline tool writes only utf8 files and cannot read utf8-encoded nppcrypt-files.
