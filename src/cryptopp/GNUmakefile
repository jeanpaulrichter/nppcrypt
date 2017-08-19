###########################################################
#####        System Attributes and Programs           #####
###########################################################

AR ?= ar
ARFLAGS ?= -cr # ar needs the dash on OpenBSD
RANLIB ?= ranlib

CP ?= cp
MV ?= mv
EGREP ?= egrep
CHMOD ?= chmod
MKDIR ?= mkdir
LN ?= ln -sf
LDCONF ?= /sbin/ldconfig -n
UNAME := $(shell uname)

IS_X86 := $(shell uname -m | $(EGREP) -v "x86_64" | $(EGREP) -i -c "i.86|x86|i86")
IS_X32 ?= 0
IS_X64 := $(shell uname -m | $(EGREP) -i -c "(_64|d64)")
IS_PPC := $(shell uname -m | $(EGREP) -i -c "ppc|power")
IS_ARM32 := $(shell uname -m | $(EGREP) -i -c "arm")
IS_ARM64 := $(shell uname -m | $(EGREP) -i -c "aarch64")

IS_SUN := $(shell uname | $(EGREP) -i -c "SunOS")
IS_LINUX := $(shell $(CXX) -dumpmachine 2>&1 | $(EGREP) -i -c "Linux")
IS_MINGW := $(shell $(CXX) -dumpmachine 2>&1 | $(EGREP) -i -c "MinGW")
IS_CYGWIN := $(shell $(CXX) -dumpmachine 2>&1 | $(EGREP) -i -c "Cygwin")
IS_DARWIN := $(shell $(CXX) -dumpmachine 2>&1 | $(EGREP) -i -c "Darwin")
IS_NETBSD := $(shell $(CXX) -dumpmachine 2>&1 | $(EGREP) -i -c "NetBSD")

SUN_COMPILER := $(shell $(CXX) -V 2>&1 | $(EGREP) -i -c "CC: (Sun|Studio)")
GCC_COMPILER := $(shell $(CXX) --version 2>&1 | $(EGREP) -i -v "clang" | $(EGREP) -i -c "(gcc|g\+\+)")
CLANG_COMPILER := $(shell $(CXX) --version 2>&1 | $(EGREP) -i -c "clang")
INTEL_COMPILER := $(shell $(CXX) --version 2>&1 | $(EGREP) -i -c "\(icc\)")
MACPORTS_COMPILER := $(shell $(CXX) --version 2>&1 | $(EGREP) -i -c "macports")

# Sun Studio 12.0 provides SunCC 0x0510; and Sun Studio 12.3 provides SunCC 0x0512
SUNCC_510_OR_LATER := $(shell $(CXX) -V 2>&1 | $(EGREP) -c "CC: (Sun|Studio) .* (5\.1[0-9]|5\.[2-9]|6\.)")
SUNCC_511_OR_LATER := $(shell $(CXX) -V 2>&1 | $(EGREP) -c "CC: (Sun|Studio) .* (5\.1[1-9]|5\.[2-9]|6\.)")
SUNCC_512_OR_LATER := $(shell $(CXX) -V 2>&1 | $(EGREP) -c "CC: (Sun|Studio) .* (5\.1[2-9]|5\.[2-9]|6\.)")
SUNCC_513_OR_LATER := $(shell $(CXX) -V 2>&1 | $(EGREP) -c "CC: (Sun|Studio) .* (5\.1[3-9]|5\.[2-9]|6\.)")

HAS_SOLIB_VERSION := $(IS_LINUX)

# Fixup SunOS
ifeq ($(IS_SUN),1)
IS_X86 := $(shell isainfo -k 2>/dev/null | grep -i -c "i386")
IS_X64 := $(shell isainfo -k 2>/dev/null | grep -i -c "amd64")
endif

###########################################################
#####                General Variables                #####
###########################################################

# Base CXXFLAGS used if the user did not specify them
ifeq ($(SUN_COMPILER),1)
  ifeq ($(SUNCC_512_OR_LATER),1)
    CXXFLAGS ?= -DNDEBUG -g3 -xO2
  else
    CXXFLAGS ?= -DNDEBUG -g -xO2
  endif
else
  CXXFLAGS ?= -DNDEBUG -g2 -O2
endif

# Default prefix for make install
ifeq ($(PREFIX),)
PREFIX = /usr/local
endif

# http://www.gnu.org/prep/standards/html_node/Directory-Variables.html
ifeq ($(DATADIR),)
DATADIR := $(PREFIX)/share
endif
ifeq ($(LIBDIR),)
LIBDIR := $(PREFIX)/lib
endif
ifeq ($(BINDIR),)
BINDIR := $(PREFIX)/bin
endif
ifeq ($(INCLUDEDIR),)
INCLUDEDIR := $(PREFIX)/include
endif

# Fix CXX on Cygwin 1.1.4
ifeq ($(CXX),gcc)
CXX := g++
endif

# We honor ARFLAGS, but the "v" option used by default causes a noisy make
ifeq ($(ARFLAGS),rv)
ARFLAGS = r
endif

###########################################################
#####               X86/X32/X64 Options               #####
###########################################################

ifneq ($(IS_X86)$(IS_X32)$(IS_X64),000)

# Fixup. Clang integrated assembler will be used (-Wa,-q)
ifneq ($(MACPORTS_COMPILER),1)
  IS_GAS := $(shell $(CXX) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(EGREP) -c "GNU assembler")
endif

ifneq ($(GCC_COMPILER),0)
  IS_GCC_29 := $(shell $(CXX) -v 2>&1 | $(EGREP) -i -c gcc-9[0-9][0-9])
  GCC42_OR_LATER := $(shell $(CXX) -v 2>&1 | $(EGREP) -i -c "gcc version (4\.[2-9]|[5-9]\.)")
  GCC46_OR_LATER := $(shell $(CXX) -v 2>&1 | $(EGREP) -i -c "gcc version (4\.[6-9]|[5-9]\.)")
endif

ifneq ($(IS_GAS),0)
  GAS210_OR_LATER := $(shell $(CXX) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(EGREP) -c "GNU assembler version (2\.[1-9][0-9]|[3-9])")
  GAS217_OR_LATER := $(shell $(CXX) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(EGREP) -c "GNU assembler version (2\.1[7-9]|2\.[2-9]|[3-9])")
  GAS219_OR_LATER := $(shell $(CXX) -xc -c /dev/null -Wa,-v -o/dev/null 2>&1 | $(EGREP) -c "GNU assembler version (2\.19|2\.[2-9]|[3-9])")
endif

ICC111_OR_LATER := $(shell $(CXX) --version 2>&1 | $(EGREP) -c "\(ICC\) ([2-9][0-9]|1[2-9]|11\.[1-9])")

# Add -fPIC for targets *except* X86, X32, Cygwin or MinGW
ifeq ($(IS_X86)$(IS_X32)$(IS_CYGWIN)$(IS_MINGW)$(SUN_COMPILER),00000)
 ifeq ($(findstring -fPIC,$(CXXFLAGS)),)
   CXXFLAGS += -fPIC
 endif
endif

# Guard use of -march=native
ifeq ($(GCC42_OR_LATER)$(IS_NETBSD),10)
   CXXFLAGS += -march=native
else ifneq ($(CLANG_COMPILER)$(INTEL_COMPILER),00)
   CXXFLAGS += -march=native
else
  # GCC 3.3 and "unknown option -march="
  # Ubuntu GCC 4.1 compiler crash with -march=native
  # NetBSD GCC 4.8 compiler and "bad value (native) for -march= switch"
  # Sun compiler is handled below
  ifeq ($(SUN_COMPILER)$(IS_X64),01)
    CXXFLAGS += -m64
  else ifeq ($(SUN_COMPILER)$(IS_X86),01)
    CXXFLAGS += -m32
  endif # X86/X32/X64
endif

# Aligned access required for -O3 and above due to vectorization
UNALIGNED_ACCESS := $(shell $(EGREP) -c "^[[:space:]]*//[[:space:]]*\#[[:space:]]*define[[:space:]]*CRYPTOPP_NO_UNALIGNED_DATA_ACCESS" config.h)
ifneq ($(UNALIGNED_ACCESS),0)
ifeq ($(findstring -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS,$(CXXFLAGS)),)
ifeq ($(findstring -O3,$(CXXFLAGS)),-O3)
CXXFLAGS += -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS
endif # -O3
ifeq ($(findstring -O5,$(CXXFLAGS)),-O5)
CXXFLAGS += -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS
endif # -O5
ifeq ($(findstring -Ofast,$(CXXFLAGS)),-Ofast)
CXXFLAGS += -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS
endif # -Ofast
endif # CRYPTOPP_NO_UNALIGNED_DATA_ACCESS
endif # UNALIGNED_ACCESS

ifneq ($(INTEL_COMPILER),0)
CXXFLAGS += -wd68 -wd186 -wd279 -wd327 -wd161 -wd3180
ifeq ($(ICC111_OR_LATER),0)
# "internal error: backend signals" occurs on some x86 inline assembly with ICC 9 and some x64 inline assembly with ICC 11.0
# if you want to use Crypto++'s assembly code with ICC, try enabling it on individual files
CXXFLAGS += -DCRYPTOPP_DISABLE_ASM
endif
endif

# .intel_syntax wasn't supported until GNU assembler 2.10
ifeq ($(GCC_COMPILER)$(MACPORTS_COMPILER)$(GAS210_OR_LATER),100)
CXXFLAGS += -DCRYPTOPP_DISABLE_ASM
else
ifeq ($(GCC_COMPILER)$(MACPORTS_COMPILER)$(GAS217_OR_LATER),100)
CXXFLAGS += -DCRYPTOPP_DISABLE_SSSE3
else
ifeq ($(GCC_COMPILER)$(MACPORTS_COMPILER)$(GAS219_OR_LATER),100)
CXXFLAGS += -DCRYPTOPP_DISABLE_AESNI
endif
endif
endif

# Tell MacPorts GCC to use Clang integrated assembler
#   http://github.com/weidai11/cryptopp/issues/190
ifeq ($(GCC_COMPILER)$(MACPORTS_COMPILER),11)
ifneq ($(findstring -Wa,-q,$(CXXFLAGS)),-Wa,-q)
CXXFLAGS += -Wa,-q
endif
ifneq ($(findstring -Wa,-q,$(CXXFLAGS)),-DCRYPTOPP_CLANG_INTEGRATED_ASSEMBLER)
CXXFLAGS += -DCRYPTOPP_CLANG_INTEGRATED_ASSEMBLER=1
endif
endif

# GCC on Solaris needs -m64. Otherwise, i386 is default
#   http://github.com/weidai11/cryptopp/issues/230
ifeq ($(IS_SUN)$(GCC_COMPILER)$(IS_X64),111)
CXXFLAGS += -m64
endif

# Allow use of "/" operator for GNU Assembler.
#   http://sourceware.org/bugzilla/show_bug.cgi?id=4572
ifeq ($(findstring -DCRYPTOPP_DISABLE_ASM,$(CXXFLAGS)),)
ifeq ($(IS_SUN)$(GCC_COMPILER),11)
CXXFLAGS += -Wa,--divide
endif
endif

ifeq ($(UNAME),)	# for DJGPP, where uname doesn't exist
CXXFLAGS += -mbnu210
else ifneq ($(findstring -save-temps,$(CXXFLAGS)),-save-temps)
ifeq ($(SUN_COMPILER),0)
CXXFLAGS += -pipe
endif
endif

else

###########################################################
#####                 Not X86/X32/X64                 #####
###########################################################

# Add PIC
ifeq ($(findstring -fPIC,$(CXXFLAGS)),)
  CXXFLAGS += -fPIC
endif

# Add -pipe for everything except ARM (allow ARM-64 because they seems to have > 1 GB of memory)
ifeq ($(IS_ARM32),0)
ifeq ($(findstring -save-temps,$(CXXFLAGS)),)
CXXFLAGS += -pipe
endif
endif

# Aligned access required for -O3 and above due to vectorization
UNALIGNED_ACCESS := $(shell $(EGREP) -c "^[[:space:]]*//[[:space:]]*\#[[:space:]]*define[[:space:]]*CRYPTOPP_NO_UNALIGNED_DATA_ACCESS" config.h)
ifneq ($(UNALIGNED_ACCESS),0)
ifeq ($(findstring -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS,$(CXXFLAGS)),)
ifeq ($(findstring -O3,$(CXXFLAGS)),-O3)
CXXFLAGS += -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS
endif # -O3
ifeq ($(findstring -O5,$(CXXFLAGS)),-O5)
CXXFLAGS += -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS
endif # -O5
ifeq ($(findstring -Ofast,$(CXXFLAGS)),-Ofast)
CXXFLAGS += -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS
endif # -Ofast
endif # CRYPTOPP_NO_UNALIGNED_DATA_ACCESS
endif # UNALIGNED_ACCESS

endif	# IS_X86

###########################################################
#####                      Common                     #####
###########################################################

ifneq ($(IS_MINGW),0)
LDLIBS += -lws2_32
endif

ifneq ($(IS_SUN),0)
LDLIBS += -lnsl -lsocket
endif

ifeq ($(IS_LINUX),1)
LDFLAGS += -pthread
ifeq ($(findstring -fopenmp,$(CXXFLAGS)),-fopenmp)
ifeq ($(findstring -lgomp,$(LDLIBS)),)
LDLIBS += -lgomp
endif # LDLIBS
endif # OpenMP
endif # IS_LINUX

ifneq ($(IS_DARWIN),0)
AR = libtool
ARFLAGS = -static -o
CXX ?= c++
ifeq ($(IS_GCC_29),1)
CXXFLAGS += -fno-coalesce-templates -fno-coalesce-static-vtables
LDLIBS += -lstdc++
LDFLAGS += -flat_namespace -undefined suppress -m
endif
endif

# Add -errtags=yes to get the name for a warning suppression
ifneq ($(SUN_COMPILER),0)	# override flags for CC Sun C++ compiler
IS_64 := $(shell isainfo -b 2>/dev/null | grep -i -c "64")
ifeq ($(IS_64),1)
CXXFLAGS += -m64
else ifeq ($(IS_64),0)
CXXFLAGS += -m32
endif
ifneq ($(SUNCC_513_OR_LATER),0)
CXXFLAGS += -native
endif
# Add for non-i386
ifneq ($(IS_X86),1)
CXXFLAGS += -KPIC
endif
# Add to all Solaris
CXXFLAGS += -template=no%extdef
SUN_CC10_BUGGY := $(shell $(CXX) -V 2>&1 | $(EGREP) -c "CC: Sun .* 5\.10 .* (2009|2010/0[1-4])")
ifneq ($(SUN_CC10_BUGGY),0)
# -DCRYPTOPP_INCLUDE_VECTOR_CC is needed for Sun Studio 12u1 Sun C++ 5.10 SunOS_i386 128229-02 2009/09/21 and was fixed in May 2010
# remove it if you get "already had a body defined" errors in vector.cc
CXXFLAGS += -DCRYPTOPP_INCLUDE_VECTOR_CC
endif
#ifneq ($SUNCC_512_OR_LATER),0)
#CXXFLAGS += -xarch=aes -D__AES__=1 -xarch=no%sse4_1 -xarch=no%sse4_2
#endif
AR = $(CXX)
ARFLAGS = -xar -o
RANLIB = true
endif

# Undefined Behavior Sanitizer (UBsan) testing. There's no sense in
#   allowing unaligned data access. There will too many findings.
ifeq ($(findstring ubsan,$(MAKECMDGOALS)),ubsan)
ifeq ($(findstring -fsanitize=undefined,$(CXXFLAGS)),)
CXXFLAGS += -fsanitize=undefined
endif # CXXFLAGS
ifeq ($(findstring -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS,$(CXXFLAGS)),)
CXXFLAGS += -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS
endif # CXXFLAGS
endif # UBsan

# Address Sanitizer (Asan) testing. Issue 'make asan'.
ifeq ($(findstring asan,$(MAKECMDGOALS)),asan)
ifeq ($(findstring -fsanitize=address,$(CXXFLAGS)),)
CXXFLAGS += -fsanitize=address
endif # CXXFLAGS
ifeq ($(findstring -fno-omit-frame-pointer,$(CXXFLAGS)),)
CXXFLAGS += -fno-omit-frame-pointer
endif # CXXFLAGS
endif # Asan

# LD gold linker testing. Triggered by 'LD=ld.gold'.
ifeq ($(findstring ld.gold,$(LD)),ld.gold)
ifeq ($(findstring -fuse-ld=gold,$(CXXFLAGS)),)
ELF_FORMAT := $(shell file `which ld.gold` 2>&1 | cut -d":" -f 2 | $(EGREP) -i -c "elf")
ifneq ($(ELF_FORMAT),0)
LDFLAGS += -fuse-ld=gold
endif # ELF/ELF64
endif # CXXFLAGS
endif # Gold

# Aligned access testing. Issue 'make aligned'.
ifneq ($(filter align aligned,$(MAKECMDGOALS)),)
ifeq ($(findstring -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS,$(CXXFLAGS)),)
CXXFLAGS += -DCRYPTOPP_NO_UNALIGNED_DATA_ACCESS
endif # CXXFLAGS
endif # Aligned access

# GCC code coverage. Issue 'make coverage'.
ifneq ($(filter coverage,$(MAKECMDGOALS)),)
ifeq ($(findstring -coverage,$(CXXFLAGS)),)
CXXFLAGS += -coverage
endif # -coverage
endif # GCC code coverage

# Debug testing on GNU systems. Triggered by -DDEBUG.
#   Newlib test due to http://sourceware.org/bugzilla/show_bug.cgi?id=20268
ifneq ($(filter -DDEBUG -DDEBUG=1,$(CXXFLAGS)),)
USING_GLIBCXX := $(shell $(CXX) -x c++ $(CXXFLAGS) -E adhoc.cpp.proto 2>&1 | $(EGREP) -i -c "__GLIBCXX__")
ifneq ($(USING_GLIBCXX),0)
HAS_NEWLIB := $(shell $(CXX) -x c++ $(CXXFLAGS) -E adhoc.cpp.proto 2>&1 | $(EGREP) -i -c "__NEWLIB__")
ifeq ($(HAS_NEWLIB),0)
ifeq ($(findstring -D_GLIBCXX_DEBUG,$(CXXFLAGS)),)
CXXFLAGS += -D_GLIBCXX_DEBUG
endif # CXXFLAGS
endif # NAS_NEWLIB
endif # USING_GLIBCXX
endif # GNU Debug build

# Dead code stripping. Issue 'make lean'.
ifeq ($(findstring lean,$(MAKECMDGOALS)),lean)
ifeq ($(findstring -ffunction-sections,$(CXXFLAGS)),)
CXXFLAGS += -ffunction-sections
endif # CXXFLAGS
ifeq ($(findstring -fdata-sections,$(CXXFLAGS)),)
CXXFLAGS += -fdata-sections
endif # CXXFLAGS
ifneq ($(IS_DARWIN),0)
ifeq ($(findstring -Wl,-dead_strip,$(LDFLAGS)),)
LDFLAGS += -Wl,-dead_strip
endif # CXXFLAGS
else # BSD, Linux and Unix
ifeq ($(findstring -Wl,--gc-sections,$(LDFLAGS)),)
LDFLAGS += -Wl,--gc-sections
endif # LDFLAGS
endif # MAKECMDGOALS
endif # Dead code stripping

# For Shared Objects, Diff, Dist/Zip rules
LIB_VER := $(shell $(EGREP) "define CRYPTOPP_VERSION" config.h | cut -d" " -f 3)
LIB_MAJOR := $(shell echo $(LIB_VER) | cut -c 1)
LIB_MINOR := $(shell echo $(LIB_VER) | cut -c 2)
LIB_PATCH := $(shell echo $(LIB_VER) | cut -c 3)

ifeq ($(strip $(LIB_PATCH)),)
LIB_PATCH := 0
endif

ifeq ($(HAS_SOLIB_VERSION),1)
# Full version suffix for shared library
SOLIB_VERSION_SUFFIX=.$(LIB_MAJOR).$(LIB_MINOR).$(LIB_PATCH)
# Different patchlevels are compatible, minor versions are not
SOLIB_COMPAT_SUFFIX=.$(LIB_MAJOR).$(LIB_MINOR)
SOLIB_FLAGS=-Wl,-soname,libcryptopp.so$(SOLIB_COMPAT_SUFFIX)
endif # HAS_SOLIB_VERSION


CXXFLAGS += -std=c++11


###########################################################
#####              Source and object files            #####
###########################################################

# List cryptlib.cpp first, then cpu.cpp, then integer.cpp to tame C++ static initialization problems.
SRCS := cryptlib.cpp cpu.cpp integer.cpp $(filter-out cryptlib.cpp cpu.cpp integer.cpp pch.cpp simple.cpp winpipes.cpp cryptlib_bds.cpp,$(wildcard *.cpp))

# Need CPU for X86/X64/X32 and ARM
ifeq ($(IS_X86)$(IS_X64)$(IS_ARM32)$(IS_ARM64),0000)
  SRCS := $(filter-out cpu.cpp, $(SRCS))
endif
# Need RDRAND for X86/X64/X32
ifeq ($(IS_X86)$(IS_X64),00)
  SRCS := $(filter-out rdrand.cpp, $(SRCS))
endif

ifneq ($(IS_MINGW),0)
SRCS += winpipes.cpp
endif

# List cryptlib.cpp first, then cpu.cpp, then integer.cpp to tame C++ static initialization problems.
OBJS := $(SRCS:.cpp=.o)

# List test.cpp first to tame C++ static initialization problems.
TESTSRCS := test.cpp bench1.cpp bench2.cpp validat1.cpp validat2.cpp validat3.cpp adhoc.cpp datatest.cpp regtest.cpp fipsalgt.cpp dlltest.cpp
TESTOBJS := $(TESTSRCS:.cpp=.o)
LIBOBJS := $(filter-out $(TESTOBJS),$(OBJS))

# List cryptlib.cpp first, then cpu.cpp, then integer.cpp to tame C++ static initialization problems.
DLLSRCS := cryptlib.cpp cpu.cpp integer.cpp shacal2.cpp md5.cpp shark.cpp zinflate.cpp gf2n.cpp salsa.cpp xtr.cpp oaep.cpp polynomi.cpp rc2.cpp default.cpp wait.cpp wake.cpp twofish.cpp iterhash.cpp adler32.cpp elgamal.cpp marss.cpp blowfish.cpp ecp.cpp filters.cpp strciphr.cpp camellia.cpp ida.cpp zlib.cpp des.cpp crc.cpp algparam.cpp dessp.cpp tea.cpp eax.cpp network.cpp emsa2.cpp pkcspad.cpp squaretb.cpp idea.cpp authenc.cpp hmac.cpp zdeflate.cpp xtrcrypt.cpp queue.cpp mars.cpp rc5.cpp blake2.cpp hrtimer.cpp eprecomp.cpp hex.cpp dsa.cpp sha.cpp fips140.cpp gzip.cpp seal.cpp files.cpp base32.cpp vmac.cpp tigertab.cpp sharkbox.cpp safer.cpp randpool.cpp esign.cpp arc4.cpp osrng.cpp skipjack.cpp seed.cpp sha3.cpp sosemanuk.cpp bfinit.cpp rabin.cpp 3way.cpp rw.cpp rdrand.cpp rsa.cpp rdtables.cpp gost.cpp socketft.cpp tftables.cpp nbtheory.cpp panama.cpp modes.cpp rijndael.cpp casts.cpp chacha.cpp gfpcrypt.cpp poly1305.cpp dll.cpp ec2n.cpp blumshub.cpp algebra.cpp basecode.cpp base64.cpp cbcmac.cpp rc6.cpp dh2.cpp gf256.cpp mqueue.cpp misc.cpp pssr.cpp channels.cpp tiger.cpp cast.cpp rng.cpp square.cpp asn.cpp whrlpool.cpp md4.cpp dh.cpp ccm.cpp md2.cpp mqv.cpp gf2_32.cpp ttmac.cpp luc.cpp trdlocal.cpp pubkey.cpp gcm.cpp ripemd.cpp eccrypto.cpp serpent.cpp cmac.cpp
DLLOBJS := $(DLLSRCS:.cpp=.export.o)

# Import lib testing
LIBIMPORTOBJS := $(LIBOBJS:.o=.import.o)
TESTIMPORTOBJS := $(TESTOBJS:.o=.import.o)
DLLTESTOBJS := dlltest.dllonly.o

################### NPPCRYPT ##############################

OBJDIR := ../../obj/cryptopp
TARGETDIR := ../../bin/cryptopp
OBJTEST := $(addprefix $(OBJDIR)/,$(TESTOBJS))
OBJLIST := $(addprefix $(OBJDIR)/,$(LIBOBJS))

###########################################################
#####                Targets and Recipes              #####
###########################################################

.PHONY: all
all: directories $(TARGETDIR)/cryptest

.PHONY: directories
directories:
	@mkdir -p $(OBJDIR)
	@mkdir -p $(TARGETDIR)

.PHONY: deps
deps GNUmakefile.deps:
	@rm -rf $(OBJDIR)
	$(CXX) $(CXXFLAGS) -MM *.cpp > $(OBJDIR)/GNUmakefile.deps

.PHONY: test check
test check: $(TARGETDIR)/cryptest
	@cp -n -R TestData $(TARGETDIR)/
	$(TARGETDIR)/cryptest v

.PHONY: clean
clean:
	@rm -rf $(OBJDIR)
	@rm -rf $(TARGETDIR)/TestData

$(TARGETDIR)/cryptest: $(TARGETDIR)/libcryptopp.a $(OBJTEST)
	$(CXX) -o $@ $(CXXFLAGS) $(OBJTEST) $(TARGETDIR)/libcryptopp.a $(LDFLAGS) $(LDLIBS)

$(TARGETDIR)/libcryptopp.a: $(OBJLIST)
	$(AR) $(ARFLAGS) $@ $^

$(OBJDIR)/%.o : %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

