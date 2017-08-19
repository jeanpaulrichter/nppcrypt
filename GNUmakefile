TARGET := nppcrypt
OBJDIR := obj
SRCDIR := src
CXX := g++
C := gcc
CXXFLAGS := -std=c++11
CFLAGS := 
CRYPTOPP := bin/cryptopp/libcryptopp.a
LDFLAGS := -lstdc++ $(CRYPTOPP)
PREFIX := /usr/local

DEP_SRC := $(shell find $(SRCDIR)/bcrypt -type f -name *.cpp)
DEP_SRC += $(shell find $(SRCDIR)/scrypt -type f -name *.c)
DEP_SRC += $(shell find $(SRCDIR)/keccak -type f -name *.cpp)
DEP_SRC += $(shell find $(SRCDIR)/tinyxml2 -type f -name *.cpp)
MAIN_SRC := src/clihelp.cpp src/cmdline.cpp src/crypt.cpp src/exception.cpp src/cryptheader.cpp

ifeq ($(mode),debug)
	mode = debug
	CFLAGS += -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -DDEBUG
	CXXFLAGS += -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -DDEBUG
	SUBDIR := debug
else
	CFLAGS += -g2 -Os -fdata-sections -ffunction-sections -DNDEBUG
	CXXFLAGS += -g2 -Os -fdata-sections -ffunction-sections -DNDEBUG
	LDFLAGS += -static -s
	SUBDIR := release
endif

DEP_OBJ := $(patsubst $(SRCDIR)/%,$(OBJDIR)/$(SUBDIR)/%,$(patsubst %.cpp,%.o,$(patsubst %.c,%.o,$(DEP_SRC))))
MAIN_OBJ := $(patsubst $(SRCDIR)/%,$(OBJDIR)/$(SUBDIR)/%,$(MAIN_SRC:.cpp=.o))

.PHONY: all
all: info directories $(CRYPTOPP) bin/$(SUBDIR)/$(TARGET)

.PHONY: info
info:
ifneq ($(mode),release)
ifneq ($(mode),debug)
	@echo "Invalid build mode." 
	@echo "Please use 'make mode=release' or 'make mode=debug'"
	@exit 1
endif
endif

.PHONY: directories
directories:
	@mkdir -p bin/$(SUBDIR)
	@mkdir -p obj/$(SUBDIR)
	@mkdir -p obj/$(SUBDIR)/bcrypt
	@mkdir -p obj/$(SUBDIR)/scrypt
	@mkdir -p obj/$(SUBDIR)/keccak
	@mkdir -p obj/$(SUBDIR)/tinyxml2

.PHONY: clean
clean:
	@make -C src/cryptopp clean
	@rm -rf $(OBJDIR)

.PHONY: install
install: bin/release/$(TARGET)
	@mkdir -p $(DESTDIR)$(PREFIX)/bin
	@cp $< $(DESTDIR)$(PREFIX)/bin/$(TARGET)

.PHONY: uninstall
uninstall:
	@rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)

$(CRYPTOPP):
	@make -C src/cryptopp

bin/$(SUBDIR)/$(TARGET): $(MAIN_OBJ) $(DEP_OBJ)
	$(CXX) $(CXXFLAGS) -o bin/$(SUBDIR)/$(TARGET) $^ $(LDFLAGS)

$(OBJDIR)/$(SUBDIR)/scrypt/%.o: src/scrypt/%.c
	$(C) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/$(SUBDIR)/bcrypt/%.o: src/bcrypt/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(OBJDIR)/$(SUBDIR)/keccak/%.o: src/keccak/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(OBJDIR)/$(SUBDIR)/tinyxml2/%.o: src/tinyxml2/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(OBJDIR)/$(SUBDIR)/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -I /src/cli11 -c -o $@ $<

