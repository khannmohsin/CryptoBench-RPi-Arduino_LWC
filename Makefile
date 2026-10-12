# Build every C cipher as a shared library loaded by the Python wrappers.
#   make build   - compile all .so files
#   make clean   - remove them
#   make list    - list available ciphers and their key/block sizes
#   make test    - build, then run the test suite
CC      ?= gcc
CFLAGS  ?= -O2 -fPIC -shared
PYTHON  ?= python3

ASCON_DIR := LW_Stream_Cipher/LWAE/ASCON/c_imp

LIBS := \
	Conv_cipher/AES/c_imp/aes.so \
	LW_Block_Cipher/SPN/PRESENT/c_imp/present.so \
	LW_Block_Cipher/FN/XTEA/c_imp/xtea.so \
	LW_Block_Cipher/FN/SIMON/c_imp/simon.so \
	LW_Block_Cipher/ARX/SPECK/c_imp/speck.so \
	LW_Block_Cipher/GFN/CLEFIA/c_imp/clefia_ref.so \
	LW_Stream_Cipher/LWAE/Grain128a/c_imp/grain128aead_32p.so \
	LW_Stream_Cipher/eSTREAM/HW_oriented/Grain/c_imp/grain.so \
	LW_Stream_Cipher/eSTREAM/HW_oriented/Mickey/c_imp/mickey2.so \
	LW_Stream_Cipher/eSTREAM/HW_oriented/Trivium/c_imp/trivium.so \
	LW_Stream_Cipher/eSTREAM/SW_oriented/Salsa/c_imp/ecrypt.so \
	LW_Stream_Cipher/eSTREAM/SW_oriented/Sosemanuk/c_imp/sosemanuk.so \
	$(ASCON_DIR)/main.so

.PHONY: build clean list test
build: $(LIBS)

%.so: %.c
	$(CC) $(CFLAGS) -o $@ $<

$(ASCON_DIR)/main.so: $(wildcard $(ASCON_DIR)/*.c) $(wildcard $(ASCON_DIR)/*.h)
	$(CC) $(CFLAGS) -o $@ $(ASCON_DIR)/main.c $(ASCON_DIR)/permutations.c $(ASCON_DIR)/printstate.c

clean:
	rm -f $(LIBS)

list:
	$(PYTHON) benchmark.py --list

test: build
	$(PYTHON) -m pytest tests
