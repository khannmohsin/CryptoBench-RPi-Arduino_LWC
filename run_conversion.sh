#!/bin/bash

# -----------------C compilation of AES CIPHER -----------------
gcc -fPIC -shared -o Conv_cipher/AES/c_imp/aes.so Conv_cipher/AES/c_imp/aes.c

# -----------------C compilation of PRESENT CIPHER -----------------
gcc -fPIC -shared -o LW_Block_Cipher/SPN/PRESENT/c_imp/present.so LW_Block_Cipher/SPN/PRESENT/c_imp/present.c

# -----------------C compilation of PRESENT CIPHER -----------------
gcc -fPIC -shared -o LW_Block_Cipher/SPN/PRESENT/c_imp/present.so LW_Block_Cipher/SPN/PRESENT/c_imp/present.c

# -----------------C compilation of XTEA CIPHER ---------------------
gcc -fPIC -shared -o LW_Block_Cipher/FN/XTEA/c_imp/xtea.so LW_Block_Cipher/FN/XTEA/c_imp/xtea.c

# -----------------C compilation of SIMON CIPHER ---------------------
gcc -fPIC -shared -o LW_Block_Cipher/FN/SIMON/c_imp/simon.so LW_Block_Cipher/FN/SIMON/c_imp/simon.c 

# -----------------C compilation of SPECK CIPHER ---------------------
gcc -fPIC -shared -o LW_Block_Cipher/ARX/SPECK/c_imp/speck.so LW_Block_Cipher/ARX/SPECK/c_imp/speck.c

# -----------------C compilation of CLEFIA CIPHER -----------------
gcc -fPIC -shared -o LW_Block_Cipher/GFN/CLEFIA/c_imp/clefia_ref.so LW_Block_Cipher/GFN/CLEFIA/c_imp/clefia_ref.c

# -----------------C compilation of ASCON CIPHER -----------------
# gcc -fPIC -shared -o LW_Stream_Cipher/LWAE/ASCON/c_imp/main.so LW_Stream_Cipher/LWAE/ASCON/c_imp/main.c

# -----------------C compilation of GRAIN-v1 CIPHER -----------------
gcc -fPIC -shared -o LW_Stream_Cipher/eSTREAM/HW_oriented/Grain/c_imp/grain.so LW_Stream_Cipher/eSTREAM/HW_oriented/Grain/c_imp/grain.c

# -----------------C compilation of GRAIN-128 CIPHER -----------------
gcc -fPIC -shared -o LW_Stream_Cipher/LWAE/Grain128a/c_imp/grain128aead_32p.so LW_Stream_Cipher/LWAE/Grain128a/c_imp/grain128aead_32p.c

# -----------------C compilation of MICKEY CIPHER -----------------
gcc -fPIC -shared -o LW_Stream_Cipher/eSTREAM/HW_oriented/Mickey/c_imp/mickey2.so LW_Stream_Cipher/eSTREAM/HW_oriented/Mickey/c_imp/mickey2.c

# -----------------C compilation of TRIVIUM CIPHER -----------------
gcc -fPIC -shared -o LW_Stream_Cipher/eSTREAM/HW_oriented/Trivium/c_imp/trivium.so LW_Stream_Cipher/eSTREAM/HW_oriented/Trivium/c_imp/trivium.c

# -----------------C compilation of SALSA CIPHER -----------------
gcc -fPIC -shared -o LW_Stream_Cipher/eSTREAM/SW_oriented/Salsa/c_imp/ecrypt.so LW_Stream_Cipher/eSTREAM/SW_oriented/Salsa/c_imp/ecrypt.c

# -----------------C compilation of SOSEMANUK CIPHER -----------------
gcc -fPIC -shared -o LW_Stream_Cipher/eSTREAM/SW_oriented/Sosemanuk/c_imp/sosemanuk.so LW_Stream_Cipher/eSTREAM/SW_oriented/Sosemanuk/c_imp/sosemanuk.c