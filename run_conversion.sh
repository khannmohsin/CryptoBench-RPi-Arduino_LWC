#!/bin/bash

# -----------------C compilation of AES CIPHER -----------------
gcc -fPIC -shared -o Conv_cipher/AES/c_imp/aes.so Conv_cipher/AES/c_imp/aes.c

# -----------------C compilation of PRESENT CIPHER -----------------
gcc -fPIC -shared -o LW_Block_Cipher/SPN/PRESENT/c_imp/present.so LW_Block_Cipher/SPN/PRESENT/c_imp/present.c

# -----------------C compilation of PRESENT CIPHER -----------------
gcc -fPIC -shared -o LW_Block_Cipher/SPN/PRESENT/c_imp/present.so LW_Block_Cipher/SPN/PRESENT/c_imp/present.c

# -----------------C compilation of CLEFIA CIPHER -----------------
gcc -fPIC -shared -o LW_Block_Cipher/GFN/CLEFIA/c_imp/clefia_ref.so LW_Block_Cipher/GFN/CLEFIA/c_imp/clefia_ref.c

# -----------------C compilation of ASCON CIPHER -----------------
gcc -fPIC -shared -o LW_Stream_Cipher/LWAE/ASCON/c_imp/main.so LW_Stream_Cipher/LWAE/ASCON/c_imp/main.c

# -----------------C compilation of GRAIN CIPHER -----------------
gcc -fPIC -shared -o LW_Stream_Cipher/LWAE/Grain128a/c_imp/grain128aead_32p.so LW_Stream_Cipher/LWAE/Grain128a/c_imp/grain128aead_32p.c

