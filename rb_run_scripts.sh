#!/bin/bash
echo -e "\n"
echo "-------------------------------------C IMPLEMENTATIONS -----------------------------------"

# -----------------C compilation of AES CIPHER -----------------
python3 rb_main.py aes 128 Files/Crypto_input/video/video_2.mp4 128

python3 rb_main.py aes 192 Files/Crypto_input/video/video_2.mp4 128

python3 rb_main.py aes 256 Files/Crypto_input/video/video_2.mp4 128

# -----------------C Implementation of PRESENT CIPHER -----------------
python3 rb_main.py present 80 Files/Crypto_input/video/video_2.mp4 64

python3 rb_main.py present 128 Files/Crypto_input/video/video_2.mp4 64


# -----------------C Implementation of XTEA CIPHER -----------------

python3 rb_main.py xtea 128 Files/Crypto_input/video/video_2.mp4 64

# -----------------C Implementation of SIMON CIPHER -----------------

python3 rb_main.py simon 64 Files/Crypto_input/video/video_2.mp4 32

python3 rb_main.py simon 96 Files/Crypto_input/video/video_2.mp4 48

python3 rb_main.py simon 128 Files/Crypto_input/video/video_2.mp4 64

python3 rb_main.py simon 144 Files/Crypto_input/video/video_2.mp4 96

# python3 rb_main.py simon 256 Files/Crypto_input/video/video_2.mp4 128

# -----------------C Implementation of SPECK CIPHER -----------------

python3 rb_main.py speck 64 Files/Crypto_input/video/video_2.mp4 32

python3 rb_main.py speck 96 Files/Crypto_input/video/video_2.mp4 48

python3 rb_main.py speck 128 Files/Crypto_input/video/video_2.mp4 64

python3 rb_main.py speck 144 Files/Crypto_input/video/video_2.mp4 96

python3 rb_main.py speck 256 Files/Crypto_input/video/video_2.mp4 128

# -----------------C Implementation of CLEFIA CIPHER -----------------

python3 rb_main.py clefia 128 Files/Crypto_input/video/video_2.mp4 128

python3 rb_main.py clefia 192 Files/Crypto_input/video/video_2.mp4 128

python3 rb_main.py clefia 256 Files/Crypto_input/video/video_2.mp4 128


# -----------------C Implementation of Ascon CIPHER -----------------

# python3 rb_main.py ascon 128 Files/Crypto_input/video/video_2.mp4 -

# -----------------C Implementation of Grain128a CIPHER -----------------

python3 rb_main.py grain-128a 128 Files/Crypto_input/video/video_2.mp4 -

# -----------------C Implementation of Grain-v1 CIPHER -----------------

python3 rb_main.py grain-v1 80 Files/Crypto_input/video/video_2.mp4 -

-----------------C Implementation of Mickey-v2 CIPHER -----------------

python3 rb_main.py mickey 80 Files/Crypto_input/video/video_2.mp4 -

-----------------C Implementation of Trivium CIPHER -----------------

python3 rb_main.py trivium 80 Files/Crypto_input/video/video_2.mp4 -

-----------------C Implementation of Salsa20 CIPHER -----------------

python3 rb_main.py salsa 128 Files/Crypto_input/video/video_2.mp4 -

-----------------C Implementation of Sosemanuk CIPHER -----------------

python3 rb_main.py sosemanuk 128 Files/Crypto_input/video/video_2.mp4 -

echo -e "\n"
echo "-------------------------------------PYTHON IMPLEMENTATIONS -----------------------------------"

# -----------------Python compilation of AES CIPHER -----------------
# python3 rb_main.py py-aes 128 Files/Crypto_input/video/video_2.mp4 128

# python3 rb_main.py py-aes 192 Files/Crypto_input/video/video_2.mp4 128

# python3 rb_main.py py-aes 256 Files/Crypto_input/video/video_2.mp4 128

# -----------------PYTHON Implementation of PRESENT CIPHER -----------------
# python3 rb_main.py py-present 80 Files/Crypto_input/video/video_2.mp4 64

# python3 rb_main.py py-present 128 Files/Crypto_input/video/video_2.mp4 64

# -----------------Python Implementation of X-TEA CIPHER -----------------

# python3 rb_main.py py-xtea 128 Files/Crypto_input/video/video_2.mp4 64

# # -----------------Python Implementation of SIMON CIPHER -----------------

# python3 rb_main.py py-simon 64 Files/Crypto_input/video/video_2.mp4 32

# python3 rb_main.py py-simon 96 Files/Crypto_input/video/video_2.mp4 48

# python3 rb_main.py py-simon 96 Files/Crypto_input/video/video_2.mp4 64

# python3 rb_main.py py-simon 128 Files/Crypto_input/video/video_2.mp4 64

# python3 rb_main.py py-simon 96 Files/Crypto_input/video/video_2.mp4 96

# python3 rb_main.py py-simon 128 Files/Crypto_input/video/video_2.mp4 128

# python3 rb_main.py py-simon 192 Files/Crypto_input/video/video_2.mp4 128

# python3 rb_main.py py-simon 256 Files/Crypto_input/video/video_2.mp4 128

# # -----------------Python Implementation of SPECK CIPHER -----------------

# python3 rb_main.py py-speck 64 Files/Crypto_input/video/video_2.mp4 32

# python3 rb_main.py py-speck 96 Files/Crypto_input/video/video_2.mp4 48

# python3 rb_main.py py-speck 96 Files/Crypto_input/video/video_2.mp4 64

# python3 rb_main.py py-speck 128 Files/Crypto_input/video/video_2.mp4 64

# python3 rb_main.py py-speck 96 Files/Crypto_input/video/video_2.mp4 96

# python3 rb_main.py py-speck 128 Files/Crypto_input/video/video_2.mp4 128

# python3 rb_main.py py-speck 192 Files/Crypto_input/video/video_2.mp4 128

# python3 rb_main.py py-speck 256 Files/Crypto_input/video/video_2.mp4 128