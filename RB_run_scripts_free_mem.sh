#!/bin/bash
iterations=5

echo -e "\n"

for ((i = 1; i <= iterations; i++)); do

    echo "----------------------C IMPLEMENTATIONS ----------------------"

    # -----------------C compilation of AES CIPHER -----------------
    python3 main.py aes 128 Files/Crypto_input/photo/oneMB_photo.jpg 128

    # Free memory after AES 128 execution
    aes_128_pid=$(pidof python3)
    kill -9 "$aes_128_pid"

    python3 main.py aes 192 Files/Crypto_input/photo/oneMB_photo.jpg 128

    # Free memory after AES 192 execution
    aes_192_pid=$(pidof python3)
    kill -9 "$aes_192_pid"

    python3 main.py aes 256 Files/Crypto_input/photo/oneMB_photo.jpg 128

    # Free memory after AES 256 execution
    aes_256_pid=$(pidof python3)
    kill -9 "$aes_256_pid"

    # -----------------C Implementation of PRESENT CIPHER -----------------
    python3 main.py present 80 Files/Crypto_input/photo/oneMB_photo.jpg 64

    # Free memory after PRESENT execution
    present_pid=$(pidof python3)
    kill -9 "$present_pid"

    python3 rb_main.py present 128 Files/Crypto_input/photo/oneMB_photo.jpg 64

    # Free memory after PRESENT execution
    present_pid=$(pidof python3)
    kill -9 "$present_pid"

    # -----------------C Implementation of X-TEA CIPHER -----------------

    python3 rb_main.py xtea 128 Files/Crypto_input/photo/oneMB_photo.jpg 64
    
    # Free memory after X-TEA execution
    xtea_pid=$(pidof python3)
    kill -9 "$xtea_pid"

    # -----------------C Implementation of SIMON CIPHER -----------------

    python3 rb_main.py simon 64 Files/Crypto_input/photo/oneMB_photo.jpg 32

    # Free memory after SIMON 64 execution
    simon_64_pid=$(pidof python3)
    kill -9 "$simon_64_pid"

    python3 rb_main.py simon 96 Files/Crypto_input/photo/oneMB_photo.jpg 48

    # Free memory after SIMON 96 execution
    simon_96_pid=$(pidof python3)
    kill -9 "$simon_96_pid"

    python3 rb_main.py simon 128 Files/Crypto_input/photo/oneMB_photo.jpg 64

    # Free memory after SIMON 128 execution
    simon_128_pid=$(pidof python3)
    kill -9 "$simon_128_pid"

    python3 rb_main.py simon 144 Files/Crypto_input/photo/oneMB_photo.jpg 96

    # Free memory after SIMON 144 execution
    simon_144_pid=$(pidof python3)
    kill -9 "$simon_144_pid"

    python3 rb_main.py simon 256 Files/Crypto_input/photo/oneMB_photo.jpg 128

    # Free memory after SIMON 256 execution
    simon_256_pid=$(pidof python3)
    kill -9 "$simon_256_pid"

    # -----------------C Implementation of SPECK CIPHER -----------------   

    python3 rb_main.py speck 64 Files/Crypto_input/photo/oneMB_photo.jpg 32

    # Free memory after SPECK 64 execution
    speck_64_pid=$(pidof python3)
    kill -9 "$speck_64_pid"

    python3 rb_main.py speck 96 Files/Crypto_input/photo/oneMB_photo.jpg 48

    # Free memory after SPECK 96 execution
    speck_96_pid=$(pidof python3)
    kill -9 "$speck_96_pid"

    python3 rb_main.py speck 128 Files/Crypto_input/photo/oneMB_photo.jpg 64

    # Free memory after SPECK 128 execution
    speck_128_pid=$(pidof python3)
    kill -9 "$speck_128_pid"

    python3 rb_main.py speck 144 Files/Crypto_input/photo/oneMB_photo.jpg 96

    # Free memory after SPECK 144 execution
    speck_144_pid=$(pidof python3)
    kill -9 "$speck_144_pid"

    python3 rb_main.py speck 256 Files/Crypto_input/photo/oneMB_photo.jpg 128

    # Free memory after SPECK 256 execution
    speck_256_pid=$(pidof python3)
    kill -9 "$speck_256_pid"

    # -----------------C Implementation of CLEFIA CIPHER -----------------

    python3 rb_main.py clefia 128 Files/Crypto_input/photo/oneMB_photo.jpg 128

    # Free memory after CLEFIA 128 execution
    kill -9 "$clefia_128_pid"

    python3 rb_main.py clefia 192 Files/Crypto_input/photo/oneMB_photo.jpg 128

    # Free memory after CLEFIA 192 execution
    clefia_192_pid=$(pidof python3)
    kill -9 "$clefia_192_pid"

    python3 rb_main.py clefia 256 Files/Crypto_input/photo/oneMB_photo.jpg 128

    # Free memory after CLEFIA 256 execution
    clefia_256_pid=$(pidof python3)
    kill -9 "$clefia_256_pid"

    # -----------------C Implementation of Ascon CIPHER -----------------

    # python3 rb_main.py ascon 128 Files/Crypto_input/photo/oneMB_photo.jpg -

    # -----------------C Implementation of Grain128a CIPHER -----------------

    python3 rb_main.py grain-128a 128 Files/Crypto_input/photo/oneMB_photo.jpg -

    # Free memory after Grain128a execution
    grain_128a_pid=$(pidof python3)
    kill -9 "$grain_128a_pid"

    # -----------------C Implementation of Grain-v1 CIPHER -----------------

    python3 rb_main.py grain-v1 80 Files/Crypto_input/photo/oneMB_photo.jpg -

    # Free memory after Grain-v1 execution
    grain_v1_pid=$(pidof python3)
    kill -9 "$grain_v1_pid"

    # -----------------C Implementation of Mickey-v2 CIPHER -----------------

    python3 rb_main.py mickey 80 Files/Crypto_input/photo/oneMB_photo.jpg -

    # Free memory after Mickey-v2 execution
    mickey_pid=$(pidof python3)
    kill -9 "$mickey_pid"

    # -----------------C Implementation of Trivium CIPHER -----------------

    python3 rb_main.py trivium 80 Files/Crypto_input/photo/oneMB_photo.jpg -

    # Free memory after Trivium execution
    trivium_pid=$(pidof python3)
    kill -9 "$trivium_pid"

    # -----------------C Implementation of Salsa20 CIPHER -----------------

    python3 rb_main.py salsa 128 Files/Crypto_input/photo/oneMB_photo.jpg -

    # Free memory after Salsa20 execution
    salsa_pid=$(pidof python3)
    kill -9 "$salsa_pid"

    # -----------------C Implementation of Sosemanuk CIPHER -----------------

    python3 rb_main.py sosemanuk 128 Files/Crypto_input/photo/oneMB_photo.jpg -

    # Free memory after Sosemanuk execution
    sosemanuk_pid=$(pidof python3)
    kill -9 "$sosemanuk_pid"

done
