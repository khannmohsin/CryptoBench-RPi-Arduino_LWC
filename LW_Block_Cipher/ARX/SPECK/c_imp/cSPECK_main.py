import ctypes
from enum import IntEnum
import time
import os
import subprocess

# Load the shared library
speck_lib = ctypes.CDLL("LW_Block_Cipher/ARX/SPECK/c_imp/speck.so")

# Define the structure for SimSpk_Cipher
class SimSpk_Cipher(ctypes.Structure):
    _fields_ = [
        ("block_size", ctypes.c_uint8),
        ("key_size", ctypes.c_uint8),
        ("round_limit", ctypes.c_uint8),
        ("cipher_cfg", ctypes.c_uint8),
        ("z_seq", ctypes.c_uint8),
        ("key_schedule", ctypes.c_uint64 * 72),  # Maximum key schedule size
        ("encryptPtr", ctypes.c_void_p),  # Function pointer for encryption
        ("decryptPtr", ctypes.c_void_p),  # Function pointer for decryption
    ]

# Define an enum for cipher configuration
class CipherConfig(IntEnum):
    cfg_64_32 = 0
    cfg_96_48 = 2
    cfg_128_64 = 3
    cfg_144_96 = 5
    cfg_256_128 = 7

# Define the function prototype for the Simon_Init function
speck_init_func = speck_lib.Speck_Init
speck_init_func.argtypes = [
    ctypes.POINTER(SimSpk_Cipher),  # SimSpk_Cipher *
    ctypes.c_uint8,  # cipher_cfg
    ctypes.c_uint8,  # c_mode
    ctypes.c_void_p,  # key
    ctypes.POINTER(ctypes.c_ubyte),  # iv
    ctypes.POINTER(ctypes.c_ubyte)  # counter
]

# Define the SIMON encryption function
speck_encrypt = speck_lib.Speck_Encrypt
speck_encrypt.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_void_p]
speck_encrypt.restype = ctypes.c_uint8

# Define the SIMON decryption function
speck_decrypt = speck_lib.Speck_Decrypt
speck_decrypt.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_void_p]
speck_decrypt.restype = ctypes.c_uint8

def get_memory_usage():
    output = subprocess.check_output(["ps", "-p", str(os.getpid()), "-o", "rss="])
    return int(output) * 1024  # Convert to bytes

def c_speck_encrypt_file(plaintext, key, block_size):
    file_size = len(plaintext)
    file_size_Kb = file_size * 8 / 1000  # File size in Kilobits

    c_mode = 0
    plaintext = (ctypes.c_ubyte * len(plaintext))(*plaintext)
    key_ptr = ctypes.cast(key, ctypes.POINTER(ctypes.c_uint8))
    iv = None
    counter = None


    if block_size == 32:
        cipher_object = SimSpk_Cipher()
        cipher_object.block_size = 32
        cipher_object.key_size = 64
        cipher_object.round_limit = 72
        cipher_object.cipher_cfg = 0
        cipher_object.z_seq = 0
        cipher_object.key_schedule = (ctypes.c_uint64 * 72)()
        cipher_object.encryptPtr = None
        cipher_object.decryptPtr = None
        block_size_bytes = 4

    elif block_size == 48:
        cipher_object = SimSpk_Cipher()
        cipher_object.block_size = 48
        cipher_object.key_size = 96
        cipher_object.round_limit = 72
        cipher_object.cipher_cfg = 2
        cipher_object.z_seq = 0
        cipher_object.key_schedule = (ctypes.c_uint64 * 72)()
        cipher_object.encryptPtr = None
        cipher_object.decryptPtr = None
        block_size_bytes = 6

    elif block_size == 64:
        cipher_object = SimSpk_Cipher()
        cipher_object.block_size = 64
        cipher_object.key_size = 128
        cipher_object.round_limit = 72
        cipher_object.cipher_cfg = 3
        cipher_object.z_seq = 0
        cipher_object.key_schedule = (ctypes.c_uint64 * 72)()
        cipher_object.encryptPtr = None
        cipher_object.decryptPtr = None
        block_size_bytes = 8

    elif block_size == 96:
        cipher_object = SimSpk_Cipher()
        cipher_object.block_size = 96
        cipher_object.key_size = 144
        cipher_object.round_limit = 72
        cipher_object.cipher_cfg = 5
        cipher_object.z_seq = 0
        cipher_object.key_schedule = (ctypes.c_uint64 * 72)()
        cipher_object.encryptPtr = None
        cipher_object.decryptPtr = None
        block_size_bytes = 12

    elif block_size == 128:
        cipher_object = SimSpk_Cipher()
        cipher_object.block_size = 128
        cipher_object.key_size = 256
        cipher_object.round_limit = 72
        cipher_object.cipher_cfg = 7
        cipher_object.z_seq = 0
        cipher_object.key_schedule = (ctypes.c_uint64 * 72)()
        cipher_object.encryptPtr = None
        cipher_object.decryptPtr = None
        block_size_bytes = 16


    result = speck_init_func(ctypes.byref(cipher_object), cipher_object.cipher_cfg, c_mode, key_ptr, iv, counter)

    if result == 0:
        print("Cipher object initialized successfully.")

    ciphertext = bytearray()
    total_encryption_time = 0
    memory_before = get_memory_usage()
    for i in range(0, len(plaintext), block_size_bytes):
        block = plaintext[i:i+block_size_bytes]
        
        if len(block) < block_size_bytes:
            block += bytes(block_size_bytes - len(block))
        block_array = (ctypes.c_ubyte * len(block))(*block)
        encrypted_block = (ctypes.c_ubyte * len(block))()
        
        start_time = time.perf_counter()
        speck_encrypt(ctypes.byref(cipher_object), block_array, encrypted_block)
        end_time = time.perf_counter()
        encryption_time = end_time - start_time
        total_encryption_time += encryption_time
        ciphertext += encrypted_block

    memory_after = get_memory_usage()
    # Format the total encryption time to two decimal places
    formatted_total_encryption_time = round(total_encryption_time, 2)

    # Print the formatted total encryption time
    print("Total encryption time:", formatted_total_encryption_time, "seconds")

    throughput = round(file_size_Kb / total_encryption_time, 2)   # Throughput in Kbps
    print("Encryption Throughput:", throughput, "Kbps")

    memory_consumption = memory_after - memory_before
    print("Memory usage:", memory_consumption, "bytes")

    return ciphertext, formatted_total_encryption_time, throughput, memory_consumption


def c_speck_decrypt_file(ciphertext, key, block_size):
        file_size = len(ciphertext)
        file_size_Kb = file_size * 8 / 1000  # File size in Kilobits

        c_mode = 0
        ciphertext = (ctypes.c_ubyte * len(ciphertext))(*ciphertext)
        key_ptr = ctypes.cast(key, ctypes.POINTER(ctypes.c_uint8))
        iv = None
        counter = None
    
        if block_size == 32:
            cipher_object = SimSpk_Cipher()
            cipher_object.block_size = 32
            cipher_object.key_size = 64
            cipher_object.round_limit = 72
            cipher_object.cipher_cfg = 0
            cipher_object.z_seq = 0
            cipher_object.key_schedule = (ctypes.c_uint64 * 72)()
            cipher_object.encryptPtr = None
            cipher_object.decryptPtr = None
            block_size_bytes = 4
    
        elif block_size == 48:
            cipher_object = SimSpk_Cipher()
            cipher_object.block_size = 48
            cipher_object.key_size = 96
            cipher_object.round_limit = 72
            cipher_object.cipher_cfg = 2
            cipher_object.z_seq = 0
            cipher_object.key_schedule = (ctypes.c_uint64 * 72)()
            cipher_object.encryptPtr = None
            cipher_object.decryptPtr = None
            block_size_bytes = 6
    
        elif block_size == 64:
            print("Block size is 64")
            cipher_object = SimSpk_Cipher()
            cipher_object.block_size = 64
            cipher_object.key_size = 128
            cipher_object.round_limit = 72
            cipher_object.cipher_cfg = 3
            cipher_object.z_seq = 0
            cipher_object.key_schedule = (ctypes.c_uint64 * 72)()
            cipher_object.encryptPtr = None
            cipher_object.decryptPtr = None
            block_size_bytes = 8
    
        elif block_size == 96:
            cipher_object = SimSpk_Cipher()
            cipher_object.block_size = 96
            cipher_object.key_size = 144
            cipher_object.round_limit = 72
            cipher_object.cipher_cfg = 5
            cipher_object.z_seq = 0
            cipher_object.key_schedule = (ctypes.c_uint64 * 72)()
            cipher_object.encryptPtr = None
            cipher_object.decryptPtr = None
            block_size_bytes = 12
    
        elif block_size == 128:
            cipher_object = SimSpk_Cipher()
            cipher_object.block_size = 128
            cipher_object.key_size = 256
            cipher_object.round_limit = 72
            cipher_object.cipher_cfg = 7
            cipher_object.z_seq = 0
            cipher_object.key_schedule = (ctypes.c_uint64 * 72)()
            cipher_object.encryptPtr = None
            cipher_object.decryptPtr = None
            block_size_bytes = 16
    
        result = speck_init_func(ctypes.byref(cipher_object), cipher_object.cipher_cfg, c_mode, key_ptr, iv, counter)
    
        if result == 0:
            print("Cipher object initialized successfully.")

        plaintext = bytearray()
        total_decryption_time = 0
        memory_before = get_memory_usage()

        for i in range(0, len(ciphertext), block_size_bytes):
            block = ciphertext[i:i+block_size_bytes]
            if len(block) < block_size_bytes:
                block += bytes(block_size_bytes - len(block))
            block_array = (ctypes.c_ubyte * len(block))(*block)
            decrypted_block = (ctypes.c_ubyte * len(block))()

            start_time = time.perf_counter()
            speck_decrypt(ctypes.byref(cipher_object), block_array, decrypted_block)
            end_time = time.perf_counter()

            decryption_time = end_time - start_time
            total_decryption_time += decryption_time
            plaintext += decrypted_block

        memory_after = get_memory_usage()

        # Format the total encryption time to two decimal places
        formatted_total_decryption_time = round(total_decryption_time, 2)

        # Print the formatted total encryption time
        print("Total decryption time:", formatted_total_decryption_time, "seconds")

        throughput = round(file_size_Kb / total_decryption_time, 2)   # Throughput in Kbps
        print("Decryption Throughput:", throughput, "Kbps")

        memory_consumption = memory_after - memory_before
        print("Memory usage:", memory_consumption, "bytes")

        return plaintext, formatted_total_decryption_time, throughput, memory_consumption
            
