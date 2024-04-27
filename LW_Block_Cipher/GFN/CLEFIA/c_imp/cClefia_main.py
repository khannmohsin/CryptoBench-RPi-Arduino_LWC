import ctypes
import time
import os
import subprocess

clefia_lib = ctypes.CDLL('LW_Block_Cipher/GFN/CLEFIA/c_imp/clefia_ref.so')

# Define the ctypes data types for the function parameters and return type
ctypes.c_char_p()  # for unsigned char pointers
ctypes.c_int()     # for int

# Define the function prototype
clefia_lib.ClefiaKeySet.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
clefia_lib.ClefiaKeySet.restype = ctypes.c_int


def get_memory_usage():
    output = subprocess.check_output(["ps", "-p", str(os.getpid()), "-o", "rss="])
    return int(output) * 1024  # Convert to bytes

# Define a Python wrapper function for ClefiaKeySet
def ClefiaKeySet(rk, skey, key_bitlen):
    # Call the C function and return its result
    return clefia_lib.ClefiaKeySet(rk, skey, key_bitlen)

# Define the function prototype
clefia_lib.ClefiaEncrypt.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
clefia_lib.ClefiaEncrypt.restype = None

# Define a Python wrapper function for ClefiaEncrypt
def ClefiaEncrypt(ct, pt, rk, r):
    # Call the C function
    clefia_lib.ClefiaEncrypt(ct, pt, rk, r)

# Define the function prototype
clefia_lib.ByteCpy.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
clefia_lib.ByteCpy.restype = None

# Define a Python wrapper function for ByteCpy
def ByteCpy(dst, src, bytelen):
    # Call the C function
    clefia_lib.ByteCpy(dst, src, bytelen)

# Define the function prototype
clefia_lib.ClefiaDecrypt.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
clefia_lib.ClefiaDecrypt.restype = None

# Define a Python wrapper function for ClefiaDecrypt
def ClefiaDecrypt(pt, ct, rk, r):
    # Call the C function
    clefia_lib.ClefiaDecrypt(pt, ct, rk, r)


def cClefia_encrypt_file(plaintext, key):

    file_size = len(plaintext)
    file_size_Kb = file_size * 8 / 1000  # File size in Kilobits

    ct = (ctypes.c_ubyte * 16)()
    rk = (ctypes.c_ubyte * (8 * 26 + 16))()

    if len(key) == 16 or len(key) == 128:
        key_array = (ctypes.c_ubyte * 32)(*key)
        key_size = 128
    elif len(key) == 24 or len(key) == 192:
        key_array = (ctypes.c_ubyte * 24)(*key)
        key_size = 192
    elif len(key) == 32 or len(key) == 256:
        key_array = (ctypes.c_ubyte * 32)(*key)
        key_size = 256
    
    # Key setup
    ClefiaKeySet(rk, key_array, key_size)

    ciphertext = bytearray()

    total_encryption_time = 0
    memory_before = get_memory_usage()
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        # Pad the last block if needed
        if len(block) < 16:
            block += bytes(16 - len(block))
        # Create ctypes array for the block
        block_array = (ctypes.c_ubyte * len(block))(*block)
        start_time = time.perf_counter()
        # Encryption
        ClefiaEncrypt(ct, block_array, rk, key_size)
        end_time = time.perf_counter()
        encryption_time = end_time - start_time
        total_encryption_time += encryption_time
        # Append the encrypted block to the ciphertext
        ciphertext.extend(ct)

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


def cClefia_decrypt_file(ciphertext, key):

    file_size = len(ciphertext)
    file_size_Kb = file_size * 8 / 1000  # File size in Kilobits

    pt = (ctypes.c_ubyte * 16)()
    ct = (ctypes.c_ubyte * 16)()
    rk = (ctypes.c_ubyte * (8 * 26 + 16))()

    if len(key) == 16 or len(key) == 128:
        key_array = (ctypes.c_ubyte * 16)(*key)
        key_size = 128
    elif len(key) == 24 or len(key) == 192:
        key_array = (ctypes.c_ubyte * 24)(*key)
        key_size = 192
    elif len(key) == 32 or len(key) == 256:
        key_array = (ctypes.c_ubyte * 32)(*key)
        key_size = 256

    # Key setup
    ClefiaKeySet(rk, key_array, key_size)

    plaintext = bytearray()

    total_decryption_time = 0
    memory_before = get_memory_usage()
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        # Create ctypes array for the block
        block_array = (ctypes.c_ubyte * len(block))(*block)
        start_time = time.perf_counter()
        # Decryption
        ClefiaDecrypt(pt, block_array, rk, key_size)
        end_time = time.perf_counter()
        decryption_time = end_time - start_time
        total_decryption_time += decryption_time
        # Append the decrypted block to the plaintext
        plaintext.extend(pt)
    
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
