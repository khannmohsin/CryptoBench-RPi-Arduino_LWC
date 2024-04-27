import ctypes
import time
import os
import subprocess

# Load the C library
lib_crypto_present = ctypes.CDLL('LW_Block_Cipher/SPN/PRESENT/c_imp/present.so')

# Define the function prototypes
present_64_128_key_schedule = lib_crypto_present.present_64_128_key_schedule
present_64_128_key_schedule.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
present_64_128_key_schedule.restype = None

present_64_80_key_schedule = lib_crypto_present.present_64_80_key_schedule
present_64_80_key_schedule.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
present_64_80_key_schedule.restype = None

present_encrypt = lib_crypto_present.present_encrypt
present_encrypt.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
present_encrypt.restype = None

present_decrypt = lib_crypto_present.present_decrypt
present_decrypt.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
present_decrypt.restype = None

def get_memory_usage():
    output = subprocess.check_output(["ps", "-p", str(os.getpid()), "-o", "rss="])
    return int(output) * 1024  # Convert to bytes

# ------------------------------------------Function to encrypt a file with a 80-bit key-------------------------------------
def c_present_encrypt_file_key_80(plaintext, key):

    file_size = len(plaintext)
    file_size_Kb = file_size * 8 / 1000  # File size in Kilobits

    # Split the binary key into 8 parts of 16 bits each
    key_parts = [int(key[i:i+8], 2) for i in range(0, 80, 8)]

    # Create the ctypes array
    key_array = (ctypes.c_uint8 * 10)(*key_parts)

    # Key schedule
    roundKeys = (ctypes.c_uint8 * (8 * 33))()  # Assuming maximum round keys needed
    present_64_80_key_schedule(key_array, roundKeys)

    # Encrypt the plaintext
    ciphertext = bytearray()
    total_encryption_time = 0
    memory_before = get_memory_usage()
    for i in range(0, len(plaintext), 8):
        block = plaintext[i:i+8]
        # Pad the last block if needed
        if len(block) < 8:
            block += bytes(8 - len(block))
        # Create ctypes array for the block
        block_array = (ctypes.c_uint8 * len(block))(*block)
        
        start_time = time.perf_counter()
        # Encrypt the block
        present_encrypt(block_array, roundKeys)
        end_time = time.perf_counter()
        encryption_time = end_time - start_time

        total_encryption_time += encryption_time
        # Append the encrypted block to the ciphertext
        ciphertext.extend(block_array)

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

# Function to decrypt a file with a 80-bit key
def c_present_decrypt_file_key_80(ciphertext, key):

    file_size = len(ciphertext)
    file_size_Kb = file_size * 8 / 1000  # File size in Kilobits

    # Split the binary key into 8 parts of 16 bits each
    key_parts = [int(key[i:i+8], 2) for i in range(0, 80, 8)]

    # Create the ctypes array
    key_array = (ctypes.c_uint8 * 10)(*key_parts)

    # Key schedule
    roundKeys = (ctypes.c_uint8 * (8 * 33))()  # Assuming maximum round keys needed
    present_64_80_key_schedule(key_array, roundKeys)

    # Decrypt the ciphertext
    plaintext = bytearray()
    total_decryption_time = 0
    memory_before = get_memory_usage()
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        # Create ctypes array for the block
        block_array = (ctypes.c_uint8 * len(block))(*block)

        start_time = time.perf_counter()
        # Decrypt the block
        present_decrypt(block_array, roundKeys)
        end_time = time.perf_counter()
        decrytion_time = end_time - start_time
        total_decryption_time += decrytion_time
        # Append the decrypted block to the plaintext
        plaintext.extend(block_array)

    memory_after = get_memory_usage()

    # Format the total encryption time to two decimal places
    formatted_total_decryption_time = round(total_decryption_time, 2)

    # Print the formatted total encryption time
    print("Total decryption time:", formatted_total_decryption_time, "seconds")

    throughput = round(file_size_Kb / total_decryption_time, 2)   # Throughput in Kbps

    print("Decryption Throughput:", throughput, "Kbps")

    memory_consumption = memory_after - memory_before
    print("Average memory usage:", memory_consumption, "bytes")

    return plaintext, formatted_total_decryption_time, throughput, memory_consumption

# --------------------------------------Function to encrypt a file with a 128-bit key--------------------------------------
def c_present_encrypt_file_key_128(plaintext, key):

    file_size = len(plaintext)
    file_size_Kb = file_size * 8 / 1000  # File size in Kilobits

    # Split the binary key into 8 parts of 16 bits each
    key_parts = [int(key[i:i+8], 2) for i in range(0, 128, 8)]

    # Create the ctypes array
    key_array = (ctypes.c_uint8 * 16)(*key_parts)

    # Key schedule
    roundKeys = (ctypes.c_uint8 * (8 * 33))()  # Assuming maximum round keys needed
    present_64_80_key_schedule(key_array, roundKeys)

    total_encryption_time = 0
    # Encrypt the plaintext
    ciphertext = bytearray()
    memory_before = get_memory_usage()
    for i in range(0, len(plaintext), 8):
        block = plaintext[i:i+8]
        # Pad the last block if needed
        if len(block) < 8:
            block += bytes(8 - len(block))
        # Create ctypes array for the block
        block_array = (ctypes.c_uint8 * len(block))(*block)

        start_time = time.perf_counter()
        # Encrypt the block
        present_encrypt(block_array, roundKeys)
        end_time = time.perf_counter()
        encryption_time = end_time - start_time
        total_encryption_time += encryption_time
        # Append the encrypted block to the ciphertext
        ciphertext.extend(block_array)

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

# Function to decrypt a file with a 128-bit key
def c_present_decrypt_file_key_128(ciphertext, key):

    file_size = len(ciphertext)
    file_size_Kb = file_size * 8 / 1000  # File size in Kilobits

    # Split the binary key into 8 parts of 16 bits each
    key_parts = [int(key[i:i+8], 2) for i in range(0, 80, 8)]

    # Create the ctypes array
    key_array = (ctypes.c_uint8 * 10)(*key_parts)

    # Key schedule
    roundKeys = (ctypes.c_uint8 * (8 * 33))()  # Assuming maximum round keys needed
    present_64_80_key_schedule(key_array, roundKeys)

    # Decrypt the ciphertext
    plaintext = bytearray()
    total_decryption_time = 0
    memory_before = get_memory_usage()
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        # Create ctypes array for the block
        block_array = (ctypes.c_uint8 * len(block))(*block)

        start_time = time.perf_counter()
        # Decrypt the block
        present_decrypt(block_array, roundKeys)
        end_time = time.perf_counter()
        decryption_time = end_time - start_time
        total_decryption_time += decryption_time
        # Append the decrypted block to the plaintex
        plaintext.extend(block_array)

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


