import ctypes
import secrets
import time
import psutil

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

def generate_random_key(num_bits):
    # Generate a random byte array of appropriate length
    num_bytes = (num_bits + 7) // 8  # Round up to the nearest whole number of bytes
    random_bytes = secrets.token_bytes(num_bytes)
    
    # Convert the byte array to a bit string
    random_key_bits = ''.join(format(byte, '08b') for byte in random_bytes)
    
    # Trim any excess bits
    random_key_bits = random_key_bits[:num_bits]
    
    return random_key_bits

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
    avg_memory_usage = []
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
        Process = psutil.Process()

        total_encryption_time += encryption_time
        avg_memory_usage.append(Process.memory_info().rss / 1024 / 1024)
        # Append the encrypted block to the ciphertext
        ciphertext.extend(block_array)
        
    # Format the total encryption time to two decimal places
    formatted_total_encryption_time = round(total_encryption_time, 2)
    # Print the formatted total encryption time
    print("Total encryption time:", formatted_total_encryption_time, "seconds")

    throughput = round(file_size_Kb / total_encryption_time, 2)   # Throughput in Kbps
    print("Encryption Throughput:", throughput, "Kbps")

    ram = round(sum(avg_memory_usage) / len(avg_memory_usage), 2)
    print("Average memory usage:", ram, "MB")
    return ciphertext, formatted_total_encryption_time, throughput, ram

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
    avg_memory_usage = []
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        # Create ctypes array for the block
        block_array = (ctypes.c_uint8 * len(block))(*block)

        start_time = time.perf_counter()
        # Decrypt the block
        present_decrypt(block_array, roundKeys)
        end_time = time.perf_counter()
        Process = psutil.Process()
        decrytion_time = end_time - start_time
        total_decryption_time += decrytion_time
        avg_memory_usage.append(Process.memory_info().rss / 1024 / 1024)
        # Append the decrypted block to the plaintext
        plaintext.extend(block_array)

    # Format the total encryption time to two decimal places
    formatted_total_decryption_time = round(total_decryption_time, 2)

    # Print the formatted total encryption time
    print("Total decryption time:", formatted_total_decryption_time, "seconds")

    throughput = round(file_size_Kb / total_decryption_time, 2)   # Throughput in Kbps

    print("Decryption Throughput:", throughput, "Kbps")

    ram = round(sum(avg_memory_usage) / len(avg_memory_usage), 2)
    print("Average memory usage:", ram, "MB")

    return plaintext, formatted_total_decryption_time, throughput, ram

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
    avg_memory_usage = []
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
        Process = psutil.Process()
        encryption_time = end_time - start_time
        total_encryption_time += encryption_time
        # Append the encrypted block to the ciphertext
        avg_memory_usage.append(Process.memory_info().rss / 1024 / 1024)
        ciphertext.extend(block_array)

    # Format the total encryption time to two decimal places
    formatted_total_encryption_time = round(total_encryption_time, 2)

    # Print the formatted total encryption time
    print("Total encryption time:", formatted_total_encryption_time, "seconds")

    throughput = round(file_size_Kb / total_encryption_time, 2)   # Throughput in Kbps
    print("Encryption Throughput:", throughput, "Kbps")

    ram = round(sum(avg_memory_usage) / len(avg_memory_usage), 2)
    print("Average memory usage:", ram, "MB")

    return ciphertext, formatted_total_encryption_time, throughput, ram

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
    avg_memory_usage = []
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        # Create ctypes array for the block
        block_array = (ctypes.c_uint8 * len(block))(*block)

        start_time = time.perf_counter()
        # Decrypt the block
        present_decrypt(block_array, roundKeys)
        end_time = time.perf_counter()
        Process = psutil.Process()
        decryption_time = end_time - start_time
        total_decryption_time += decryption_time
        avg_memory_usage.append(Process.memory_info().rss / 1024 / 1024)
        # Append the decrypted block to the plaintex
        plaintext.extend(block_array)

    # Format the total encryption time to two decimal places
    formatted_total_decryption_time = round(total_decryption_time, 2)

    # Print the formatted total encryption time
    print("Total decryption time:", formatted_total_decryption_time, "seconds")

    throughput = round(file_size_Kb / total_decryption_time, 2)   # Throughput in Kbps
    print("Decryption Throughput:", throughput, "Kbps")

    ram = round(sum(avg_memory_usage) / len(avg_memory_usage), 2)
    print("Average memory usage:", ram, "MB")

    return plaintext, formatted_total_decryption_time, throughput, ram


