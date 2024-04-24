import ctypes
import time
import resource
import secrets

xtea_lib = ctypes.CDLL("LW_Block_Cipher/FN/XTEA/c_imp/xtea.so")

xtea_encipher = xtea_lib.xtea_encipher
xtea_encipher.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
xtea_encipher.restype = None

xtea_decipher = xtea_lib.xtea_decipher
xtea_decipher.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
xtea_decipher.restype = None

# def generate_random_key():
#     # Generate 128-bit random key
#     key = secrets.randbits(128)
#     return key

def get_memory_usage():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

def xtea_encrypt(data, key):
    # Pad the data if its length is not a multiple of 2
    if len(data) % 2 != 0:
        data += [0]  # Append a zero to make the length even

    # Convert data and key to uint32_t arrays
    data_array = (ctypes.c_uint32 * len(data))(*data)
    key_array = (ctypes.c_uint32 * 4)(*key)
    
    # Call the C function
    xtea_encipher(data_array, key_array)
    
    # Return the encrypted data
    return list(data_array)

def c_xtea_encrypt_file(plaintext, key):
    file_size = len(plaintext)
    file_size_Kb = file_size * 8 / 1000  # File size in Kilobits
    key_length = len(key) * 8  # Key length in bits

    key = int(key.hex(), 16)
    key = [
    (key >> 96) & 0xFFFFFFFF,
    (key >> 64) & 0xFFFFFFFF,
    (key >> 32) & 0xFFFFFFFF,
    key & 0xFFFFFFFF
    ]

    data = []
    memory_before = get_memory_usage()
    for i in range(0, len(plaintext), 4):
        block = plaintext[i:i + 4]
        value = int.from_bytes(block, byteorder='big') if len(block) == 4 else int.from_bytes(block.ljust(4, b'\x00'), byteorder='big')
        data.append(value)

    start_time = time.perf_counter()
    encrypted_data = xtea_encrypt(data, key)
    end_time = time.perf_counter()
    encryption_time = end_time - start_time
    total_encryption_time = encryption_time

    encrypted_bytes = b''.join(value.to_bytes(4, byteorder='big') for value in encrypted_data)
    # print("ciphertext:", ciphertext)

    memory_after = get_memory_usage()

    formatted_total_encryption_time = round(total_encryption_time, 2)
    print("Total encryption time:", formatted_total_encryption_time, "seconds")

    throughput = round(file_size_Kb / total_encryption_time, 2)  # Throughput in Kbps
    print("Encryption Throughput:", throughput, "Kbps")

    memory_consumption = memory_after - memory_before
    print("Average memory usage:", memory_consumption, "bytes")

    return encrypted_bytes, formatted_total_encryption_time, throughput, memory_consumption


def xtea_decrypt(data, key):
    # Pad the data if its length is not a multiple of 2
    if len(data) % 2 != 0:
        data += [0]  # Append a zero to make the length even

    # Convert data and key to uint32_t arrays
    data_array = (ctypes.c_uint32 * len(data))(*data)
    key_array = (ctypes.c_uint32 * 4)(*key)
    
    # Call the C function
    xtea_decipher(data_array, key_array)

    # Return the decrypted data
    return list(data_array)

def c_xtea_decrypt_file(ciphertext, key):
    file_size = len(ciphertext)
    file_size_Kb = file_size * 8 / 1000  # File size in Kilobits

    key = int(key.hex(), 16)
    key = [
    (key >> 96) & 0xFFFFFFFF,
    (key >> 64) & 0xFFFFFFFF,
    (key >> 32) & 0xFFFFFFFF,
    key & 0xFFFFFFFF
    ]

    data = []
    memory_before = get_memory_usage()
    for i in range(0, len(ciphertext), 4):
        block = ciphertext[i:i + 4]
        value = int.from_bytes(block, byteorder='big') if len(block) == 4 else int.from_bytes(block.ljust(4, b'\x00'), byteorder='big')
        data.append(value)

    if len(data) % 2 != 0:
        data += [0]

    start_time = time.perf_counter()
    decrypted_data = xtea_decrypt(data, key)
    end_time = time.perf_counter()
    decryption_time = end_time - start_time
    total_decryption_time = decryption_time

    decrypted_bytes = b''.join(value.to_bytes(4, byteorder='big') for value in decrypted_data)
    # print("plaintext:", plaintext)

    memory_after = get_memory_usage()

    formatted_total_decryption_time = round(total_decryption_time, 2)
    print("Total decryption time:", formatted_total_decryption_time, "seconds")

    throughput = round(file_size_Kb / total_decryption_time, 2)  # Throughput in Kbps
    print("Decryption Throughput:", throughput, "Kbps")

    memory_consumption = memory_after - memory_before
    print("Average memory usage:", memory_consumption, "bytes")

    return decrypted_bytes, formatted_total_decryption_time, throughput, memory_consumption