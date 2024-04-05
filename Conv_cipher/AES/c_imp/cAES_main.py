import ctypes
import sys
import time
import psutil

# Load the AES library
aes_lib = ctypes.CDLL("Conv_cipher/AES/c_imp/aes.so")  # Replace "libaes.so" with the appropriate library name

# Define required types
WORD = ctypes.c_uint
BYTE = ctypes.c_ubyte * 16

# Define the function signature
aes_key_setup = aes_lib.aes_key_setup
aes_key_setup.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(WORD), ctypes.c_int]

aes_encrypt = aes_lib.aes_encrypt
aes_encrypt.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(WORD), ctypes.c_int]

aes_decrypt = aes_lib.aes_decrypt
aes_decrypt.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(WORD), ctypes.c_int]

def appendPadding(block, blocksize, mode):
    """Append padding to the block.

    Args:
    block: bytes - The input block to pad.
    blocksize: int - The desired block size after padding.
    mode: str - The padding mode. Can be 'EBC' or 'CMS'.

    Returns:
    bytes: The padded block.
    """
    # Perform padding according to the mode
    if mode == 'EBC':
        pad_len = blocksize - (len(block) % blocksize)
        padding = bytes([pad_len]) * pad_len  # Convert pad_len to bytes
    elif mode == 'CMS':
        # Perform padding according to the CMS mode
        pad_len = blocksize - (len(block) % blocksize)
        padding = bytes([0x80]) + bytes([0] * (pad_len - 1))
    else:
        raise ValueError("Invalid padding mode")

    # Concatenate the original block with the padding
    padded_block = block + padding
    return padded_block

def detectPadding(block, mode):
    """Detect and remove padding from the block.

    Args:
    block: bytes - The block from which to detect and remove padding.
    mode: str - The padding mode. Can be 'EBC' or 'CMS'.

    Returns:
    bytes: The unpadded block.
    """
    if mode == 'EBC':
        pad_len = block[-1]  # Get the last byte, which indicates padding length
        if all(byte == pad_len for byte in block[-pad_len:]):
            return block[:-pad_len]  # Remove padding bytes from the end
    elif mode == 'CMS':
        pad_len = block[-1]  # Get the last byte, which indicates padding length
        if all(byte == pad_len for byte in block[-pad_len:]):
            return block[:-pad_len]  # Remove padding bytes from the end
    else:
        raise ValueError("Invalid padding mode")

    # No valid padding detected, return the original block
    return block


def c_aes_encrypt_file(plaintext, key):

    file_size = len(plaintext)
    file_size_Kb = file_size * 8 / 1000  # File size in Kilobits
    key_length = len(key) * 8

    # Prepare key schedule
    key_schedule = (WORD * 60)()
    aes_key_setup((ctypes.c_ubyte * 32)(*key), key_schedule, key_length)

    # Encrypt the plaintext
    ciphertext = bytearray()
    total_encryption_time = 0
    # avg_memory_usage = []
    initial_ram = psutil.virtual_memory().used
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        # Pad the last block if needed
        if len(block) < 16:
            block = appendPadding(block, blocksize=16, mode='EBC')

        enc_buf = (BYTE)()
        start_time = time.perf_counter()
        aes_encrypt((BYTE)(*block), enc_buf, key_schedule, key_length)
        end_time = time.perf_counter()
        # Process = psutil.Process()
        encryption_time = end_time - start_time
        total_encryption_time += encryption_time
        ciphertext += enc_buf
        # avg_memory_usage.append(Process.memory_info().rss / 1024 / 1024)
    final_ram = psutil.virtual_memory().used
    ram_consumption = (final_ram - initial_ram)/1000000
    # Format the total encryption time to two decimal places
    formatted_total_encryption_time = round(total_encryption_time, 2)
    

    # Print the formatted total encryption time
    print("Total encryption time:", formatted_total_encryption_time, "seconds")

    throughput = round(file_size_Kb / total_encryption_time, 2)   # Throughput in Kbps

    print("Encryption Throughput:", throughput, "Kbps")

    # ram = round(sum(avg_memory_usage) / len(avg_memory_usage), 2)
    print("Average memory usage:", ram_consumption, "MB")

    return ciphertext, formatted_total_encryption_time, throughput, ram_consumption


def c_aes_decrypt_file(ciphertext, key):

    file_size = len(ciphertext)
    file_size_Kb = file_size * 8 / 1000  # File size in Kilobits
    key_length = len(key) * 8

    # Prepare key schedule
    key_schedule = (WORD * 60)()
    aes_key_setup((ctypes.c_ubyte * 32)(*key), key_schedule, key_length)

    # Decrypt the ciphertext
    plaintext = bytearray()
    total_decryption_time = 0
    # avg_memory_usage = []
    initial_ram = psutil.virtual_memory().used
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec_buf = (BYTE)()
        start_time = time.perf_counter()
        aes_decrypt((BYTE)(*block), dec_buf, key_schedule, key_length)
        end_time = time.perf_counter()
        # Process = psutil.Process()

        decryption_time = end_time - start_time
        total_decryption_time += decryption_time
        # avg_memory_usage.append(Process.memory_info().rss / 1024 / 1024)
        plaintext += dec_buf

    final_ram = psutil.virtual_memory().used
    ram_consumption = (final_ram - initial_ram)/1000000
    # Format the total encryption time to two decimal places
    formatted_total_decryption_time = round(total_decryption_time, 2)

    # Print the formatted total encryption time
    print("Total decryption time:", formatted_total_decryption_time, "seconds")

    throughput = round(file_size_Kb / total_decryption_time, 2)   # Throughput in Kbps

    print("Decryption Throughput:", throughput, "Kbps")
    # print("Decrypted text:", plaintext)

    # ram = round(sum(avg_memory_usage) / len(avg_memory_usage), 2)
    print("Average memory usage:", ram_consumption, "MB")

    return plaintext, formatted_total_decryption_time, throughput, ram_consumption
