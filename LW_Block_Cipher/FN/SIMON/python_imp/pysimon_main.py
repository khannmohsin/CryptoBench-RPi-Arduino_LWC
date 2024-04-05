# https://asecuritysite.com/encryption/simon
import simon
import binascii
import sys
import time
import resource
	

def get_memory_usage():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

def pysimon_encrypt_file(plaintext, key, block_size):

    file_size = len(plaintext)
    file_size_Kb = file_size * 8 / 1000  # File size in Kilobits

    ksize = len(key)*8
    bsize = int(block_size)

    block_size = int(bsize/8)	
    
    key = int.from_bytes(key, byteorder='big')
    
    cipher = simon.SimonCipher(key, key_size=ksize, block_size=bsize, mode="ECB")
    
    ciphertext = bytearray()

    total_encryption_time = 0
    memory_before = get_memory_usage()  
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i+block_size]
        if len(block) < block_size:
            block = appendPadding(block, blocksize=block_size, mode='EBC')
        
        int_block = int.from_bytes(block, byteorder='big')

        start_time = time.perf_counter()
        encrypted_block = cipher.encrypt(int_block)

        end_time = time.perf_counter()

        encryption_time = end_time - start_time

        total_encryption_time += encryption_time

        encrypted_block = encrypted_block.to_bytes(block_size, byteorder='big')
        ciphertext.extend(encrypted_block)

    memory_after = get_memory_usage()

    formatted_total_encryption_time = round(total_encryption_time, 2)

    print("Total encryption time:", formatted_total_encryption_time, "seconds")

    throughput = round(file_size_Kb / total_encryption_time, 2)   # Throughput in Kbps

    print("Encryption Throughput:", throughput, "Kbps")

    memory_consumption = memory_after - memory_before
    print("Average memory usage:", memory_consumption, "bytes")

    return ciphertext, formatted_total_encryption_time, throughput, memory_consumption
	
def pysimon_decrypt_file(ciphertext, key, block_size):

    file_size = len(ciphertext)
    file_size_Kb = file_size * 8 / 1000  # File size in Kilobits

    ksize = len(key)*8
    bsize = int(block_size)
    
    block_size = int(bsize/8)
    
    key = int.from_bytes(key, byteorder='big')
    
    cipher = simon.SimonCipher(key, key_size=ksize, block_size=bsize, mode="ECB")

    plaintext = bytearray()

    total_decryption_time = 0
    memory_before = get_memory_usage()

    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]

        int_block = int.from_bytes(block, byteorder='big')

        start_time = time.perf_counter()

        decrypted_block = cipher.decrypt(int_block)

        end_time = time.perf_counter()

        decryption_time = end_time - start_time

        total_decryption_time += decryption_time

        decrypted_block = decrypted_block.to_bytes(block_size, byteorder='big')
        plaintext.extend(decrypted_block)

    memory_after = get_memory_usage()

    formatted_total_decryption_time = round(total_decryption_time, 2)

    print("Total decryption time:", formatted_total_decryption_time, "seconds")

    throughput = round(file_size_Kb / total_decryption_time, 2)   # Throughput in Kbps
    print("Decryption Throughput:", throughput, "Kbps")

    memory_consumption = memory_after - memory_before
    print("Average memory usage:", memory_consumption, "bytes")

    return plaintext, formatted_total_decryption_time, throughput, memory_consumption	


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
