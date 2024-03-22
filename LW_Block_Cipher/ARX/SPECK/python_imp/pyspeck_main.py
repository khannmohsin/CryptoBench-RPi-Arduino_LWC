import speck
import time
import psutil


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

def pyspeck_encrypt_file(plaintext, key, block_size):

    len_key = len(key)
    len_plaintext = len(plaintext)
    file_size_Kb = len_plaintext * 8 / 1000  # File size in Kilobits
    
    ksize = len(key)*8
    bsize = int(block_size)

    block_size = int(bsize/8)	
    
    key = int.from_bytes(key, byteorder='big')
    
    cipher = speck.SpeckCipher(key, key_size=ksize, block_size=bsize, mode="ECB")
    
    ciphertext = bytearray()

    total_encryption_time = 0
    avg_memory_usage = []
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i+block_size]
        if len(block) < block_size:
            block = appendPadding(block, blocksize=block_size, mode='EBC')

        int_block = int.from_bytes(block, byteorder='big')

        start_time = time.perf_counter()
        encrypted_block = cipher.encrypt(int_block)

        end_time = time.perf_counter()

        Process = psutil.Process()
        encryption_time = end_time - start_time

        total_encryption_time += encryption_time

        encrypted_block = encrypted_block.to_bytes(block_size, byteorder='big')
        avg_memory_usage.append(Process.memory_info().rss / 1024 / 1024)  # Memory usage in MB
        ciphertext.extend(encrypted_block)

    formatted_total_encryption_time = round(total_encryption_time, 2)

    print("Total encryption time:", formatted_total_encryption_time, "seconds")
    throughput = round(file_size_Kb / total_encryption_time, 2)   # Throughput in Kbps

    print("Encryption Throughput:", throughput, "Kbps")

    ram = round(sum(avg_memory_usage) / len(avg_memory_usage), 2)
    print("Average memory usage:", ram, "MB")
    return ciphertext, formatted_total_encryption_time, throughput, ram 
	
def pyspeck_decrypt_file(ciphertext, key, block_size):

    len_key = len(key)
    len_ciphertext = len(ciphertext)
    file_size_Kb = len_ciphertext * 8 / 1000  # File size in Kilobits

    ksize = len(key)*8
    bsize = int(block_size)
    
    block_size = int(bsize/8)
    
    key = int.from_bytes(key, byteorder='big')
    
    cipher = speck.SpeckCipher(key, key_size=ksize, block_size=bsize, mode="ECB")

    plaintext = bytearray()

    total_decryption_time = 0
    avg_memory_usage = []
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]

        int_block = int.from_bytes(block, byteorder='big')

        start_time = time.perf_counter()

        decrypted_block = cipher.decrypt(int_block)

        end_time = time.perf_counter()

        Process = psutil.Process()

        decryption_time = end_time - start_time

        total_decryption_time += decryption_time

        decrypted_block = decrypted_block.to_bytes(block_size, byteorder='big')
        avg_memory_usage.append(Process.memory_info().rss / 1024 / 1024)
        plaintext.extend(decrypted_block)

    formatted_total_decryption_time = round(total_decryption_time, 2)

    print("Total decryption time:", formatted_total_decryption_time, "seconds")

    throughput = round(file_size_Kb / total_decryption_time, 2)   # Throughput in Kbps
    print("Decryption Throughput:", throughput, "Kbps")

    ram = round(sum(avg_memory_usage) / len(avg_memory_usage), 2)
    print("Average memory usage:", ram, "MB")

    return plaintext, formatted_total_decryption_time, throughput, ram
