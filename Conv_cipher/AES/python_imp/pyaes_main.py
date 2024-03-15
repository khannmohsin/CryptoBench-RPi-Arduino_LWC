from aes import AES
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


def pyaes_encrypt_file(plaintext, key, block_size):

    len_key = len(key)
    len_plaintext = len(plaintext)
    
    ksize = len(key)*8
    bsize = int(block_size)
    aes = AES(key)
    
    ciphertext = bytearray()
    # print("Plaintext:", plaintext)  # Debugging
    block_size = int(bsize/8)

    total_encryption_time = 0
    avg_memory_usage = []
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i+block_size]
        if len(block) < block_size:
            block = appendPadding(block, blocksize=block_size, mode='EBC')

        start_time = time.perf_counter()
        encrypted = aes._encrypt_single_block(block)
        end_time = time.perf_counter()
        Process = psutil.Process()

        encryption_time = end_time - start_time
        total_encryption_time += encryption_time
        avg_memory_usage.append(Process.memory_info().rss / 1024 / 1024)
        ciphertext.extend(encrypted)

    formatted_total_encryption_time = round(total_encryption_time, 2)

    print("Total encryption time:", formatted_total_encryption_time, "seconds")

    throughput = round(len_plaintext / total_encryption_time, 2)   # Throughput in Kbps

    print("Encryption Throughput:", throughput, "Kbps")

    ram = round(sum(avg_memory_usage) / len(avg_memory_usage), 2)
    print("Average memory usage:", ram, "MB")

    return ciphertext, formatted_total_encryption_time, throughput


def pyaes_decrypt_file(ciphertext, key, block_size):

    len_ciphertext = len(ciphertext)
    bsize = int(block_size)
    block_size = int(bsize/8)
    aes = AES(key)
    plaintext = bytearray()

    total_decryption_time = 0
    avg_memory_usage = []
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]

        start_time = time.perf_counter()
        decrypted_block = aes._decrypt_single_block(block)
        end_time = time.perf_counter()
        Process = psutil.Process()

        if len(decrypted_block) < block_size:
            decrypted_block = detectPadding(decrypted_block, mode='EBC')

        decryption_time = end_time - start_time
        total_decryption_time += decryption_time
        avg_memory_usage.append(Process.memory_info().rss / 1024 / 1024)
        plaintext.extend(decrypted_block)

    formatted_total_decryption_time = round(total_decryption_time, 2)

    print("Total decryption time:", formatted_total_decryption_time, "seconds")

    throughput = round(len_ciphertext / total_decryption_time, 2)   # Throughput in Kbps

    print("Decryption Throughput:", throughput, "Kbps")

    ram = round(sum(avg_memory_usage) / len(avg_memory_usage), 2)
    print("Average memory usage:", ram, "MB")

    return plaintext, formatted_total_decryption_time, throughput, ram