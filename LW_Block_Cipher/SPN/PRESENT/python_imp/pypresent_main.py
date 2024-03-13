from pypresent import Present
import sys
import time
import psutil

if (len(sys.argv)>1):
	text=str(sys.argv[1])


if (len(sys.argv)>2):
	k=str(sys.argv[2])

# print ('Text:\t'+text)
# print ('Key:\t'+k)
# print ('--------')
# print
# key = bytes.fromhex(k)

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
	

def pypresent_encrypt_file(plaintext, key):

    file_size = len(plaintext)
    file_size_Kb = file_size * 8 / 1000  # File size in Kilobits

    cipher = Present(key)
    block_size = 8
    ciphertext = bytearray()

    total_encryption_time = 0
    avg_memory_usage = []
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i+block_size]
        if len(block) < block_size:
            block = appendPadding(block, blocksize=block_size, mode='EBC')
        
        start_time = time.perf_counter()
        encrypted_block = cipher.encrypt(block)
        end_time = time.perf_counter()
        Process = psutil.Process()
        encryption_time = end_time - start_time
        total_encryption_time += encryption_time
        avg_memory_usage.append(Process.memory_info().rss / 1024 / 1024)  # Memory usage in MB
        ciphertext.extend(encrypted_block)
    # Format the total encryption time to two decimal places
    formatted_total_encryption_time = round(total_encryption_time, 2)

    # Print the formatted total encryption time
    print("Total encryption time:", formatted_total_encryption_time, "seconds")

    throughput = round(file_size_Kb / total_encryption_time, 2)   # Throughput in Kbps
    print("Encryption Throughput:", throughput, "Kbps")

    ram = round(sum(avg_memory_usage) / len(avg_memory_usage), 2)
    print("Average memory usage:", ram, "MB")

    return ciphertext, formatted_total_encryption_time, throughput, ram
	
def pypresent_decrypt_file(ciphertext, key):

    file_size = len(ciphertext)
    file_size_Kb = file_size * 8 / 1000  # File size in Kilobits

    cipher = Present(key)
    block_size = 8
    plaintext = bytearray()
    total_decryption_time = 0
    avg_memory_usage = []   
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]

        start_time = time.perf_counter()
        decrypted_block = cipher.decrypt(block)
        end_time = time.perf_counter()
        Process = psutil.Process()
        decryption_time = end_time - start_time
        total_decryption_time += decryption_time
        avg_memory_usage.append(Process.memory_info().rss / 1024 / 1024)
        plaintext.extend(decrypted_block)

    # Format the total encryption time to two decimal places
    formatted_total_decryption_time = round(total_decryption_time, 2)

    # Print the formatted total encryption time
    print("Total decryption time:", formatted_total_decryption_time, "seconds")

    throughput = round(file_size_Kb / total_decryption_time, 2)   # Throughput in Kbps
    print("Decryption Throughput:", throughput, "Kbps")

    ram = round(sum(avg_memory_usage) / len(avg_memory_usage), 2)
    print("Average memory usage:", ram, "MB")

    return plaintext, formatted_total_decryption_time, throughput, ram

# text = Padding.appendPadding(text,blocksize=8,mode='EBC')
# cipher = Present(key) 
# start=time.perf_counter()
# encrypted = cipher.encrypt(text.encode())
# end=time.perf_counter()
# print ("Encrypt time: ",(end-start))
# print ('Cipher:\t\t'+encrypted.hex())

# start=time.perf_counter()
# decrypted = cipher.decrypt(encrypted)
# end=time.perf_counter()
# print ("Decrypt time: ",(end-start))


# print ('Decrypted:\t'+decrypted.hex())
# print ('Decrypted:\t'+Padding.removePadding(decrypted.decode(),blocksize=8,mode='CMS'))

