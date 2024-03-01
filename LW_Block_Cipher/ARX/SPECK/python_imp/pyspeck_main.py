import speck
import time


# mess='hello'


# k='0x1b1a1918131211100b0a090803020100'

# def getBinary(word):
#     return int(binascii.hexlify(word), 16)

# if (len(sys.argv)>1):
# 	mess=str(sys.argv[1])
# 	m=getBinary(mess)

# if (len(sys.argv)>2):
# 	k=str(sys.argv[2])

# key=int(k,16)

# print ("Message:\t",mess)
# print ("Key:\t\t",k)

# ksize=(len(k)-2)*4

# bsize=32
# if (ksize==72): bsize=48
# if (ksize==96): bsize=48
# if (ksize==128): bsize=64

# print ("Key size:\t",ksize)
# print ("Block size:\t",bsize)

# w = speck.SpeckCipher(key, key_size=ksize, block_size=bsize)

# t = w.encrypt(int.from_bytes(mess.encode(), byteorder='big'))

# print ("Encrypted:\t",hex(t))

# res = w.decrypt(t)

# hexstr= hex(res)
# print ("Decrypt:\t",hexstr)

# res_str=bytes.fromhex(hexstr[2:]).decode('utf-8')
# print ("Decrypt:\t",res_str)

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
    
    ksize = len(key)*8
    bsize = int(block_size)

    block_size = int(bsize/8)	
    
    key = int.from_bytes(key, byteorder='big')
    
    cipher = speck.SpeckCipher(key, key_size=ksize, block_size=bsize, mode="ECB")
    
    ciphertext = bytearray()

    total_encryption_time = 0

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

    formatted_total_encryption_time = round(total_encryption_time, 2)

    print("Total encryption time:", formatted_total_encryption_time, "seconds")

    throughput = round(len_plaintext / total_encryption_time, 2)   # Throughput in Kbps

    print("Encryption Throughput:", throughput, "Kbps")
    return ciphertext, formatted_total_encryption_time, throughput
	
def pyspeck_decrypt_file(ciphertext, key, block_size):

    len_key = len(key)
    len_ciphertext = len(ciphertext)

    ksize = len(key)*8
    bsize = int(block_size)
    
    block_size = int(bsize/8)
    
    key = int.from_bytes(key, byteorder='big')
    
    cipher = speck.SpeckCipher(key, key_size=ksize, block_size=bsize, mode="ECB")

    plaintext = bytearray()

    total_decryption_time = 0
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

    formatted_total_decryption_time = round(total_decryption_time, 2)

    print("Total decryption time:", formatted_total_decryption_time, "seconds")

    throughput = round(len_ciphertext / total_decryption_time, 2)   # Throughput in Kbps

    print("Decryption Throughput:", throughput, "Kbps")
    return plaintext, formatted_total_decryption_time, throughput
