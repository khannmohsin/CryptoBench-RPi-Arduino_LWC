import ctypes
import time
import subprocess
import os

crypto_lib = ctypes.CDLL('LW_Stream_Cipher/LWAE/ASCON/c_imp/main.so')

# Define the argument types and return type for the function
crypto_lib.crypto_aead_encrypt.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),  # unsigned char *c
    ctypes.POINTER(ctypes.c_ulonglong),  # unsigned long long *clen
    ctypes.POINTER(ctypes.c_ubyte),  # const unsigned char *m
    ctypes.c_ulonglong,  # unsigned long long mlen
    ctypes.POINTER(ctypes.c_ubyte),  # const unsigned char *ad
    ctypes.c_ulonglong,  # unsigned long long adlen
    ctypes.POINTER(ctypes.c_ubyte),  # const unsigned char *nsec
    ctypes.POINTER(ctypes.c_ubyte),  # const unsigned char *npub
    ctypes.POINTER(ctypes.c_ubyte)   # const unsigned char *k
]
crypto_lib.crypto_aead_encrypt.restype = ctypes.c_int  # Return type int

# Define the argument types and return type for the function
crypto_lib.crypto_aead_decrypt.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),  # unsigned char *m
    ctypes.POINTER(ctypes.c_ulonglong),  # unsigned long long *mlen
    ctypes.POINTER(ctypes.c_ubyte),  # unsigned char *nsec
    ctypes.POINTER(ctypes.c_ubyte),  # const unsigned char *cp
    ctypes.c_ulonglong,  # unsigned long long clen
    ctypes.POINTER(ctypes.c_ubyte),  # const unsigned char *adp
    ctypes.c_ulonglong,  # unsigned long long adlen
    ctypes.POINTER(ctypes.c_ubyte),  # const unsigned char *npubp
    ctypes.POINTER(ctypes.c_ubyte)   # const unsigned char *kp
]
crypto_lib.crypto_aead_decrypt.restype = ctypes.c_int  # Return type int

def crypto_aead_decrypt(m, mlen, nsec, cp, clen, adp, adlen, npubp, kp):
    return crypto_lib.crypto_aead_decrypt(m, mlen, nsec, cp, clen, adp, adlen, npubp, kp)

def crypto_aead_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k):
    return crypto_lib.crypto_aead_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k)

def get_memory_usage():
    output = subprocess.check_output(["ps", "-p", str(os.getpid()), "-o", "rss="])
    return int(output) * 1024  # Convert to bytes


def c_ascon_encrypt_file(plaintext, key):

    len_key = len(key)
    len_plaintext = len(plaintext)
    file_size_Kb = len_plaintext * 8 / 1000  # File size in Kilobits

    hex_image_bytes_literal = plaintext

    # Example usage
    m = plaintext  # Example plaintext
    m_buffer = ctypes.create_string_buffer(hex_image_bytes_literal)  # Example buffer for plaintext
    m_ptr = ctypes.cast(m_buffer, ctypes.POINTER(ctypes.c_ubyte))
    mlen = ctypes.c_ulonglong(len(m))  # Length of the message

    ad = b"additional data"  # Example additional data
    ad_buffer = ctypes.create_string_buffer(ad)
    ad_ptr = ctypes.cast(ad_buffer, ctypes.POINTER(ctypes.c_ubyte))
    adlen = ctypes.c_ulonglong(len(ad))  # Length of additional data

    nsec = None  # Example value for nsec (can be None)

    npub = b"nonce"  # Example nonce
    npub_buffer = ctypes.create_string_buffer(npub)
    npub_ptr = ctypes.cast(npub_buffer, ctypes.POINTER(ctypes.c_ubyte))

    k = key  # Example key
    k_buffer = ctypes.create_string_buffer(k)
    k_ptr = ctypes.cast(k_buffer, ctypes.POINTER(ctypes.c_ubyte))

    c_len = ctypes.c_ulonglong()  # Example variable for clen
    
    memory_before = get_memory_usage()
    c_buffer = ctypes.create_string_buffer(len(m) + 16)  # Example buffer for ciphertext
    c_ptr = ctypes.cast(c_buffer, ctypes.POINTER(ctypes.c_ubyte))

    # Call the function
    start_time = time.perf_counter()
    result_encrypt = crypto_aead_encrypt(c_ptr, ctypes.byref(c_len), m_ptr, mlen, ad_ptr, adlen, nsec, npub_ptr, k_ptr)
    end_time = time.perf_counter()
    encryption_time = end_time - start_time
    memory_after = get_memory_usage()

    if result_encrypt == 0:
        print("Encryption successful!")
        buffer_contents = ctypes.string_at(c_buffer, c_len.value)

        formatted_encryption_time = round(encryption_time, 2)
        print("Total encryption time:", formatted_encryption_time, "seconds")

        throughput = round(file_size_Kb / encryption_time, 2)   # Throughput in Kbps
        print("Encryption Throughput:", throughput, "Kbps")

        memory_consumption = memory_after - memory_before
        print("Memory usage:", memory_consumption, "bytes")

        return buffer_contents, formatted_encryption_time, throughput, memory_consumption
    else:
        print("Encryption failed!")


def c_ascon_decrypt_file(ciphertext, key):

    len_key = len(key)
    len_ciphertext = len(ciphertext)
    file_size_Kb = len_ciphertext * 8 / 1000  # File size in Kilobits
    
    k_buffer = ctypes.create_string_buffer(key)
    k_ptr = ctypes.cast(k_buffer, ctypes.POINTER(ctypes.c_ubyte))

    ad = b"additional data"  # Example additional data
    ad_buffer = ctypes.create_string_buffer(ad)
    ad_ptr = ctypes.cast(ad_buffer, ctypes.POINTER(ctypes.c_ubyte))
    adlen = ctypes.c_ulonglong(len(ad))  # Length of additional data

    nsec = None  # Example value for nsec (can be None)

    npub = b"nonce"  # Example nonce
    npub_buffer = ctypes.create_string_buffer(npub)
    npub_ptr = ctypes.cast(npub_buffer, ctypes.POINTER(ctypes.c_ubyte))
    m_len = ctypes.c_ulonglong()

    clen = ctypes.c_ulonglong(len(ciphertext))
    ciphertext_buffer = ctypes.create_string_buffer(ciphertext)
    ciphertext_ptr = ctypes.cast(ciphertext_buffer, ctypes.POINTER(ctypes.c_ubyte))

    memory_before = get_memory_usage()
    m_buffer = ctypes.create_string_buffer(len(ciphertext) - 16)  # Example buffer for decrypted message
    m_ptr = ctypes.cast(m_buffer, ctypes.POINTER(ctypes.c_ubyte))

    start_time = time.perf_counter()
    # Call the function
    result_decrypt = crypto_aead_decrypt(m_ptr, ctypes.byref(m_len), nsec, ciphertext_ptr, clen, ad_ptr, adlen, npub_ptr, k_ptr)
    end_time = time.perf_counter()
    decryption_time = end_time - start_time
    memory_after = get_memory_usage()

    if result_decrypt == 0:
        print("Decryption successful!")
        buffer_contents = ctypes.string_at(m_buffer, m_len.value)

        formatted_decryption_time = round(decryption_time, 2)
        
        print("Total decryption time:", formatted_decryption_time, "seconds")

        throughput = round(file_size_Kb / decryption_time, 2)   # Throughput in Kbps

        print("Decryption Throughput:", throughput)

        memory_consumption = memory_after - memory_before
        print("Memory usage:", memory_consumption, "bytes")

        return buffer_contents, formatted_decryption_time, throughput, memory_consumption

    else:
        print("Decryption failed!")

