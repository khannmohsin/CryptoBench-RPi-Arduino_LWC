from rabbit import Rabbit
import time
import psutil



def py_rabbit_encrypt_file(plaintext, key):
    iv = 0

    # Convert key to an integer
    int_key = int.from_bytes(key, byteorder='big')

    cipher = Rabbit(int_key, iv)  # Initialize Rabbit cipher with the provided key
    
    start_time = time.perf_counter()
    cipher.keystream(len(plaintext))  # Generate keystream
    plaintext = plaintext.hex()
    ciphertext = cipher.encrypt(plaintext)  # Encrypt plaintext
    end_time = time.perf_counter()

    Process = psutil.Process()
    encryption_time = end_time - start_time

    formatted_encryption_time = round(encryption_time, 2)
    print("Total encryption time:", formatted_encryption_time, "seconds")

    throughput = round(len(plaintext) / encryption_time, 2)   # Throughput in Kbps
    print("Encryption Throughput:", throughput, "Kbps")

    memory_usage = Process.memory_info().rss / 1024 / 1024  # Memory usage in MB
    print("Memory usage:", round(memory_usage, 2), "MB")
    
    return ciphertext, formatted_encryption_time, throughput, round(memory_usage, 2)

def py_rabbit_decrypt_file(ciphertext, key):
    print("passdecrypt")
    iv = 0
    cipher = Rabbit(key, iv)  # Initialize Rabbit cipher with the provided key
    
    start_time = time.perf_counter()
    cipher.keystream(1048576)
    plaintext = cipher.decrypt(ciphertext)
    end_time = time.perf_counter()

    Process = psutil.Process()
    decryption_time = end_time - start_time

    formatted_decryption_time = round(decryption_time, 2)
    print("Total decryption time:", formatted_decryption_time, "seconds")

    throughput = round(len(ciphertext) / decryption_time, 2)   # Throughput in Kbps
    print("Decryption Throughput:", throughput, "Kbps")

    memory_usage = Process.memory_info().rss / 1024 / 1024  # Memory usage in MB
    print("Memory usage:", round(memory_usage, 2), "MB")

    return plaintext, formatted_decryption_time, throughput, round(memory_usage, 2)

# # Example usage:
# plaintext = 'Hello0000000000000000000000 World!'
# key = 0x912813292E3D36FE3BFC62F1DC51C3AC  # Example key
# ciphertext, enc_time, throughput, mem_usage = pyrabbit_encrypt_file(plaintext, key)
# print("Ciphertext:", ciphertext)

# decrypted_plaintext, dec_time, dec_throughput, dec_mem_usage = pyrabbit_decrypt_file(ciphertext, key)
# print("Decrypted plaintext:", decrypted_plaintext)

