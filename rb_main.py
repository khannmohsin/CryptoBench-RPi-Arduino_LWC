import memory_profiler
import argparse
import secrets
import sys
import csv
import os
import time
import subprocess


avg_cpu_cycles = []
bcmticks_process = subprocess.Popen(["./first_cycles"])
time.sleep(10)
bcmticks_process.terminate() 
os.system(f"kill -9 {bcmticks_process.pid}")

if bcmticks_process.poll() is None:
    print("Process is still running. Lets terminate")
else:
	print("Successfully Terminated")

with open ('output.txt', 'r') as file:
    lines = file.readlines()
for line in lines:
    line = line.strip()
    avg_cpu_cycles.append(int(line))

avg_cpu_cycles = avg_cpu_cycles[1:]
avg_cpu_cycles = sum(avg_cpu_cycles)/len(avg_cpu_cycles)

os.remove('output.txt')

def generate_random_key(num_bits):
    # Generate a random byte array of appropriate length
    num_bytes = (num_bits + 7) // 8  # Round up to the nearest whole number of bytes
    random_bytes = secrets.token_bytes(num_bytes)
    # random_integer = int.from_bytes(random_bytes, byteorder='big')
    
    # Convert the byte array to a bit string
    random_key_bits = ''.join(format(byte, '08b') for byte in random_bytes)
    
    # Trim any excess bits
    random_key_bits = random_key_bits[:num_bits]
    
    return random_key_bits, random_bytes

def save_to_csv(algorithm, block_size, key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram):
    headers = ['Algorithm', 'Block Size', 'Key Size', 'Time', 'Throughput', 'Cycles per Byte', 'RAM']
    enc_time_filename = 'Measurements/encryption_time.csv'
    dec_time_filename = 'Measurements/decryption_time.csv'
    enc_throughput_filename = 'Measurements/encryption_throughput.csv'
    dec_throughput_filename = 'Measurements/decryption_throughput.csv'
    enc_CpB_filename = 'Measurements/encryption_CpB.csv'
    dec_CpB_filename = 'Measurements/decryption_CpB.csv'
    enc_ram_filename = 'Measurements/encryption_RAM.csv'
    dec_ram_filename = 'Measurements/decryption_RAM.csv'
    # Update data for Encryption Time
    update_csv_data(enc_time_filename, algorithm, block_size, key_size, enc_time)

    # Update data for Decryption Time
    update_csv_data(dec_time_filename, algorithm, block_size, key_size, dec_time)

    # Update data for Encryption Throughput
    update_csv_data(enc_throughput_filename, algorithm, block_size, key_size, enc_throughput)

    # Update data for Decryption Throughput
    update_csv_data(dec_throughput_filename, algorithm, block_size, key_size, dec_throughput)

    # Update data for Encryption Cycles per Byte
    update_csv_data(enc_CpB_filename, algorithm, block_size, key_size, cycle_per_byte_enc)

    # Update data for Decryption Cycles per Byte
    update_csv_data(dec_CpB_filename, algorithm, block_size, key_size, cycle_per_byte_dec)

    # Update data for Encryption RAM
    update_csv_data(enc_ram_filename, algorithm, block_size, key_size, enc_ram)

    # Update data for Decryption RAM
    update_csv_data(dec_ram_filename, algorithm, block_size, key_size, dec_ram)

def update_csv_data(filename, algorithm, block_size, key_size, value):
    if not os.path.isfile(filename):
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Algorithm', 'Block Size', 'Key Size', 'Value'])

    with open(filename, 'r', newline='') as file:
        reader = csv.reader(file)
        data = list(reader)
        algorithm_exists = False
        for row in data[1:]:
            if row[0] == algorithm and row[1] == str(block_size) and row[2] == str(key_size):
                algorithm_exists = True
                row.append(value)  # Append value to existing row
                break

    if not algorithm_exists:
        with open(filename, 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([algorithm, block_size, key_size, value])
    else:
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Algorithm', 'Block Size', 'Key Size', 'Value'])
            writer.writerows(data[1:])  # Write updated data



def main():
    parser = argparse.ArgumentParser(description="Encrypt/Decrypt files using different cryptographic algorithms")
    parser.add_argument("algorithm", help="The cryptographic algorithm to use", choices=["aes", "py-aes", "present", "py-present", "py-xtea", "clefia", "py-simon", "py-speck", "ascon" , "grain-128a", "mickey", "trivium", "salsa", "sosemanuk"])
    parser.add_argument("key_size", help="The size of the key to use", choices=["64", "80", "96", "128", "192", "256"])
    parser.add_argument("file_path", help="The path to the file to encrypt/decrypt")
    parser.add_argument("block_size", help="The size of the block to use (optional)", choices=["32", "48", "64", "96","128", "-"], default="64")
    args = parser.parse_args()

    number_of_iterations = 10

    file_size_mb = round(os.path.getsize(args.file_path) / (1024 * 1024), 2)
    print("\n----------------------------------------------------------------------------------------------------------")
    print(f"Selected algorithm: {args.algorithm}, key size: {args.key_size}, block size: {args.block_size}, size of file: {file_size_mb} MB., number of iterations: {number_of_iterations}\n")
    print("------------------------------------------------------------------------------------------------------------")
    with open(args.file_path, 'rb') as file:
        plaintext = file.read()
#------------------------------------------ C IMP OF AES CIPHER ------------------------------------------
    if args.algorithm == "aes":

        sys.path.append('Conv_cipher/AES/c_imp/')
        from cAES_main import c_aes_encrypt_file, c_aes_decrypt_file
        
        for i in range(number_of_iterations):
            print("\n-----------C-imp of AES | Iteration: ", i+1)
            if args.block_size == "128":
                block_size = 128
                print("Encryption Metrics: ")
                if args.key_size == "128":
                    random_key_bits, random_bytes = generate_random_key(128)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = c_aes_encrypt_file(plaintext, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')
                    
                elif args.key_size == "192":
                    random_key_bits, random_bytes = generate_random_key(192)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = c_aes_encrypt_file(plaintext, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                elif args.key_size == "256":
                    random_key_bits, random_bytes = generate_random_key(256)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = c_aes_encrypt_file(plaintext, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:
                    print("--------------Invalid key size for the C AES algorithm.--------------")
                    sys.exit(1)
                    
                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics: ")
                if args.key_size == "128":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = c_aes_decrypt_file(imdt_output, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("c-AES", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                elif args.key_size == "192":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = c_aes_decrypt_file(imdt_output, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("c-AES", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                elif args.key_size == "256":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = c_aes_decrypt_file(imdt_output, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("c-AES", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)

            else: 
                print("--------------Invalid block size for the C AES algorithm.--------------")

#------------------------------------------ PYTHON IMP OF AES CIPHER ------------------------------------------
    if args.algorithm == "py-aes":

        sys.path.append('Conv_cipher/AES/python_imp/')
        from pyaes_main import pyaes_encrypt_file, pyaes_decrypt_file
        
        for i in range(number_of_iterations):
            print("\n-----------Python-imp of AES | Iteration: ", i+1)
            if args.block_size == "128":
                block_size = 128
                print("Encryption Metrics: ")
                if args.key_size == "128":
                    random_key_bits, random_bytes = generate_random_key(128)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pyaes_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')
                    
                elif args.key_size == "192":
                    random_key_bits, random_bytes = generate_random_key(192)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pyaes_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                elif args.key_size == "256":
                    random_key_bits, random_bytes = generate_random_key(256)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pyaes_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:
                    print("--------------Invalid key size for the Python AES algorithm.--------------")
                    sys.exit(1)
                    
                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics: ")
                if args.key_size == "128":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pyaes_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-AES", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                elif args.key_size == "192":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pyaes_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-AES", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                elif args.key_size == "256":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pyaes_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-AES", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)

            else: 
                print("--------------Invalid block size for the Python AES algorithm.--------------")


#------------------------------------------ C IMP OF PRESENT CIPHER ------------------------------------------
    if args.algorithm == "present":

        sys.path.append('LW_Block_Cipher/SPN/PRESENT/c_imp/')
        from cpresent_main import c_present_encrypt_file_key_80, c_present_decrypt_file_key_80, c_present_encrypt_file_key_128, c_present_decrypt_file_key_128

        for i in range(number_of_iterations):
            print("\n-----------C-imp of PRESENT | Iteration: ", i+1)
            if args.block_size == "64":
                print("Encryption Metrics: ")
                if args.key_size == "80":
                    random_key_bits, random_bytes = generate_random_key(80)
                    key = random_key_bits
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram   = c_present_encrypt_file_key_80(plaintext, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')
                
                elif args.key_size == "128":
                    random_key_bits, random_bytes = generate_random_key(128)
                    key = random_key_bits
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = c_present_encrypt_file_key_128(plaintext, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:
                    print("--------------Invalid key size for the C PRESENT algorithm------------------")
                    sys.exit(1)
                

                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics: ")
                if args.key_size == "80":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = c_present_decrypt_file_key_80(imdt_output, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("c-PRESENT", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                elif args.key_size == "128":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = c_present_decrypt_file_key_128(imdt_output, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("c-PRESENT", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)
                
                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)

            else:
                print("----------------Invalid block size for the C PRESENT algorithm------------------")
    

#------------------------------------------ PYTHON IMP OF PRESENT CIPHER ------------------------------------------
    if args.algorithm == "py-present":

        sys.path.append('LW_Block_Cipher/SPN/PRESENT/python_imp/')
        from pypresent_main import pypresent_encrypt_file, pypresent_decrypt_file

        for i in range(number_of_iterations):
            print("\n-----------Python-imp of PRESENT | Iteration: ", i+1)
            if args.block_size == "64":
                print("Encryption Metrics: ")
                if args.key_size == "80":
                    random_key_bits, random_bytes = generate_random_key(80)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram  = pypresent_encrypt_file(plaintext, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')
                
                elif args.key_size == "128":
                    random_key_bits, random_bytes = generate_random_key(128)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pypresent_encrypt_file(plaintext, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:
                    print("--------------Invalid key size for the Python PRESENT algorithm.--------------")
                    sys.exit(1)

                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics: ")
                if args.key_size == "80":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram  = pypresent_decrypt_file(imdt_output, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-PRESENT", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                elif args.key_size == "128":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram  = pypresent_decrypt_file(imdt_output, key)
                    bcmticks_process.terminate()        
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-PRESENT", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)
            else:
                print("--------------Invalid block size for the Python PRESENT algorithm.--------------")

#------------------------------------------ PYTHON IMP OF XTEA CIPHER ------------------------------------------
    if args.algorithm == "py-xtea":

        sys.path.append('LW_Block_Cipher/FN/XTEA/python_imp/')
        from pyxtea_main import pyxtea_encrypt_file, pyxtea_decrypt_file
        
        for i in range(number_of_iterations):
            print("\n-----------Python-imp of XTEA | Iteration: ", i+1)
            if args.block_size == "64":
                print("Encryption Metrics: ")
                if args.key_size == "128":
                    random_key_bits, random_bytes = generate_random_key(128)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pyxtea_encrypt_file(plaintext, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:
                    print("--------------Invalid key size for the Python XTEA algorithm.--------------")
                    sys.exit(1)

                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics: ")
                if args.key_size == "128":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pyxtea_decrypt_file(imdt_output, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-XTEA", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)

            else:
                print("--------------Invalid block size for the Python XTEA algorithm.--------------")

#------------------------------------------ C IMP OF CLEFIA CIPHER ------------------------------------------
    if args.algorithm == "clefia":

        sys.path.append('LW_Block_Cipher/GFN/CLEFIA/c_imp/')
        from cClefia_main import cClefia_encrypt_file, cClefia_decrypt_file
        
        for i in range(number_of_iterations):
            print("\n-----------C-imp of CLEFIA | Iteration: ", i+1)
            if args.block_size == "128":
                block_size = 128
                print("Encryption Metrics: ")
                if args.key_size == "128":
                    random_key_bits, random_bytes = generate_random_key(128)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = cClefia_encrypt_file(plaintext, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                elif args.key_size == "192":
                    random_key_bits, random_bytes = generate_random_key(192)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = cClefia_encrypt_file(plaintext, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                elif args.key_size == "256":
                    random_key_bits, random_bytes = generate_random_key(256)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = cClefia_encrypt_file(plaintext, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:
                    print("--------------Invalid key size for the C Clefia algorithm.--------------")
                    sys.exit(1)
                    
                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics: ")
                if args.key_size == "128":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = cClefia_decrypt_file(imdt_output, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("c-CLEFIA", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                elif args.key_size == "192":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = cClefia_decrypt_file(imdt_output, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("c-CLEFIA", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                elif args.key_size == "256":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = cClefia_decrypt_file(imdt_output, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("c-CLEFIA", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)

            else: 
                print("--------------Invalid block size for the C Clefia algorithm.--------------")

#------------------------------------------ PYTHON IMP OF SIMON CIPHER ------------------------------------------
    if args.algorithm == "py-simon":

        sys.path.append('LW_Block_Cipher/FN/SIMON/python_imp/')
        from pysimon_main import pysimon_encrypt_file, pysimon_decrypt_file

        for i in range(number_of_iterations):
            print("\n-----------Python-imp of SIMON | Iteration: ", i+1)
            if args.block_size == "32":
                block_size = 32
                print("Encryption Metrics: ")
                if args.key_size == "64":
                    random_key_bits, random_bytes = generate_random_key(64)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pysimon_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:
                    print("--------------Invalid key size for the Python SIMON algorithm.--------------")
                    sys.exit(1) 

                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics: ")
                if args.key_size == "64":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pysimon_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-SIMON", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)
            
            elif args.block_size == "48":
                block_size = 48
                print("Encryption Metrics: ")
                if args.key_size == "96":
                    random_key_bits, random_bytes = generate_random_key(96)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pysimon_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:   
                    print("--------------Invalid key size for the Python SIMON algorithm.--------------")
                    sys.exit(1)

                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics: ")
                if args.key_size == "96":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pysimon_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-SIMON", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)

            elif args.block_size == "64":
                block_size = 64
                print("Encryption Metrics: ")
                if args.key_size == "96":
                    random_key_bits, random_bytes = generate_random_key(96)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pysimon_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')
                
                elif args.key_size == "128":
                    random_key_bits, random_bytes = generate_random_key(128)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pysimon_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:
                    print("--------------Invalid key size for the Python SIMON algorithm.--------------")
                    sys.exit(1)

                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics: ")
                if args.key_size == "96":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pysimon_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-SIMON", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                elif args.key_size == "128":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pysimon_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-SIMON", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)

            elif args.block_size == "96":
                block_size = 96
                print("Encryption Metrics: ")
                if args.key_size == "96":
                    random_key_bits, random_bytes = generate_random_key(96)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pysimon_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:
                    print("--------------Invalid key size for the Python SIMON algorithm.--------------")

                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics: ")
                if args.key_size == "96":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pysimon_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-SIMON", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)

            elif args.block_size == "128":
                block_size = 128
                print("Encryption Metrics: ")
                if args.key_size == "128":
                    random_key_bits, random_bytes = generate_random_key(128)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pysimon_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                elif args.key_size == "192":
                    random_key_bits, random_bytes = generate_random_key(192)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pysimon_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')
                
                elif args.key_size == "256":
                    random_key_bits, random_bytes = generate_random_key(256)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pysimon_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:
                    print("--------------Invalid key size for the Python SIMON algorithm.--------------")
                    sys.exit(1)

                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics: ")
                if args.key_size == "128":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pysimon_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))
                    
                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-SIMON", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)
                
                elif args.key_size == "192":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pysimon_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-SIMON", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                elif args.key_size == "256":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pysimon_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-SIMON", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)

            else:
                print("--------------Invalid block size for the Python SIMON algorithm.--------------")

#------------------------------------------ PYTHON IMP OF SPECK CIPHER ------------------------------------------
    if args.algorithm == "py-speck":

        sys.path.append('LW_Block_Cipher/ARX/SPECK/python_imp/')
        from pyspeck_main import pyspeck_encrypt_file, pyspeck_decrypt_file

        for i in range(number_of_iterations):
            print("\n-----------Python-imp of SPECK | Iteration: ", i+1)
            if args.block_size == "32":
                block_size = 32
                print("Encryption Metrics: ")
                if args.key_size == "64":
                    random_key_bits, random_bytes = generate_random_key(64)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pyspeck_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:
                    print("--------------Invalid key size for the Python SPECK algorithm.--------------")
                    sys.exit(1)

                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics: ")
                if args.key_size == "64":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pyspeck_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    save_to_csv("py-SPECK", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)
            
            elif args.block_size == "48":
                block_size = 48
                print("Encryption Metrics: ")
                if args.key_size == "96":
                    random_key_bits, random_bytes = generate_random_key(96)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pyspeck_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:   
                    print("--------------Invalid key size for the Python SPECK algorithm.--------------")
                    sys.exit(1)

                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics: ")
                if args.key_size == "96":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pyspeck_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-SPECK", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)

            elif args.block_size == "64":
                block_size = 64
                print("Encryption Metrics: ")
                if args.key_size == "96":
                    random_key_bits, random_bytes = generate_random_key(96)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pyspeck_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')
                
                elif args.key_size == "128":
                    random_key_bits, random_bytes = generate_random_key(128)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pyspeck_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:   
                    print("--------------Invalid key size for the Python SPECK algorithm.--------------")
                    sys.exit(1)

                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics: ")
                if args.key_size == "96":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pyspeck_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-SPECK", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                elif args.key_size == "128":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pyspeck_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-SPECK", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)

            elif args.block_size == "96":
                block_size = 96
                print("Encryption Metrics: ")
                if args.key_size == "96":
                    random_key_bits, random_bytes = generate_random_key(96)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pyspeck_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:   
                    print("--------------Invalid key size for the Python SPECK algorithm.--------------")
                    sys.exit(1)

                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics: ")
                if args.key_size == "96":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pyspeck_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-SPECK", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)

            elif args.block_size == "128":
                block_size = 128
                print("Encryption Metrics: ")
                if args.key_size == "128":
                    random_key_bits, random_bytes = generate_random_key(128)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pyspeck_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                elif args.key_size == "192":
                    random_key_bits, random_bytes = generate_random_key(192)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pyspeck_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')
                
                elif args.key_size == "256":
                    random_key_bits, random_bytes = generate_random_key(256)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = pyspeck_encrypt_file(plaintext, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt') 

                else:
                    print("--------------Invalid key size for the Python SPECK algorithm.--------------")
                    sys.exit(1)

                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics: ")
                if args.key_size == "128":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pyspeck_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-SPECK", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)
                
                elif args.key_size == "192":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pyspeck_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-SPECK", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                elif args.key_size == "256":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = pyspeck_decrypt_file(imdt_output, key, block_size)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("py-SPECK", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)

#------------------------------------------ C IMP OF ASCON CIPHER ------------------------------------------

    if args.algorithm == "ascon":
             
            sys.path.append('LW_Stream_Cipher/LWAE/ASCON/c_imp/')
            from cAscon_main import c_ascon_encrypt_file, c_ascon_decrypt_file

            for i in range(number_of_iterations):
                print("\n-----------C-imp of ASCON | Iteration: ", i+1)
                print("Encryption Metrics:")
                if args.key_size == "128":
                    random_key_bits, random_bytes = generate_random_key(128)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = c_ascon_encrypt_file(plaintext, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:
                    print("--------------Invalid key size for the C ASCON algorithm.--------------")
                    
                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics:")
                if args.key_size == "128":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = c_ascon_decrypt_file(imdt_output, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("c-ASCON", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)
        
                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)

#------------------------------------------ C IMP OF Grain-128a CIPHER ------------------------------------------

    if args.algorithm == "grain-128a":
             
            sys.path.append('LW_Stream_Cipher/LWAE/Grain128a/c_imp/')
            from cGrain128a_main import c_grain128_encrypt_file, c_grain128_decrypt_file

            for i in range(number_of_iterations):
                print("\n-----------C-imp of Grain-128a | Iteration: ", i+1)
                print("Encryption Metrics:")
                if args.key_size == "128":
                    random_key_bits, random_bytes = generate_random_key(128)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram = c_grain128_encrypt_file(plaintext, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:
                    print("--------------Invalid key size for the C Grain-128a algorithm.--------------")
                    
                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics:")
                if args.key_size == "128":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = c_grain128_decrypt_file(imdt_output, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("c-Grain-128a", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)


#------------------------------------------ C IMP OF Mickey-v2 CIPHER ------------------------------------------

    if args.algorithm == "mickey":
             
            sys.path.append('LW_Stream_Cipher/eSTREAM/HW_oriented/Mickey/c_imp')
            from cMickey_main import c_mickey_encrypt_file, c_mickey_decrypt_file

            for i in range(number_of_iterations):   
                print("\n-----------C-imp of Mickey-v2 | Iteration: ", i+1)
                print("Encryption Metrics:")
                if args.key_size == "80":
                    random_key_bits, random_bytes = generate_random_key(80)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram  = c_mickey_encrypt_file(plaintext, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:
                    print("--------------Invalid key size for the C Mickey-v2 algorithm.--------------")
                    
                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics:")
                if args.key_size == "80":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = c_mickey_decrypt_file(imdt_output, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("c-MICKEY-80", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)


#------------------------------------------ C IMP OF Trivium CIPHER ------------------------------------------

    if args.algorithm == "trivium":
             
            sys.path.append("LW_Stream_Cipher/eSTREAM/HW_oriented/Trivium/c_imp")
            from cTRivium_main import c_trivium_encrypt_file, c_trivium_decrypt_file

            for i in range(number_of_iterations):
                print("\n-----------C-imp of Trivium | Iteration: ", i+1)  
                print("Encryption Metrics:")
                if args.key_size == "80":
                    print("You selected the 80-bit key C Trivium algorithm.")
                    random_key_bits, random_bytes = generate_random_key(80)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput, enc_ram  = c_trivium_encrypt_file(plaintext, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:
                    print("--------------Invalid key size for the C Mickey-v2 algorithm.--------------")
                    
                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics:")
                if args.key_size == "80":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput, dec_ram = c_trivium_decrypt_file(imdt_output, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("c-Trivium-80", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)


#------------------------------------------ C IMP OF Salsa CIPHER ------------------------------------------

    if args.algorithm == "salsa":
             
            sys.path.append("LW_Stream_Cipher/eSTREAM/SW_oriented/Salsa/c_imp")
            from cSalsa_main import c_salsa_encrypt_file, c_salsa_decrypt_file

            for i in range(number_of_iterations):  
                print("\n-----------C-imp of Salsa | Iteration: ", i+1) 
                print("Encryption Metrics:")
                if args.key_size == "128":
                    random_key_bits, random_bytes = generate_random_key(128)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput  = c_salsa_encrypt_file(plaintext, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:
                    print("--------------Invalid key size for the C Salsa20 algorithm.--------------")
                    
                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics:")        
                if args.key_size == "128":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput = c_salsa_decrypt_file(imdt_output, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    os.remove('output.txt')
                    save_to_csv("c-Salsa-128", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)

#------------------------------------------ C IMP OF Sosemanuk CIPHER ------------------------------------------

    if args.algorithm == "sosemanuk":
             
            sys.path.append("LW_Stream_Cipher/eSTREAM/SW_oriented/Sosemanuk/c_imp")
            from cSosemanuk_main import c_sosemanuk_encrypt_file, c_sosemanuk_decrypt_file

            for i in range(number_of_iterations):   
                print("\n-----------C-imp of Sosemanuk | Iteration: ", i+1)
                print("Encryption Metrics:")
                if args.key_size == "128":
                    random_key_bits, random_bytes = generate_random_key(128)
                    key = random_bytes
                    cycle_count_enc = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    imdt_output, enc_time, enc_throughput  = c_sosemanuk_encrypt_file(plaintext, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_enc.append(int(line))

                    cycle_count_enc = [x - int(avg_cpu_cycles) for x in cycle_count_enc]
                    cycle_per_byte_enc = sum(cycle_count_enc)/len(plaintext)
                    cycle_per_byte_enc = int(cycle_per_byte_enc)
                    print(f"Encryption Cycles per byte: {cycle_per_byte_enc} CpB")
                    os.remove('output.txt')

                else:
                    print("--------------Invalid key size for the C Sosemanuk algorithm.--------------")
                    
                with open('Files/Crypto_intermediate/encrypted_imdt.enc', 'wb') as file:
                        file.write(imdt_output)

                print("\nDecryption Metrics:")
                if args.key_size == "128":
                    cycle_count_dec = []
                    bcmticks_process = subprocess.Popen(["./first_cycles"])
                    decrypted_output, dec_time, dec_throughput = c_sosemanuk_decrypt_file(imdt_output, key)
                    bcmticks_process.terminate()
                    os.system(f"kill -9 {bcmticks_process.pid}")
                    with open ('output.txt', 'r') as file:
                        lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        cycle_count_dec.append(int(line))

                    cycle_count_dec = [x - int(avg_cpu_cycles) for x in cycle_count_dec]
                    cycle_per_byte_dec = sum(cycle_count_dec)/len(plaintext)
                    cycle_per_byte_dec = int(cycle_per_byte_dec)
                    print(f"Decryption Cycles per byte: {cycle_per_byte_dec} CpB")
                    save_to_csv("c-Sosemanuk-128", args.block_size, args.key_size, enc_time, enc_throughput, dec_time, dec_throughput, cycle_per_byte_enc, cycle_per_byte_dec, enc_ram, dec_ram)

                with open('Files/Crypto_output/decrypted_image.jpg', 'wb') as file:
                    file.write(decrypted_output)

if __name__ == "__main__":
    main()