import ctypes
import secrets

# Load the shared object file
cham_lib = ctypes.CDLL('/Users/khannmohsin/VSCode Projects/Measurement_metrics_LWC/LW_Block_Cipher/ARX/CHAM/c_imp/cham_main.so')

# Define function prototypes---------64/128
KeyExpansion64_128 = cham_lib.KeyExpansion64_128
KeyExpansion64_128.argtypes = [ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(ctypes.c_uint16)]
KeyExpansion64_128.restype = None

Encryption64_128 = cham_lib.Encryption64_128
Encryption64_128.argtypes = [ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(ctypes.c_uint16)]
Encryption64_128.restype = None

Decryption64_128 = cham_lib.Decryption64_128
Decryption64_128.argtypes = [ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(ctypes.c_uint16)]
Decryption64_128.restype = None

# Define function prototypes---------128/128
KeyExpansion128_128 = cham_lib.KeyExpansion128_128
KeyExpansion128_128.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
KeyExpansion128_128.restype = None

Encryption128_128 = cham_lib.Encryption128_128
Encryption128_128.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
Encryption128_128.restype = None

Decryption128_128 = cham_lib.Decryption128_128
Decryption128_128.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
Decryption128_128.restype = None

# Define function prototypes---------128/256

KeyExpansion128_256 = cham_lib.KeyExpansion128_256
KeyExpansion128_256.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
KeyExpansion128_256.restype = None

Encryption128_256 = cham_lib.Encryption128_256
Encryption128_256.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
Encryption128_256.restype = None

Decryption128_256 = cham_lib.Decryption128_256
Decryption128_256.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
Decryption128_256.restype = None

# Define function prototypes---------128/512

def generate_random_key(num_bits):
    # Generate a random byte array of appropriate length
    num_bytes = (num_bits + 7) // 8  # Round up to the nearest whole number of bytes
    random_bytes = secrets.token_bytes(num_bytes)
    
    # Convert the byte array to a bit string
    random_key_bits = ''.join(format(byte, '08b') for byte in random_bytes)
    
    # Trim any excess bits
    random_key_bits = random_key_bits[:num_bits]
    
    return random_key_bits

# -----------------------------------------------------------CHAM-64/128-----------------------------------------------------
def encrypt_file_64_128(plaintext, key):

    # Encode the plaintext using ASCII encoding
    plaintext_bytes = plaintext.encode('ascii')

    # Convert each character to its binary representation
    binary_list = [bin(byte)[2:].zfill(8) for byte in plaintext_bytes]

    # Join the binary representations together
    binary_string = ''.join(binary_list)
    # Split the binary plaintext into 4 parts of 16 bits each
    plaintext_parts = [int(binary_string[i:i+16], 2) for i in range(0, 64, 16)]
    # Create the ctypes array
    plaintext_array = (ctypes.c_uint16 * 4)(*plaintext_parts)


    # Split the binary key into 8 parts of 16 bits each
    key_parts = [int(key[i:i+16], 2) for i in range(0, 128, 16)]
    # Create the ctypes array
    key_array = (ctypes.c_uint16 * 8)(*key_parts)


    # Create the ctypes array for the ciphertext
    ciphertext = (ctypes.c_uint16 * 4)()

    # Convert the key array to an integer
    # key_int_back = int(''.join(format(value, '016b') for value in key_array), 2)
    # print("Key value:", key_int_back)


    round_keys = (ctypes.c_uint16 * 16)()

    # Key schedule
    KeyExpansion64_128(key_array, round_keys)

    # Encrypt the plaintext
    Encryption64_128(plaintext_array, round_keys, ciphertext)

    return ciphertext

# def decrypt_file_64_128(plaintext, key):

# Example usage

def decrypt_file_64_128(ciphertext, key):

    decryped_plaintext = (ctypes.c_uint16 * 4)()

    # Split the binary key into 8 parts of 16 bits each
    key_parts = [int(key[i:i+16], 2) for i in range(0, 128, 16)]
    # Create the ctypes array
    key_array = (ctypes.c_uint16 * 8)(*key_parts)

    # Key Schedule
    round_keys = (ctypes.c_uint16 * 16)()

    KeyExpansion64_128(key_array, round_keys)

    Decryption64_128(ciphertext, round_keys, decryped_plaintext)

    print([hex(value) for value in decryped_plaintext])
    decrypted_hex_list = [hex(value) for value in decryped_plaintext]
    print("Decrypted hex:", decrypted_hex_list)
    # Remove the '0x' prefix from each hexadecimal value
    hex_values_no_prefix = [value[2:] for value in decrypted_hex_list]
    # Join the hexadecimal values together
    decrypted_hex_string = ''.join(hex_values_no_prefix)
    # Convert the hexadecimal string to bytes
    decrypted_binary_data = bytes.fromhex(decrypted_hex_string)
    decrypted_plaintext = decrypted_binary_data.decode('ascii')
    print("Original plaintext:", decrypted_plaintext)

# -----------------------------------------------------------CHAM-64/128 (ECB)-----------------------------------------------------
# def encrypt_file_64_128_ecb(plaintext, key):

#     # Encode the plaintext using ASCII encoding
#     plaintext_bytes = plaintext.encode('ascii')

#     # Convert each character to its binary representation
#     binary_list = [bin(byte)[2:].zfill(8) for byte in plaintext_bytes]

#     # Join the binary representations together
#     binary_string = ''.join(binary_list)

#     # Split the binary plaintext into blocks of 64 bits (8 bytes each)
#     plaintext_blocks = [binary_string[i:i+64] for i in range(0, len(binary_string), 64)]

#     # Split the binary key into 8 parts of 16 bits each
#     key_parts = [int(key[i:i+16], 2) for i in range(0, 128, 16)]
        
#     # Create the ctypes array for the key
#     key_array = (ctypes.c_uint16 * 8)(*key_parts)
    
#     # Create the ctypes array for the round keys
#     round_keys = (ctypes.c_uint16 * 16)()

#     # Key schedule
#     KeyExpansion64_128(key_array, round_keys) 
    
#     # Convert each block to 16-bit integers
#     ciphertext_blocks = []

#     for block in plaintext_blocks:

        # # Calculate the length of padding needed
        # padding_length = 64 - len(block)
        # # Pad the binary block with zeros
        # block += '0' * padding_length

#         # Convert the block to 16-bit parts
#         plaintext_parts = [int(block[i:i+16], 2) for i in range(0, 64, 16)]
        
#         # Create the ctypes array for the plaintext
#         plaintext_array = (ctypes.c_uint16 * 4)(*plaintext_parts)

#         # Create the ctypes array for the ciphertext
#         ciphertext = (ctypes.c_uint16 * 4)()

#         # Encrypt the plaintext block
#         Encryption64_128(plaintext_array, round_keys, ciphertext)

#         # Append the ciphertext block to the list
#         ciphertext_blocks.append(ciphertext)

#     return ciphertext_blocks

# def decrypt_file_64_128_ecb(ciphertext_blocks, key):
#     decrypted_plaintext = ""

#     # Split the binary key into 8 parts of 16 bits each
#     key_parts = [int(key[i:i+16], 2) for i in range(0, 128, 16)]
    
#     # Create the ctypes array for the key
#     key_array = (ctypes.c_uint16 * 8)(*key_parts)

#     # Create the ctypes array for the round keys
#     round_keys = (ctypes.c_uint16 * 16)()

#     # Key schedule
#     KeyExpansion64_128(key_array, round_keys)

#     # Decrypt each ciphertext block separately
#     for ciphertext_block in ciphertext_blocks:
#         # Create the ctypes array for the ciphertext
#         ciphertext = (ctypes.c_uint16 * 4)(*ciphertext_block)

#         # Create the ctypes array for the decrypted plaintext
#         decrypted_block = (ctypes.c_uint16 * 4)()

#         # Decrypt the ciphertext block
#         Decryption64_128(ciphertext, round_keys, decrypted_block)

#         # Convert the ctypes array to a Python list before printing
#         ciphertext_values = [value for value in decrypted_block]

#         # Print the ciphertext block
#         #print("Ciphertext:", [hex(value) for value in ciphertext_values])

#         # Convert the decrypted block to binary string
#         decrypted_binary_string = ''.join(format(value, '016b') for value in decrypted_block)

#         # Convert binary string to ASCII characters and append to decrypted plaintext
#         decrypted_plaintext += ''.join(chr(int(decrypted_binary_string[i:i+8], 2)) for i in range(0, len(decrypted_binary_string), 8))

#     return decrypted_plaintext

# -----------------------------------------------------------CHAM-64/128 (ECB) file input-----------------------------------------------------


def encrypt_file_64_128_ecb(file_path, key):
    with open(file_path, 'rb') as file:
        data = file.read()

    # Convert the binary data to a binary string
    binary_string = ''.join(format(byte, '08b') for byte in data)

    # Split the binary plaintext into blocks of 64 bits (8 bytes each)
    plaintext_blocks = [binary_string[i:i+64] for i in range(0, len(binary_string), 64)]
    
    # Split the binary key into 8 parts of 16 bits each
    key_parts = [int(key[i:i+16], 2) for i in range(0, 128, 16)]
        
    # Create the ctypes array for the key
    key_array = (ctypes.c_uint16 * 8)(*key_parts)
    
    # Create the ctypes array for the round keys
    round_keys = (ctypes.c_uint16 * 16)()

    # Key schedule
    KeyExpansion64_128(key_array, round_keys) 
    
    # Convert each block to 16-bit integers
    ciphertext_blocks = []

    for block in plaintext_blocks:

        # Calculate the length of padding needed
        padding_length = 64 - len(block)
        # Pad the binary block with zeros
        block += '0' * padding_length

        # Convert the block to 16-bit parts
        plaintext_parts = [int(block[i:i+16], 2) for i in range(0, 64, 16)]
        
        # Create the ctypes array for the plaintext
        plaintext_array = (ctypes.c_uint16 * 4)(*plaintext_parts)

        # Create the ctypes array for the ciphertext
        ciphertext = (ctypes.c_uint16 * 4)()

        # Encrypt the plaintext block
        Encryption64_128(plaintext_array, round_keys, ciphertext)

        # Append the ciphertext block to the list
        ciphertext_blocks.append(ciphertext)

    return ciphertext_blocks

def decrypt_file_64_128_ecb(ciphertext_blocks, key):
    decrypted_plaintext = b""
    
    # Split the binary key into 8 parts of 16 bits each
    key_parts = [int(key[i:i+16], 2) for i in range(0, 128, 16)]
    
    # Create the ctypes array for the key
    key_array = (ctypes.c_uint16 * 8)(*key_parts)

    # Create the ctypes array for the round keys
    round_keys = (ctypes.c_uint16 * 16)()

    # Key schedule
    KeyExpansion64_128(key_array, round_keys)

    # Decrypt each ciphertext block separately
    for ciphertext_block in ciphertext_blocks:
        # Create the ctypes array for the ciphertext
        ciphertext = (ctypes.c_uint16 * 4)(*ciphertext_block)

        # Create the ctypes array for the decrypted plaintext
        decrypted_block = (ctypes.c_uint16 * 4)()

        # Decrypt the ciphertext block
        Decryption64_128(ciphertext, round_keys, decrypted_block)

        # Convert the decrypted block to binary string
        decrypted_binary_string = ''.join(format(value, '016b') for value in decrypted_block)

        # Convert binary string to bytes and append to decrypted plaintext
        for i in range(0, len(decrypted_binary_string), 8):
            decrypted_plaintext += int(decrypted_binary_string[i:i+8], 2).to_bytes(1, byteorder='big')

    return decrypted_plaintext


# -----------------------------------------------------------CHAM-128/128-----------------------------------------------------
def encrypt_file_128_128_ecb(file_path, key):
    with open(file_path, 'rb') as file:
        data = file.read()

    # Convert the binary data to a binary string
    binary_string = ''.join(format(byte, '08b') for byte in data)

    # Split the binary plaintext into blocks of 128 bits (16 bytes each)
    plaintext_blocks = [binary_string[i:i+128] for i in range(0, len(binary_string), 128)]
    
    # Split the binary key into 8 parts of 16 bits each
    key_parts = [int(key[i:i+16], 2) for i in range(0, 128, 16)]
        
    # Create the ctypes array for the key
    key_array = (ctypes.c_uint32 * 8)(*key_parts)
    
    # Create the ctypes array for the round keys
    round_keys = (ctypes.c_uint32 * 40)()

    # Key schedule
    KeyExpansion128_128(key_array, round_keys) 
    
    # Convert each block to 32-bit integers
    ciphertext_blocks = []

    for block in plaintext_blocks:

        # Calculate the length of padding needed
        padding_length = 128 - len(block)
        # Pad the binary block with zeros
        block += '0' * padding_length

        # Convert the block to 32-bit parts
        plaintext_parts = [int(block[i:i+32], 2) for i in range(0, 128, 32)]
        
        # Create the ctypes array for the plaintext
        plaintext_array = (ctypes.c_uint32 * 4)(*plaintext_parts)

        # Create the ctypes array for the ciphertext
        ciphertext = (ctypes.c_uint32 * 4)()

        # Encrypt the plaintext block
        Encryption128_128(plaintext_array, round_keys, ciphertext)

        # Append the ciphertext block to the list
        ciphertext_blocks.append(ciphertext)

    return ciphertext_blocks

def decrypt_file_128_128_ecb(ciphertext_blocks, key):
    decrypted_plaintext = b""
    
    
    # Split the binary key into 8 parts of 16 bits each
    key_parts = [int(key[i:i+16], 2) for i in range(0, 128, 16)]
        
    # Create the ctypes array for the key
    key_array = (ctypes.c_uint32 * 8)(*key_parts)

    # Create the ctypes array for the round keys
    round_keys = (ctypes.c_uint32 * 40)()

    # Key schedule
    KeyExpansion128_128(key_array, round_keys)

    # Decrypt each ciphertext block separately
    for ciphertext_block in ciphertext_blocks:
        # Create the ctypes array for the ciphertext
        ciphertext = (ctypes.c_uint32 * 4)(*ciphertext_block)

        # Create the ctypes array for the decrypted plaintext
        decrypted_block = (ctypes.c_uint32 * 4)()

        # Decrypt the ciphertext block
        Decryption128_128(ciphertext, round_keys, decrypted_block)

        # Convert the decrypted block to binary string
        decrypted_binary_string = ''.join(format(value, '032b') for value in decrypted_block)

        # # Convert binary string to bytes and append to decrypted plaintext
        # decrypted_plaintext += int(decrypted_binary_string, 2).to_bytes(len(decrypted_binary_string) // 8, byteorder='big')

        for i in range(0, len(decrypted_binary_string), 8):
            decrypted_plaintext += int(decrypted_binary_string[i:i+8], 2).to_bytes(1, byteorder='big')

    return decrypted_plaintext


# def decrypt_file_128_128_ecb(ciphertext_blocks, key):
#     decrypted_plaintext = b""
    
#     # Split the binary key into 8 parts of 16 bits each
#     key_parts = [int(key[i:i+16], 2) for i in range(0, 128, 16)]
        
#     # Create the ctypes array for the key
#     key_array = (ctypes.c_uint32 * 8)(*key_parts)

#     # Create the ctypes array for the round keys
#     round_keys = (ctypes.c_uint32 * 40)()

#     # Key schedule
#     KeyExpansion128_128(key_array, round_keys)

#     # Decrypt each ciphertext block separately
#     for ciphertext_block in ciphertext_blocks:
#         # Create the ctypes array for the ciphertext
#         ciphertext = (ctypes.c_uint32 * 4)(*ciphertext_block)

#         # Create the ctypes array for the decrypted plaintext
#         decrypted_block = (ctypes.c_uint32 * 4)()

#         # Decrypt the ciphertext block
#         Decryption128_128(ciphertext, round_keys, decrypted_block)

#         # Convert the decrypted block to binary string
#         decrypted_binary_string = ''.join(format(value, '032b') for value in decrypted_block)

#         # Convert binary string to bytes and append to decrypted plaintext
#         for i in range(0, len(decrypted_binary_string), 8):
#             decrypted_plaintext += int(decrypted_binary_string[i:i+8], 2).to_bytes(1, byteorder='big')

#     return decrypted_plaintext

# -----------------------------------------------------------CHAM-128/256-----------------------------------------------------
        

def main():
    key = generate_random_key(128)

    # Initialize arrays
    # plaintext = "Hello World....! em Ipsum is simply dummy text of the printing and typesetting industry. "
    # ciphertext = encrypt_file_64_128_ecb(plaintext, key)
    # print("Ciphertext:", ciphertext)
    # decrypted_plaintext = decrypt_file_64_128_ecb(ciphertext, key)
    # print("decrypted plaintext:", decrypted_plaintext)

    # decrypt_file_64_128_ecb(ciphertext, key)
    input_file = "/Users/khannmohsin/VSCode Projects/Measurement_metrics_LWC/Files/Crypto_input/video/00_hermes_dag29.mp4"
    encrypted_file = "/Users/khannmohsin/VSCode Projects/Measurement_metrics_LWC/Files/Crypto_intermediate/encrypted_CHAM.enc"
    decrypted_file = "/Users/khannmohsin/VSCode Projects/Measurement_metrics_LWC/Files/Crypto_output/decrypted_image_CHAM.mp4"

    # Encrypt the input file
    ciphertext = encrypt_file_64_128_ecb(input_file, key)
    print("File encrypted successfully.")

    # Decrypt the encrypted file
    decrypted_text = decrypt_file_64_128_ecb(ciphertext, key)
    print(decrypted_text)
    print("File decrypted successfully.")

    # Write the decrypted text to a file
    with open(decrypted_file, 'wb') as file:
        file.write(decrypted_text)
# Ensure main() is called when the script is executed
if __name__ == "__main__":
    main()
