import ctypes
import os


# Define the necessary types for the function arguments
class SimSpk_Cipher(ctypes.Structure):
    _fields_ = [
        ('block_size', ctypes.c_uint8),
        ('key_size', ctypes.c_uint8),
        ('round_limit', ctypes.c_uint8),
        ('cipher_cfg', ctypes.c_int),
        ('z_seq', ctypes.c_int),
        ('key_schedule', ctypes.c_uint64 * 272)  # Adjust the size according to your needs
    ]
    
# Load the SIMON library
simon_lib = ctypes.CDLL("simon.so")

# Define the function prototypes for the C functions
simon_init_func = simon_lib.Simon_Init
simon_init_func.argtypes = [
    ctypes.POINTER(SimSpk_Cipher),  # SimSpk_Cipher *
    ctypes.c_int,  # cipher_cfg
    ctypes.c_int,  # c_mode
    ctypes.c_void_p,  # key
    ctypes.POINTER(ctypes.c_ubyte),  # iv
    ctypes.POINTER(ctypes.c_ubyte)  # counter
]
simon_init_func.restype = ctypes.c_uint8

# Define the SIMON encryption function
Simon_Encrypt = simon_lib.Simon_Encrypt
Simon_Encrypt.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_void_p]
Simon_Encrypt.restype = ctypes.c_uint8

# Define the SIMON decryption function
Simon_Decrypt = simon_lib.Simon_Decrypt
Simon_Decrypt.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_void_p]
Simon_Decrypt.restype = ctypes.c_uint8

def simon_init(cipher_object, cipher_cfg, c_mode, key, iv, counter):
    return simon_init_func(ctypes.byref(cipher_object), cipher_cfg, c_mode, key, iv, counter)

def simon_encrypt(cipher_object, plaintext, ciphertext):
    return Simon_Encrypt(ctypes.byref(cipher_object), plaintext, ciphertext)

def simon_decrypt(cipher_object, ciphertext, plaintext):
    return Simon_Decrypt(ctypes.byref(cipher_object), ciphertext, plaintext)

# Define the SIMON cipher configurations
class CipherConfig:
    cfg_64_32 = 0
    cfg_128_64 = 1
    # Define other configurations as needed

class Mode:
    default_mode = 0
    # Define other modes as needed

def test_simon_init():
    # Define the arguments
    cipher_object = SimSpk_Cipher()
    
    # Choose the cipher configuration
    cipher_cfg = CipherConfig.cfg_64_32  # Example: 64-bit block, 32-bit key
    c_mode = Mode.default_mode  # Example: ECB mode
    
    # Define the key, IV, and counter
    key = b'\x01\x23\x45\x67\x89\xab\xcd\xef'  # Example key, adjust as needed
    iv = None  # Example IV, adjust as needed
    counter = None  # Example counter, adjust as needed

    # Call the function
    result = simon_init(cipher_object, cipher_cfg, c_mode, key, iv, counter)

    # Check the result
    if result == 0:
        print("Simon initialization successful.")
        print("Block size:", cipher_object.block_size)
        print("Key size:", cipher_object.key_size)
        print("Round limit:", cipher_object.round_limit)
        print("Cipher configuration:", cipher_object.cipher_cfg)
        print("Z sequence:", cipher_object.z_seq)
    else:
        print("Simon initialization failed.")

# Test the function
# test_simon_init()

def test_simon_encrypt():
    # Define the arguments
    cipher_object = SimSpk_Cipher()
    cipher_cfg = CipherConfig.cfg_64_32 
    key = b'\x01\x23\x45\x67\x89\xab\xcd\xef'  # Example key, adjust as needed
    iv = None  # Example IV, adjust as needed
    plaintext = b'Hello, SIMON!'  # Example plaintext, adjust as needed
    ciphertext = (ctypes.c_ubyte * 8)()  # Allocate space for ciphertext (8 bytes for 64-bit block size)
    counter = None  # Example counter, adjust as needed
    c_mode = 0  # Example mode, adjust as needed

    plaintext_ptr = (ctypes.c_ubyte * len(plaintext))(*plaintext)

    # Initialize the SIMON cipher
    result = simon_init(cipher_object, cipher_cfg, c_mode, key, iv, counter)

    # Check if initialization was successful
    if result == 0:
        print("Simon initialization successful.")

        # Encrypt the plaintext
        encrypt_result = simon_encrypt(cipher_object, plaintext_ptr, ciphertext)

        # Check if encryption was successful
        if encrypt_result == 0:
            print("Encryption successful.")
            print("Plaintext:", plaintext)
            print("Ciphertext:", bytes(ciphertext))  # Convert ciphertext to bytes for display
        else:
            print("Encryption failed.")
    else:
        print("Simon initialization failed.")


def test_simon_decrypt():
    # Define the arguments
    cipher_object = SimSpk_Cipher()
    cipher_cfg = CipherConfig.cfg_64_32
    key = b'\x01\x23\x45\x67\x89\xab\xcd\xef'  # Example key, adjust as needed
    iv = None  # Example IV, adjust as needed
    plaintext = b'Hello, SIMON!'  # Example plaintext, adjust as needed
    ciphertext = (ctypes.c_ubyte * 8)()  # Allocate space for ciphertext (8 bytes for 64-bit block size)
    decrypted_plaintext = (ctypes.c_ubyte * len(plaintext))()  # Allocate space for decrypted plaintext
    counter = None  # Example counter, adjust as needed
    c_mode = 0  # Example mode, adjust as needed

    plaintext_ptr = (ctypes.c_ubyte * len(plaintext))(*plaintext)

    # Initialize the SIMON cipher
    result = simon_init(cipher_object, cipher_cfg, c_mode, key, iv, counter)

    # Check if initialization was successful
    if result == 0:
        print("Simon initialization successful.")

        # Encrypt the plaintext
        encrypt_result = simon_encrypt(cipher_object, plaintext_ptr, ciphertext)

        # Check if encryption was successful
        if encrypt_result == 0:
            print("Encryption successful.")
            print("Plaintext:", plaintext)
            print("Ciphertext:", bytes(ciphertext))  # Convert ciphertext to bytes for display

            # Decrypt the ciphertext
            decrypt_result = simon_decrypt(cipher_object, ciphertext, decrypted_plaintext)

            # Check if decryption was successful
            if decrypt_result == 0:
                print("Decryption successful.")
                print("Decrypted plaintext:", bytes(decrypted_plaintext))  # Convert decrypted plaintext to bytes for display
            else:
                print("Decryption failed.")
        else:
            print("Encryption failed.")
    else:
        print("Simon initialization failed.")

# Test the SIMON decryption function
test_simon_decrypt()