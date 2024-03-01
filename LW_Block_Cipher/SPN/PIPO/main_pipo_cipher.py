import ctypes
import os

# Load the C library
lib_crypto_pipo = ctypes.CDLL(os.path.abspath("/Users/khannmohsin/VSCode Projects/Measurement_metrics_LWC/LW_Block_Cipher/SPN/PIPO/c_imp/PIPO_reference_bitslice.so")) 

# Define the function prototypes
PIPO_ROUND_KEY_GEN = lib_crypto_pipo.ROUND_KEY_GEN

PIPO_ENC = lib_crypto_pipo.ENC
PIPO_ENC.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
PIPO_ENC.restype = None

PIPO_DEC = lib_crypto_pipo.DEC
PIPO_DEC.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
PIPO_DEC.restype = None




# # Define types
# u32 = ctypes.c_uint32
# u8 = ctypes.c_uint8 * 4

# # Set up function prototypes
# lib.ENC.argtypes = (ctypes.POINTER(u32), ctypes.POINTER(u32), ctypes.POINTER(u32))
# lib.DEC.argtypes = (ctypes.POINTER(u32), ctypes.POINTER(u32), ctypes.POINTER(u32))
# lib.ROUND_KEY_GEN.restype = None

# # Define the key schedule function
# def key_schedule(key):
#     # Convert the key to a list of 32-bit integers
#     key = [int(key[i:i+32], 2) for i in range(0, len(key), 32)]
#     key = (u32 * 4)(*key)
    
#     # Generate the round keys
#     round_keys = (u32 * 32)()
#     lib.ROUND_KEY_GEN(key, round_keys)
    
#     # Convert the round keys to a list of 32-bit integers
#     round_keys = [round_keys[i] for i in range(32)]
#     round_keys = [f"{round_keys[i]:032b}" for i in range(32)]
    
#     return round_keys

# # Define the encryption function
# def encrypt(plaintext, key):
#     # Convert the plaintext to a list of 32-bit integers
#     plaintext = [int(plaintext[i:i+32], 2) for i in range(0, len(plaintext), 32)]
#     plaintext = (u32 * 4)(*plaintext)
    
#     # Convert the round keys to a list of 32-bit integers
#     round_keys = key_schedule(key)
#     round_keys = [int(round_keys[i], 2) for i in range(32)]
#     round_keys = (u32 * 32)(*round_keys)
    
#     # Encrypt the plaintext
#     ciphertext = (u32 * 4)()
#     lib.ENC(plaintext, round_keys, ciphertext)
    
#     # Convert the ciphertext to a list of 32-bit integers
#     ciphertext = [ciphertext[i] for i in range(4)]
#     ciphertext = [f"{ciphertext[i]:032b}" for i in range(4)]
    
#     return ''.join(ciphertext)

# # Define the decryption function

# def decrypt(ciphertext, key):
#     # Convert the ciphertext to a list of 32-bit integers
#     ciphertext = [int(ciphertext[i:i+32], 2) for i in range(0, len(ciphertext), 32)]
#     ciphertext = (u32 * 4)(*ciphertext)
    
#     # Convert the round keys to a list of 32-bit integers
#     round_keys = key_schedule(key)
#     round_keys = [int(round_keys[i], 2) for i in range(32)]
#     round_keys = (u32 * 32)(*round_keys)
    
#     # Decrypt the ciphertext
#     plaintext = (u32 * 4)()
#     lib.DEC(ciphertext, round_keys, plaintext)
    
#     # Convert the plaintext to a list of 32-bit integers
#     plaintext = [plaintext[i] for i in range(4)]
#     plaintext = [f"{plaintext[i]:032b}" for i in range(4)]
    
#     return ''.join(plaintext)  


