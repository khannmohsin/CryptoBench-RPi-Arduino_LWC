import ctypes
import time 

# Define types
u8 = ctypes.c_uint8
u32 = ctypes.c_uint32

# Load the shared library
lib = ctypes.CDLL("trivium.so")

# Define the ECRYPT_ctx structure
class ECRYPT_ctx(ctypes.Structure):
    _fields_ = [("key", u8 * 16),
                ("s", u32 * 13),
                ("keylen", u32),
                ("ivlen", u32)]

# Define function prototypes
ECRYPT_init = lib.ECRYPT_init
ECRYPT_init.argtypes = []
ECRYPT_init.restype = None

ECRYPT_keysetup = lib.ECRYPT_keysetup
ECRYPT_keysetup.argtypes = [ctypes.POINTER(ECRYPT_ctx), ctypes.POINTER(u8), u32, u32]
ECRYPT_keysetup.restype = None

ECRYPT_ivsetup = lib.ECRYPT_ivsetup
ECRYPT_ivsetup.argtypes = [ctypes.POINTER(ECRYPT_ctx), ctypes.POINTER(u8)]
ECRYPT_ivsetup.restype = None

ECRYPT_process_bytes = lib.ECRYPT_process_bytes
ECRYPT_process_bytes.argtypes = [ctypes.c_int, ctypes.POINTER(ECRYPT_ctx), ctypes.POINTER(u8), ctypes.POINTER(u8), u32]
ECRYPT_process_bytes.restype = None

# Initialize the library
ECRYPT_init()

# Encryption function
def c_rabbit_encrypt_file(plaintext, key):
    ctx = ECRYPT_ctx()
    key = (u8 * 16)(*key)
    iv = (u8 * 10)(11, 12, 13, 14, 15, 16, 17, 18, 19, 20)  # Example IV
    ECRYPT_keysetup(ctypes.byref(ctx), key, 128, 80)
    ECRYPT_ivsetup(ctypes.byref(ctx), iv)

    ciphertext = bytearray(len(plaintext))
    ECRYPT_process_bytes(0, ctypes.byref(ctx), plaintext, ciphertext, len(plaintext))

    for i in range(len(plaintext)):
        ciphertext[i] = plaintext[i] ^ ciphertext[i]    

    return ciphertext

# Decryption function
def c_trivium_decrypt_file(ciphertext, key):
    len_ciphertext = len(ciphertext)
    ctx = ECRYPT_ctx()
    key = (u8 * 16)(*key)
    iv = (u8 * 10)(11, 12, 13, 14, 15, 16, 17, 18, 19, 20)  # Example IV
    ECRYPT_keysetup(ctypes.byref(ctx), key, 128, 80)
    ECRYPT_ivsetup(ctypes.byref(ctx), iv)

    plaintext = bytearray(len(ciphertext))

    ECRYPT_process_bytes(0, ctypes.byref(ctx), ciphertext, plaintext, len(ciphertext))

    for i in range(len(ciphertext)):

        plaintext[i] = ciphertext[i] ^ plaintext[i]

    return plaintext

