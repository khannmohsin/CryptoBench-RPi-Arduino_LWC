import ctypes

# Load the shared object files
libsimeck = ctypes.CDLL('/Users/khannmohsin/VSCode Projects/Measurement_metrics_LWC/LW_Block_Cipher/ARX/Simeck/c_imp/simeck_main.so')

# Define the function signatures for the encryption functions
simeck_32_64 = libsimeck.simeck_32_64
simeck_48_96 = libsimeck.simeck_48_96
simeck_64_128 = libsimeck.simeck_64_128

# Define argument types and return types for the functions
simeck_32_64.argtypes = [
    ctypes.POINTER(ctypes.c_uint16),  # key64
    ctypes.POINTER(ctypes.c_uint16),  # text32
    ctypes.POINTER(ctypes.c_uint16)   # text32_out
]
simeck_32_64.restype = None

simeck_48_96.argtypes = [
    ctypes.POINTER(ctypes.c_uint32),  # key96
    ctypes.POINTER(ctypes.c_uint32),  # text48
    ctypes.POINTER(ctypes.c_uint32)   # text48_out
]
simeck_48_96.restype = None

simeck_64_128.argtypes = [
    ctypes.POINTER(ctypes.c_uint32),  # key128
    ctypes.POINTER(ctypes.c_uint32),  # text64
    ctypes.POINTER(ctypes.c_uint32)   # text64_out
]
simeck_64_128.restype = None

if __name__ == "__main__":
    # Define text and keys
    text32 = (ctypes.c_uint16 * 2)(0x6877, 0x6565)
    key64 = (ctypes.c_uint16 * 4)(0x0100, 0x0908, 0x1110, 0x1918)

    text48 = (ctypes.c_uint32 * 2)(0x20646e, 0x726963)
    key96 = (ctypes.c_uint32 * 4)(0x020100, 0x0a0908, 0x121110, 0x1a1918)

    text64 = (ctypes.c_uint32 * 2)(0x20646e75, 0x656b696c)
    key128 = (ctypes.c_uint32 * 4)(0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918)

    # Encrypt
    simeck_32_64(key64, text32, text32)
    simeck_48_96(key96, text48, text48)
    simeck_64_128(key128, text64, text64)

    

    #Decrypt
    simeck_32_64(key64, text32, text32)
    simeck_48_96(key96, text48, text48)
    simeck_64_128(key128, text64, text64)

    # Print results
    print("Simeck32/64 %04x %04x" % (text32[1], text32[0]))
    print("Simeck48/96 %06x %06x" % (text48[1], text48[0]))
    print("Simeck64/128 %08x %08x" % (text64[1], text64[0]))
