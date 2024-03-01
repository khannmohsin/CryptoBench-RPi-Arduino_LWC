# https://asecuritysite.com/encryption/xtea
import struct
import sys

message='ABCDEFG'
key='0123456789012345'

if (len(sys.argv)>1):
        message=str(sys.argv[1])
if (len(sys.argv)>2):
        key=str(sys.argv[2])

class XTEA():
    
    def __init__(self):
        self.DELTA = 0x9E3779B9
        self.MASK = 0xffffffff

    def strdecode(self, key, msg):
        z = msg.decode('hex')
        return self.xtea_decrypt(key, z, 32)
        
    def xtea_encrypt(self, key,block,n=32):
        v0,v1 = struct.unpack("2I",block)
        k = struct.unpack("4I",key)

        sum = 0
        for round in range(n):
            v0 = (v0 + (((v1<<4 ^ v1>>5) + v1) ^ (sum + k[sum & 3]))) & self.MASK
            sum = (sum + self.DELTA) & self.MASK
            v1 = (v1 + (((v0<<4 ^ v0>>5) + v0) ^ (sum + k[sum>>11 & 3]))) & self.MASK
        return struct.pack("2I",v0,v1)

    def xtea_decrypt(self, key,block,n=32):
       
        v0,v1 = struct.unpack("2I",block)

        k = struct.unpack("4I",key)
       
        sum = (self.DELTA * n) & self.MASK
        for round in range(n):
            v1 = (v1 - (((v0<<4 ^ v0>>5) + v0) ^ (sum + k[sum>>11 & 3]))) & self.MASK
            sum = (sum - self.DELTA) & self.MASK
            v0 = (v0 - (((v1<<4 ^ v1>>5) + v1) ^ (sum + k[sum & 3]))) & self.MASK
        return struct.pack("2I",v0,v1)


# key = key.rjust(32, '0')      # Key is 32 hex chars - 128 bits 
# message = message.rjust(8, '0')  # Block size is 64 bytes
# print('Message:\t',message)
# print('Key:\t\t',key.encode())    
# x = XTEA()
# z = x.xtea_encrypt(bytes.fromhex(key),message.encode())
# z= z.hex()
# print('Cipher:\t\t',z ) 
# z = bytes.fromhex(z)
# x = x.xtea_decrypt(bytes.fromhex(key),z)
# print('Decrypt:\t',x.decode())