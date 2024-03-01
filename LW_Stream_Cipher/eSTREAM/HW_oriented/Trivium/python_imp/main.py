from  trivium import Trivium

def get_bytes_from_file(filename):
    return open(filename, "rb").read()

def _hex_to_bytes(s):
    return [_allbytes[s[i:i+2].upper()] for i in range(0, len(s), 2)]

def bits_to_hex(b):
    return "".join(["%02X" % sum([b[i + j] << j for j in range(8)]) for i in range(0, len(b), 8)])

def hex_to_bits(s):
    return [(b >> i) & 1 for b in _hex_to_bytes(s) for i in range(8)]

_allbytes = dict([("%02X" % i, i) for i in range(256)])
def get_next_stream_byte():
  rtn = 0
  for j in range(8):
    rtn+=int(next_key_bit()) << j;
  return rtn

k1="0F62B5085BAE0154A7FA"
i1="288FF65DC42B92F960C7"

print ("Key: "+k1)
print ("IV:  "+i1)

KEY = hex_to_bits(k1)[::-1]
IV = hex_to_bits(i1)[::-1]
trivium = Trivium(KEY, IV)

next_key_bit = trivium.keystream().__next__
    
b=get_bytes_from_file("1.txt")

print ("Writing to cipher file")
with open("cipher.txt", "wb") as binary_file:
  for mybyte in b:
    buffer=bytearray()
#    print (mybyte,get_next_stream_byte())
    newbyte = (mybyte ^ get_next_stream_byte()) & 0xFF
    buffer.append(newbyte)
    binary_file.write(buffer)

# Reset key stream
trivium = Trivium(KEY, IV)
next_key_bit = trivium.keystream().__next__


print ("Reading from cipher file")
b=get_bytes_from_file("cipher.txt")

with open("decipter.txt", "wb") as binary_file:
  for mybyte in b:
    buffer=bytearray()
#    print (mybyte,get_next_stream_byte())
    newbyte = (mybyte ^ get_next_stream_byte()) & 0xFF
    buffer.append(newbyte)
    binary_file.write(buffer)
