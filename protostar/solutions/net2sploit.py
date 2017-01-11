import socket
import struct
from ctypes import *
target_host = "localhost"
target_port = 2997

#create socket obj
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#connect the client
client.connect ( (target_host,target_port))
#get quad elements concatted
var = client.recv(4096)

#split by 4
n=4
newlist = [var[i:i+n] for i in range(0, len(var), n)]

#unpack as an int
intlist = map(lambda x: struct.unpack('=I',x),newlist) 
#grab only first element of tuple
intlist = map(lambda x:x[0],intlist) 

#convert to unsigned int
summed = c_uint(sum(intlist))

#pack as int
packed = struct.pack('=I',summed.value)

#send data
client.send (packed) 

#get response
response = client.recv(4096)
print response