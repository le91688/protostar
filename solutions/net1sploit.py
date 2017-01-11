import socket
import struct

target_host = "localhost"
target_port = 2998


#create socket obj
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#connect the client
client.connect ( (target_host,target_port))

#get fub variable
wanted = client.recv(4096)
#unpack fub as an unsigned int
unpacked = struct.unpack('=I',wanted)

print "sending ", str(unpacked[0])
#cast the unsigned int as string and send
client.send (str(unpacked[0])+'\x00' )
#add null byte just in case

#get response
response = client.recv(4096)
print response
