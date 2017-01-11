import socket
import struct

target_host = "localhost"
target_port = 2999

#create socket obj
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#connect the client
client.connect ( (target_host,target_port))

#recieve initial data
prompt = client.recv(4096)
#split by ' into list
data = prompt.split("'")
#grab the 2nd element, which is our target "random" value
value= data[1]
#send value packed as little endian unsigned int
client.send (struct.pack('<I',int(value))) #pack as little endian
#recieve data
response = client.recv(4096)

print response