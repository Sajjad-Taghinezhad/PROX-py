#!/usr/bin/python3

import socket
import struct
import zlib
import os 
import math
import time
from colorama import Fore, Back, Style

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
protocol_id = 234
ip_address = "192.168.0.13"
dest_ip_address = "192.168.0.17"
ip_address = "172.16.0.1"
dest_ip_address = "172.16.0.128"
mtu = 1500 + 14 # mtu + 14 bytes of Ethernet header
fragmentOffset = mtu - 20 - 8 - 14 # MTU - IP header length - PROX header length - Ethernet II header
max_attempts=1000
timeout=3


#Packet class contain: raw, address, IP_packet, prox, protocol, packet_type 
class PACKET : 
    def __init__(self, raw, address, IP_packet, prox, protocol,packet_type):
        self.raw = raw
        self.address = address
        self.IP_packet = IP_packet
        self.prox = prox
        self.protocol = protocol
        self.packet_type = packet_type

# IP header class
class IP : 
    def __init__(self, version, length, ttl, protocol, source_address, destination_address ):
        self.version = version
        self.length = length
        self.ttl = ttl
        self.protocol = protocol
        self.source_address = source_address
        self.destination_address = destination_address

# PROX protocol class
class PROX : 
    def __init__(self, id, flags, length, checksum, data):
        self.id = id
        self.flag = flags
        self.total_length = length
        self.checksum = checksum
        self.data = data

# function that give incoming unknown packet and return IP packet class
def IP_parse(ip_header: bytes) -> IP: 
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        IP_packet = IP(
        iph[0] >> 4,
        len(ip_header),
        iph[5],
        iph[6],
        socket.inet_ntoa(iph[8]),
        socket.inet_ntoa(iph[9])
        )
        return IP_packet

# function that give PROX packet data and return and object that have the packet details 
def PROX_parse(PROX_data: bytes) -> PROX: 
        PROX_packet = struct.unpack('!BBH4s', PROX_data[:8])
        data = PROX_data[8:]
        PROX_packet = PROX(
        PROX_packet[0],
        PROX_packet[1],
        PROX_packet[2],
        PROX_packet[3],
        data
        )
        return PROX_packet
    
# Create a raw socket object and send IP packet to destination
def sendto(packet, dest_ip_address):
        # Set the IP header fields
    version = 4
    ihl = 5
    tos = 0
    tot_len = 120  # IP header + UDP header
    id = 54321
    frag_off = 0
    ttl = 255
    protocol = 255
    check = 0
    saddr = socket.inet_aton(ip_address)
    daddr = socket.inet_aton(dest_ip_address)

    # Build the IP header
    # ip_header = struct.pack('!BBHHHBBH4s4s', (version << 4) + ihl, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
    # packet = ip_header + packet
    sock.sendto(packet, (socket.inet_ntoa(daddr), 5000)) 


# check IP packet data to detect the protocol : only support PROX detection
def packet_protocol(packet):
    if packet[20:21] == struct.pack("!B",234):
        return "PROX"
    return "unknown"

# get full IP packet data and check signature for PROX protocol packet : based on Adler-32
def check_signature(packet) -> bool:
    PROX_header = packet[:4]
    data = packet[8:]
    if packet[4:8] == zlib.adler32(PROX_header+data).to_bytes(4, 'big'): 
        return True
    return False

# Listen for packet and analyze
def pack() :
    while True:
        packet, address = sock.recvfrom(65535)
        protocol = packet_protocol(packet)
        IP_packet = IP_parse(packet[:20]) # parse IP packet | select first 20 bytes that belong to IP packet
        if IP_packet.destination_address != ip_address or IP_packet.protocol != 255:
            continue
        prox = PROX_parse(packet[20:])

        if prox.flag == 255 :
            packet_type = "start"
        elif prox.flag == 85 : 
            packet_type = "ack"
        elif prox.flag == 240 : 
            packet_type = "data-ok"
        elif prox.flag == 204 : 
            packet_type = "accept"
        elif prox.flag == 0 : 
            packet_type = "end"
        elif prox.flag == 146 : 
            packet_type = "err"
        elif prox.flag == 238 : 
            packet_type = "data"
        elif prox.flag == 187 : 
            packet_type = "rst-chunk"
        elif prox.flag == 180 : 
            packet_type = "ack-data"
        elif prox.flag == 150 : 
            packet_type = "req-ack"
        else : 
            packet_type = "unknown"

        return PACKET(packet, address, IP_packet, prox, protocol,packet_type)


# ===================================================================================

# send ack packet to destination
def ack():
    data = b""
    flags = 85
    length = 8 + len(data)
    PROX_header = struct.pack("!BBH", protocol_id, flags, length)
    PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + data).to_bytes(4, 'big'))
    PROX_packet = PROX_header + data
    sendto(PROX_packet, packet.IP_packet.source_address)

# send ack packet to destination
def rst_chunk():
    data = b""
    flags = 187
    length = 8 + len(data)
    PROX_header = struct.pack("!BBH", protocol_id, flags, length)
    PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + data).to_bytes(4, 'big'))
    PROX_packet = PROX_header + data
    sendto(PROX_packet, packet.IP_packet.source_address)

# send get_ack packet to destination
def req_ack(destination):
    data = b""
    flags = 150
    length = 8 + len(data)
    PROX_header = struct.pack("!BBH", protocol_id, flags, length)
    PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + data).to_bytes(4, 'big'))
    PROX_packet = PROX_header + data
    sendto(PROX_packet, destination)

# send accept packet to destination
def accept():
    data = b""
    flags = 204
    length = 8 + len(data)
    PROX_header = struct.pack("!BBH", protocol_id, flags, length)
    PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + data).to_bytes(4, 'big'))
    PROX_packet = PROX_header + data
    sendto(PROX_packet, packet.IP_packet.source_address)

# send end packet to destination
def end(destination):
    data = b""
    flags = 0
    length = 8 + len(data)
    PROX_header = struct.pack("!BBH", protocol_id, flags, length)
    PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + data).to_bytes(4, 'big'))
    PROX_packet = PROX_header + data
    sendto(PROX_packet, destination)

# send err packet to destination
def err(destination):
    data = b""
    flags = 146
    length = 8 + len(data)
    PROX_header = struct.pack("!BBH", protocol_id, flags, length)
    PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + data).to_bytes(4, 'big'))
    PROX_packet = PROX_header + data
    sendto(PROX_packet, destination)

# send packet with data flag and data in byte to destination
def send_data(data: bytes,destination):
    flags = 238
    length = 8 + len(data)
    PROX_header = struct.pack("!BBH", protocol_id, flags, length)
    PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + data).to_bytes(4, 'big'))
    PROX_packet = PROX_header + data
    sendto(PROX_packet, destination)



# ---------------------------------Init---------------------------------


file_path = "sample2.data"
fileName = "sample2.data"
fileSize = os.path.getsize(file_path)
expectedNumberOfPacket = math.ceil(fileSize / fragmentOffset)
ackOffset = math.ceil(expectedNumberOfPacket / mtu)



# get 6 argument
packed_fileName =  fileName.encode('utf-8')[:30].ljust(30, b'\x00')
data = struct.pack("!QHQQ", fileSize, fragmentOffset, expectedNumberOfPacket, ackOffset)
data = packed_fileName + data
flags = 255 # start 
length = 8 + len(data)
PROX_header = struct.pack("!BBH", protocol_id, flags, length)
PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + data).to_bytes(4, 'big'))
PROX_packet = PROX_header + data

# req_ack(dest_ip_address)
# packet = pack()
# print('Received {} bytes from {} {},{}'.format(len(packet.raw), packet.address,packet.protocol,packet.packet_type))
# packet_no = struct.unpack("!Q",packet.prox.data)[0]
# print(packet_no)


# send data and wait for ack packet
for attempt in range(max_attempts):
    try:
        sendto(PROX_packet, dest_ip_address)
        print("establishing connection ...")
        sock.settimeout(timeout)
        packet = pack()
        if packet.packet_type == "ack" : 
            print("ack received")
            break
        else: 
            print("wrong packet received. expected ack packet. exit")
            exit(1)
    except socket.timeout:
        print(f"Attempt {attempt+1}/{max_attempts} timed out, retrying...")
        continue    

# wait for accept packet 
for attempt in range(max_attempts):
    try:
        print("waiting for accept packet to start sending data")
        sock.settimeout(timeout)
        packet = pack()
        if packet.packet_type == "accept" : 
            print("accept received")
            break
        elif packet.packet_type == "end" :
            print("receiver does not accept file. sending ack and exit")
            ack()
            exit(1)
        else: 
            print("wrong packet received. expected accept packet. exit")
            exit(1)
    except socket.timeout:
        print(f"Attempt {attempt+1}/{max_attempts} timed out, retrying...")
        continue  


file = open(file_path, 'rb')

sending_rate = 5000
delay = 1 / sending_rate
buffer = b""
data = b''
total = 0
ack_count = 0

while True:
    chunk = file.read(fragmentOffset) # read file chunk by chunk 
    if not chunk:
        break # check for end of file 

    buffer = buffer + chunk # implement buffer to save the cycle of sending packets

    send_data(chunk,dest_ip_address) # send file data to receiver 
    ack_count = ack_count + 1 # count for ack sent packets
    total_sent = total + 1 # count for total sent packet
    time.sleep(delay) # set a delay for protect packet lost on wire
    if ack_count == ackOffset:  # check for ack offset 
        req_ack(dest_ip_address) # send packet with req-ack flag to get number of successful arrived packets from receiver
        ack_data = pack
        if ack_data.packet_type == 'ack-data': # listen for input packet and check for type of packet flag 
            if struct.unpack("!Q",ack_data.prox.data)[0] == total: # compare packet send and arrived 
                print("compare success") #!debug
                buffer = b""




        

    # if g == ackOffset: 
    #     # print("{} / {}".format(g,ackOffset))
    #     req_ack(dest_ip_address)
    #     try:
    #         packet = pack()
    #         if packet.packet_type == "ack-data": 
    #             packet_no = struct.unpack("!Q",packet.prox.data)[0]
    #             if packet_no == total:
    #                 g = 0
    #                 print("{} / {}". format(packet_no,total))
    #                 continue
    #             else:
    #                 print("packet count not matched!\ntrying to restore..")
                    
    #     except socket.timeout:
    #         print(f"error detected \n try resume....")
    #         continue    
# req_ack(dest_ip_address)
# packet = pack()
# if packet.packet_type == "ack-data":
#     packet_no = struct.unpack("!Q",packet.prox.data)[0]
#     if packet_no == total: 
#         print("done")




    
end(dest_ip_address)
print("end")

print("{} packet sent".format(total))









            # print(total)
            # for attempt in range(3):
            #     try:
            #         req_ack(dest_ip_address)
            #         print("get-ack sent")
            #         sock.settimeout(1)
            #         packet = pack()
            #         if packet.packet_type == "ack-data" : 
            #             packet_no = struct.unpack("!Q",packet.prox.data)
            #             print(packet_no)
            #     except socket.timeout:
            #         print(f"Attempt {attempt+1}/{max_attempts} timed out, retrying...")
            #         continue  

            # req_ack(dest_ip_address)
            # packet = pack()
            # if packet.packet_type == "ack" : 
            #     continue




            # 4601078adf964b1b8547f4e2b9c6ed0c