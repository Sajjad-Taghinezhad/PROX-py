#!/usr/bin/python3

import socket
import struct
import zlib
import os 
import math
import time
from colorama import Fore, Back, Style

# define socket for send and receive data
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

# specific ID for custom protocol : random 
protocol_id = 234

# ----Specific source and destination---------------------
ip_address = "192.168.0.13"
dest_ip_address = "192.168.0.17"
ip_address = "172.16.0.1"
dest_ip_address = "172.16.0.128"
# --------------------------------------------------------

# define and calculate MTU, fragmentation, timeout, and max attempts(reconnecting)
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

# IP header class : contain all IP header data : version, length, .....
class IP : 
    def __init__(self, version, length, ttl, protocol, source_address, destination_address ):
        self.version = version
        self.length = length
        self.ttl = ttl
        self.protocol = protocol
        self.source_address = source_address
        self.destination_address = destination_address

# PROX protocol class : contain PROX header and body(data)
class PROX : 
    def __init__(self, id, flags, length, checksum, data):
        self.id = id
        self.flag = flags
        self.total_length = length
        self.checksum = checksum
        self.data = data

# function that give incoming packet and parse it as a IP packet class
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

# function that give PROX packet data and parse it as a PROX object
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
    
# Create a raw socket object and send packet to destination
def sendto(packet, dest_ip_address):
    #! in MacOS don't need to create an IP header but in Linux, should create  
    # Set the IP header fields
    # -----IP header creation-----------------
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
    # -----------------------------------------

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
#! need implement signature check, error handling, 
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


# ======Packet=Functions=============================================================================

# send ack packet to destination
def ack():
    data = b""
    flags = 85
    length = 8 + len(data)
    PROX_header = struct.pack("!BBH", protocol_id, flags, length)
    PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + data).to_bytes(4, 'big'))
    PROX_packet = PROX_header + data
    sendto(PROX_packet, packet.IP_packet.source_address)

# send rst-chunk packet to destination
def rst_chunk():
    data = b""
    flags = 187
    length = 8 + len(data)
    PROX_header = struct.pack("!BBH", protocol_id, flags, length)
    PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + data).to_bytes(4, 'big'))
    PROX_packet = PROX_header + data
    sendto(PROX_packet, packet.IP_packet.source_address)

# send req-ack packet to destination
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

# send data packet to destination
def send_data(data: bytes,destination):
    flags = 238
    length = 8 + len(data)
    PROX_header = struct.pack("!BBH", protocol_id, flags, length)
    PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + data).to_bytes(4, 'big'))
    PROX_packet = PROX_header + data
    sendto(PROX_packet, destination)

#=================================================================================================================================



# ========Start sending file=============================================================-

# specific file to transfer
#! implement dynamic specific : argument
file_path = "sample2.data"
fileName = "sample2.data"
fileSize = os.path.getsize(file_path) # get file size 

# Calculate the number of expected packets
expectedNumberOfPacket = math.ceil(fileSize / fragmentOffset)

# Calculate the ack offset
ackOffset = math.ceil(expectedNumberOfPacket / mtu)



# convert filename to 30 bytes
packed_fileName =  fileName.encode('utf-8')[:30].ljust(30, b'\x00') 
# pack info to bytes
data = struct.pack("!QHQQ", fileSize, fragmentOffset, expectedNumberOfPacket, ackOffset)
# concat name and info
data = packed_fileName + data 
# start flag
flags = 255 
# calculate length of packet : header length + data length
length = 8 + len(data)
# pack PROX header data
PROX_header = struct.pack("!BBH", protocol_id, flags, length) 
# calculate checksum and pack again
PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + data).to_bytes(4, 'big'))
# concat PROX header and data : byte
PROX_packet = PROX_header + data




# send data and wait for ack packet
# implement timeout and reattempt
for attempt in range(max_attempts):
    try:
        sendto(PROX_packet, dest_ip_address)
        print(Fore.BLUE+"establishing connection ..."+Fore.RESET)
        sock.settimeout(timeout)
        packet = pack()
        if packet.packet_type == "ack" : 
            # print("ack received")
            break
        else: 
            print("wrong packet received. ack packet but received {}. exit".format(Fore.RED+packet.packet_type+Fore.RESET))
            exit(1)
    except socket.timeout:
        print(f"{Fore.CYAN}Attempt {attempt+1}/{max_attempts} timed out, retrying...{Fore.RESET}")
        continue    

# in here file info was sent and wait for receiver to accept connection =============================
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

# open specific file for sending 
file = open(file_path, 'rb')

# specific and calculate sending rate
sending_rate = 5000
delay = 1 / sending_rate

# specific some variable for control sending
buffer = b""
data = b''
total = 0
ack_count = 0

while True:
    # read file chunk by chunk : chunk == fragmentation size 
    chunk = file.read(fragmentOffset) 
    if not chunk:
        break # check for end of file 
    
    # implement buffer to save the cycle of sending packets
    buffer = buffer + chunk 

    send_data(chunk,dest_ip_address) # send file data to receiver 
    ack_count = ack_count + 1 # count for ack sent packets
    total_sent = total + 1 # count for total sent packet
    time.sleep(delay) # set a delay for protect packet lost on wire
    
    if ack_count == ackOffset:
        try:  # check for ack offset 
            req_ack(dest_ip_address) # send packet with req-ack flag to get number of successful arrived packets from receiver
            ack_data = pack()
            if ack_data.packet_type == 'ack-data': # listen for input packet and check for type of packet flag 
                if struct.unpack("!Q",ack_data.prox.data)[0] == total: # compare number of sent packets and arrived 
                    # print("compare success")
                    buffer = b""
                else: 
                    print(Fore.RED+"error detected in packet transferring. exit ")
                    exit(1)
        except socket.timeout:
            #!! handle timeout of ack-data





        

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