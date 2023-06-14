import socket
import struct
import zlib
import psutil
from colorama import Fore, Back, Style
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
protocol_id = 234
ip_address = "192.168.0.13"
dest_ip_address = "192.168.0.17"
ip_address = "172.16.0.129"
dest_ip_address = "172.16.0.1"
mtu = 1500
fragmentOffset = mtu - 20 - 8 - 14 # MTU - IP header length - PROX header length
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


# PROX protocol class
class PROX : 
    def __init__(self, id, flags, length, checksum, data):
        self.id = id
        self.flag = flags
        self.total_length = length
        self.checksum = checksum
        self.data = data

# IP header class
class IP : 
    def __init__(self, version, length, ttl, protocol, source_address, destination_address ):
        self.version = version
        self.length = length
        self.ttl = ttl
        self.protocol = protocol
        self.source_address = source_address
        self.destination_address = destination_address

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
    ip_header = struct.pack('!BBHHHBBH4s4s', (version << 4) + ihl, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
    packet = ip_header + packet
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
        if check_signature(packet):
            print("fail signature")
            exit(1)
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





# send ack packet to destination
def ack():
    data = b""
    flags = 85
    length = 8 + len(data)
    PROX_header = struct.pack("!BBH", protocol_id, flags, length)
    PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + data).to_bytes(4, 'big'))
    PROX_packet = PROX_header + data
    sendto(PROX_packet, dest_ip_address)

# send ack packet to destination
def ack_data(number):
    flags = 180
    number = struct.pack("!Q",number)
    length = 8 + len(number) 
    PROX_header = struct.pack("!BBH", protocol_id, flags, length)
    PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + number).to_bytes(4, 'big'))
    PROX_packet = PROX_header + number
    sendto(PROX_packet, dest_ip_address)

# send get_ack packet to destination
def get_ack(destination):
    data = b""
    flags = 240
    length = 8 + len(data)
    PROX_header = struct.pack("!BBH", protocol_id, flags, length)
    PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + data).to_bytes(4, 'big'))
    PROX_packet = PROX_header + data
    sendto(PROX_packet, dest_ip_address)

# send accept packet to destination
def accept():
    data = b""
    flags = 204
    length = 8 + len(data)
    PROX_header = struct.pack("!BBH", protocol_id, flags, length)
    PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + data).to_bytes(4, 'big'))
    PROX_packet = PROX_header + data
    sendto(PROX_packet, dest_ip_address)

# send end packet to destination
def end(destination):
    data = b""
    flags = 0
    length = 8 + len(data)
    PROX_header = struct.pack("!BBH", protocol_id, flags, length)
    PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + data).to_bytes(4, 'big'))
    PROX_packet = PROX_header + data
    sendto(PROX_packet, dest_ip_address)

# send err packet to destination
def err(destination):
    data = b""
    flags = 146
    length = 8 + len(data)
    PROX_header = struct.pack("!BBH", protocol_id, flags, length)
    PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + data).to_bytes(4, 'big'))
    PROX_packet = PROX_header + data
    sendto(PROX_packet, dest_ip_address)

# send packet with data flag and data in byte to destination
def send_data(data: bytes,destination):
    flags = 238
    length = 8 + len(data)
    PROX_header = struct.pack("!BBH", protocol_id, flags, length)
    PROX_header = struct.pack("!BBH4s", protocol_id, flags, length, zlib.adler32(PROX_header + data).to_bytes(4, 'big'))
    PROX_packet = PROX_header + data
    sendto(PROX_packet, dest_ip_address)







def get_free_space(path):
    disk_usage = psutil.disk_usage(path)
    free_space = disk_usage.free
    return free_space

path = "."  # Replace with the actual path
free_space = get_free_space(path)


# ---------------------------------Init---------------------------------
# print("---------------Start listening---------------")s

arguments = sys.argv
# print("Arguments:", arguments[1:])
# if arguments[1] == "e": 
#     print("echo mode")
#     print("---------------Start listening---------------")
#     while True:
#         packet = pack()  
#         if packet.packet_type == 'req-ack':
#             ack_data(123)
#         print('Received {} bytes from {} {},{}'.format(len(packet.raw), packet.address,packet.protocol,packet.packet_type))


while True:
    print("---------------Start listening---------------")
    packet = pack()

    # print('=======================================================================')
    print('Received {} bytes from {} {},{}'.format(len(packet.raw), packet.address,packet.protocol,packet.packet_type))


    if packet.packet_type == "get-ack" : 
        ack()
    if packet.packet_type == "start" : 
        print(Fore.GREEN + '{} is trying send a file'.format(packet.IP_packet.source_address) + Fore.RESET)
        ack()
        info = struct.unpack("!30sQHQQ", packet.prox.data[:56])
        filename = info[0].rstrip(b'\x00').decode('utf-8')
        filesize = info[1]
        fragment_offset = info[2]
        number_of_packets = info[3]
        ack_offset = info[4]
        buffer_size = fragment_offset * ack_offset
        res = "Filename : {}, Filesize : {} Bytes, Fragment offset : {} Bytes, Number of Packets : {}, Ack offset : {} \n System free space : {} Bytes  \n so Buffer size is {} Bytes".format(filename,filesize,fragment_offset,number_of_packets,ack_offset,free_space,buffer_size)
        print(res)

        if filesize < free_space : 
            print('You can get this file')
            print(ack_offset)
            accept()
        else: 
            print("You not have the enough space for this file. send end packet")
            end(packet.address)
            continue

# ---------------------------------------------------------------------------------------------------
        file_path = "./{}.rsc".format(filename)
        file = open(file_path, 'wb')
        print('file {} created'.format(file_path))
        ack_count = 0
        buffer = b""
        print('listening for data')
        g=0
        total = 0
        while True:
            packet = pack()
            ack_count = ack_count + 1
            if packet.packet_type == "req-ack":
                ack_data(total)
                file.write(buffer)
                # print("{}/{} ack sent. total: {} - {}".format(ack_count,ack_offset,total,g))
                ack_count = 0
                buffer = b""

            if packet.packet_type == "end":
                file.close()
                print('end of file')
                print("{} packets received".format(g))
                break
            elif packet.packet_type == "data" : 
                g = g + 1
                total = 1 + total
                buffer = buffer + packet.prox.data
        continue





# {
#     "name": "Kali",
#     "host": "192.168.0.13",
#     "protocol": "sftp",
#     "port": 22,
#     "username": "sajx",
#     "remotePath": "/home/sajx/workspace/projects/protox-py/",
#     "password": "jjd",
#     "uploadOnSave": true,
#     "useTempFile": false,
#     "openSsh": false
# }

