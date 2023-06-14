# # import sys
# # import os

# # def get_string_size(string, encoding='utf-8'):
# #     encoded_string = string.encode(encoding)
# #     return len(encoded_string)

# # def get_number_size(number):
# #     return sys.getsizeof(number)

# # number = 42
# # size_in_bytes = get_number_size(number)
# # print(f"Size of the number: {size_in_bytes} bytes")
# # string = "Hello, World!"
# # size_in_bytes = get_string_size(string)
# # print(f"Size of the string: {size_in_bytes} bytes")

# # def get_file_size_in_bits(file_path):
# #     # Get the size of the file in bytes
# #     size_in_bytes = os.path.getsize(file_path)
    
# #     # Convert bytes to bits
# #     size_in_bits = size_in_bytes * 8
    
# #     return size_in_bits

# # file_path = "/Users/sajjad/Downloads/tmp/vv.mp4"  # Replace with the actual file path
# # file_size_in_bits = get_file_size_in_bits(file_path)
# # print(f"Size of the file: {file_size_in_bits} bits")

# import struct

# def pack_string_to_packet(string):
#     # Encode the string using an appropriate encoding, such as UTF-8
#     encoded_string = string.encode('utf-8')
    
#     # Pad or truncate the string to fit the desired packet size
#     packed_string = encoded_string[:30].ljust(30, b'\x00')
    
#     return packed_string

# string = "Hello, World!"
# packed_data = pack_string_to_packet(string)
# print(f"Packed data: {packed_data}")


import socket

def get_current_ip():
    ip_address = socket.gethostbyname("host.kali")
    return ip_address

current_ip = get_current_ip()
print("Current IP Address:", current_ip)