import socket
import os

UDP_IP = "192.168.100.151"
UDP_PORT = 53

sock = socket.socket(socket.AF_INET,
                     socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(1024)
    packet = str(data[0]) + str(data[1]) + b"\x81\x80" + os.urandom(128)
    sock.sendto(packet, addr)
