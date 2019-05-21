#!/usr/bin/env python 

""" 
A UDP echo server that uses select to handle multiple clients at a time. 
Entering any line of input at the terminal will exit the server. 
"""
import select
import socket
import sys

if len(sys.argv) != 2:
    print("You need to specify a listening port!")
    sys.exit()

host = ''
port = int(sys.argv[1])
size = 1024

sock = socket.socket(socket.AF_INET,  # Internet
                     socket.SOCK_DGRAM)  # UDP
sock.bind((host, port))

while True:
    data, addr = sock.recvfrom(size)  # buffer size is 1024 bytes
    print "received message:", data
