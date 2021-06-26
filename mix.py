# Shilo Leopold 304996937, Yonatan Gat 203625264

# package: socket, os, date, random, threding

import os
import sys
import socket
import random
import time
import threading
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


def start_server(ip, port, sk):
    # Lets build a standard server
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the socket to the port
    server_address = (ip, int(port))
    sock.bind(server_address)

    while True:
        sock.listen()
        connection, client_address = sock.accept()
        try:

            while True:
                data = connection.recv(4096)
                if data:
                    # Decrypt with SK and insert to the queue
                    print("")
                else:
                    # No more data
                    break
        finally:
            # Close connection
            connection.close()


def ip_port_parser(Y):
    int_Y = int(Y)
    ip_port = ""
    with open("ips.txt") as file:
        for i, line in enumerate(file):
            if i == int_Y - 1:
                ip_port = line
                break
    # Now we got the specific details
    ip_port = ip_port.split()
    if len(ip_port) == 2:
        return ip_port[0], ip_port[1]
    else:
        print("There is a problem with the details of ip and port")


# Credit to StackOverFlow
def load_key(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, None, default_backend())
    return private_key


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Argument Missing!")
        exit(1)
    Y = sys.argv[1]
    # Load skY.pem
    file_name = "sk" + Y + ".pem"
    server_sk = load_key(file_name)
    # Load ip and port - load ips.txt and take both from the 'Y' line
    ip, port = ip_port_parser(Y)
    start_server(ip, port, server_sk)
