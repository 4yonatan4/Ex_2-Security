# Shilo Leopold 304996937, Yonatan Gat 203625264
import random
import sys
import socket
from threading import Lock
from time import sleep
from threading import Thread
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# List for the messages from the clients
msg_list = []
mutex = Lock()


def start_server(ip, port, sk):
    global msg_list
    # Lets build a standard server
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the socket to the port
    server_address = (ip, int(port))
    sock.bind(server_address)
    sock.listen()
    while True:
        connection, client_address = sock.accept()
        try:
            while True:
                data = ""
                # While loop to get entire message
                curr = connection.recv(1024)
                data = curr
                while len(curr) == 1024:
                    curr = connection.recv(1024)
                    data += curr
                if data:
                    # # Decrypt with SK and insert to the list
                    ip_port_msg = sk.decrypt(data, padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    ))
                    mutex.acquire()
                    try:
                        # Insert ip_port_msg to the list
                        msg_list.append(ip_port_msg)
                    finally:
                        # Release the mutex
                        mutex.release()
                else:
                    # No more data
                    break
        finally:
            # Close connection
            connection.close()


def send_messages():
    global msg_list
    while True:
        mutex.acquire()
        random.shuffle(msg_list)
        try:
            if len(msg_list) > 0:
                for ip_port_msg in msg_list:
                    # ip_port_msg = ip_port_msg.decode('UTF-8')
                    # Parse the data: ip - 4 bytes, port - 2 bytes, msg - all the rest
                    # maybe need to use: (num).to_bytes(2, 'big')
                    ip = ip_port_msg[:4]
                    ip = socket.inet_ntoa(ip)
                    port = ip_port_msg[4:6]
                    port = int.from_bytes(port, "big")
                    msg = ip_port_msg[6:]
                    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    # # Send the msg to ip, port
                    conn.connect((ip, port))
                    conn.send(msg)
                # Clear list
                msg_list.clear()
        finally:
            # Release the mutex
            mutex.release()
        sleep(60)


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
    # Open socket to send messages
    t = Thread(target=send_messages)
    t.daemon = True
    t.start()
    start_server(ip, port, server_sk)
