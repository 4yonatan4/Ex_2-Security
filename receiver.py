import socket
import sys

def open_server(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("", int(port)))
    while True:
        server.listen()


if __name__ == '__main__':
    password = sys.argv[1]
    salt = sys.argv[2]
    port = int(sys.argv[3])
    open_server(port)
