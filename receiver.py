import base64
import socket
import sys
from datetime import datetime

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, kdf
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def open_server(port, password, salt):
    bytes_pass = bytes(password, "utf-8")
    bytes_salt = bytes(salt, "utf-8")
    rec = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rec.bind(("", int(port)))
    rec.listen()
    while True:
        connection, client_address = rec.accept()
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
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=bytes_salt,
                        iterations=100000, )
                    key = base64.urlsafe_b64encode(kdf.derive(bytes_pass))
                    f = Fernet(key)
                    msg = f.decrypt(data)
                    msg = msg.decode("utf-8")
                    time = datetime.now().time()
                    time = time.strftime("%H:%M:%S")
                    print(msg + " " + time)
        finally:
            connection.close()


if __name__ == '__main__':
    password = sys.argv[1]
    salt = sys.argv[2]
    port = sys.argv[3]
    open_server(port, password, salt)
