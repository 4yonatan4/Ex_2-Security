import socket
import sys
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import socket

def load_keys(file_name):
    with open(file_name, "rb") as f:
        public = serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )
    return public


def get_ip_port_from_file(line_number):
    to_int = int(line_number)
    to_int -= 1
    with open('ips.txt') as f:
        return f.readlines()[to_int]


def encrypt(password, salt, mess):
    bytes_pass = bytes(password, 'utf-8')
    bytes_salt = bytes(salt, 'utf-8')
    bytes_message = bytes(mess, 'utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes_salt,
        iterations=100000, )
    key = base64.urlsafe_b64encode(kdf.derive(bytes_pass))
    f_key = Fernet(key)
    token = f_key.encrypt(bytes_message)
    return token


if __name__ == '__main__':
    file_path = "messages" + sys.argv[1] + ".txt"
    f = open(file_path, "r")
    for line in f:
        print(line)
        message = line.split()
        mes_len = len(message)
        destination_port = message[mes_len - 1]
        destination_ip = message[mes_len - 2]
        salt = message[mes_len - 3]
        key_password = message[mes_len - 4]
        data = message[0]
        round_number = message[mes_len - 5]
        path_mes = message[1:mes_len - 5]
        path_message = path_mes[0].split(",")
        c = encrypt(key_password, salt, data)
        msg = destination_ip + destination_port + str(c)
        b_msg = bytes(msg, 'utf-8')
        for i in reversed(path_message):
            public_key = load_keys("pk" + i + ".pem")
            ciphertext = public_key.encrypt(
                b_msg,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(ciphertext)
            ip_port = get_ip_port_from_file(i)
            ip_port_list = ip_port.split()
            b_ip = socket.inet_aton(ip_port_list[0])
            b_port = (int(ip_port_list[1])).to_bytes(2, 'big')
            b_msg = b_ip + b_port + ciphertext

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b_msg, (ip_port_list[0], int(ip_port_list[1])))
            # data, addr = s.recvfrom(1024)
            # print(str(data), addr)
            s.close()

