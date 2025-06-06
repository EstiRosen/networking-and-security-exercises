import socket

PORT = 8888
LEN_FIELD_SIZE = 2


def create_msg(data):
    length = str(len(data))
    length_field = length.zfill(LEN_FIELD_SIZE)
    return (length_field + data).encode()


def get_message(sckt):
    length = int(sckt.recv(LEN_FIELD_SIZE).decode())
    msg = sckt.recv(length).decode()
    return msg
