import socket


with socket.create_connection(("127.0.0.1", 8080), timeout=0.5):
    pass
