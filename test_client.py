import socket
import sys

IP="127.0.0.1"
PORT=7777
def start_tcp_client(ip, port):
    while True:
        try:
            clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clientsocket.connect((ip, port))
        except socket.error:
            print('fail to setup socket connection')
            clientsocket.close()
            break	
        data = input('>')  
        if not data:  
            break  
        clientsocket.send(bytes(data,encoding="utf-8"))
        data = clientsocket.recv(65536)  
        data = data.decode("utf-8")
        if not data:  
            break
        print("{}".format(data))
        clientsocket.close()
	
if __name__ == "__main__":
	start_tcp_client(IP,PORT)